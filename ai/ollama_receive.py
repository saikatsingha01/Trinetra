from __future__ import annotations

import asyncio
import logging
import time
import threading
import traceback
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from integration_models import OllamaRequestModel
from logic_send import send_ollama_failure, send_to_logic
from ollama_model import (
    EmailModel,
    EvidencePackage,
    SecurityAnalysisModel,
    ThreatAnalysisModel,
)
from src.ai.pipeline import analyze


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cypherx.ollama.receive")

# Tracks case_ids for which an Ollama failure notification has already been
# sent from process_backend_payload. Used to make the done-callback idempotent:
# if the failure was already reported inside the task, the callback must NOT
# send a second notification. Bounded in practice by number of concurrent
# tasks; entries are removed after callback runs.
_ollama_failure_notified: set[str] = set()

# ============================================================
# BOUNDED CONCURRENCY / QUEUE STATE
# ============================================================
# Queue holds (OllamaRequestModel, enqueue_time) tuples.
# Bounded to prevent unbounded memory/task growth under burst load.
# Workers are fixed and started on lifespan startup, stopped on shutdown.
# All queue/worker state is in-memory per-process (not distributed).
# For multi-process uvicorn workers, each process has its own pool.
_queue: asyncio.Queue | None = None  # type: ignore
_worker_tasks: list[asyncio.Task] = []
_is_shutting_down: bool = False
_init_lock = threading.Lock()
_metrics_lock = threading.Lock()
_metrics: dict[str, Any] = {
    "total_queued": 0,
    "total_completed": 0,
    "total_failed": 0,
    "total_rejected": 0,
    "total_logic_failed": 0,
    "active_workers": 0,
    "max_active_observed": 0,
    "max_workers": 0,
    "queue_maxsize": 0,
    "queue_depth": 0,
    "avg_queue_wait_ms": 0.0,
    "avg_analysis_time_ms": 0.0,
    "_queue_wait_sum": 0.0,
    "_queue_wait_count": 0,
    "_analysis_sum": 0.0,
    "_analysis_count": 0,
}

def _get_receiver_settings():
    """Load receiver settings from OllamaSettings (env OLLAMA_*)."""
    try:
        from src.ai.llm.config import get_ollama_settings
        return get_ollama_settings()
    except Exception:
        # Fallback defaults if config not importable
        class _Fallback:
            max_concurrency = 2
            queue_maxsize = 50
            shutdown_timeout_seconds = 10.0
        return _Fallback()

def _update_metrics_on_enqueue():
    with _metrics_lock:
        _metrics["total_queued"] += 1
        if _queue is not None:
            _metrics["queue_depth"] = _queue.qsize()

def _update_metrics_rejected():
    with _metrics_lock:
        _metrics["total_rejected"] += 1

async def _startup_workers() -> None:
    """Create queue and fixed worker pool. Idempotent."""
    global _queue, _worker_tasks, _is_shutting_down
    # Fast path check without lock
    if _queue is not None and _worker_tasks and all(not t.done() for t in _worker_tasks):
        return
    with _init_lock:
        # Double-check after acquiring lock
        if _queue is not None and _worker_tasks and all(not t.done() for t in _worker_tasks):
            return
        # If queue exists but workers died, clean up
        if _worker_tasks and any(t.done() for t in _worker_tasks):
            # remove done tasks, will recreate
            _worker_tasks = [t for t in _worker_tasks if not t.done()]
            if _queue is not None and _worker_tasks:
                return
        settings = _get_receiver_settings()
        max_workers = int(getattr(settings, "max_concurrency", 2))
        queue_maxsize = int(getattr(settings, "queue_maxsize", 50))
        # Validate ranges
        max_workers = max(1, min(32, max_workers))
        queue_maxsize = max(1, min(1000, queue_maxsize))
        with _metrics_lock:
            _metrics["max_workers"] = max_workers
            _metrics["queue_maxsize"] = queue_maxsize
        if _queue is None:
            _queue = asyncio.Queue(maxsize=queue_maxsize)
            logger.info(f"Created bounded queue maxsize={queue_maxsize}")
        else:
            # queue exists but may have different maxsize due to settings change; log
            logger.info(f"Reusing existing queue maxsize={_queue.maxsize} (configured {queue_maxsize})")
        _is_shutting_down = False
        # Create workers if needed
        existing = len(_worker_tasks)
        needed = max_workers - existing
        for i in range(needed):
            wid = existing + i + 1
            task = asyncio.create_task(_worker_loop(wid), name=f"ollama-worker-{wid}")
            _worker_tasks.append(task)
        if needed > 0:
            logger.info(f"Ollama workers started: {max_workers} workers (added {needed}), queue_maxsize={_queue.maxsize}")
        else:
            logger.info(f"Ollama workers ready: {max_workers} workers, queue_maxsize={_queue.maxsize}")

async def _ensure_workers_started() -> None:
    """Lazy init for contexts that don't trigger lifespan (e.g. TestClient without context)."""
    if _queue is not None and _worker_tasks and all(not t.done() for t in _worker_tasks):
        return
    await _startup_workers()

async def _shutdown_workers() -> None:
    """Graceful shutdown: stop accepting, let active finish, discard queued, cancel idle."""
    global _is_shutting_down, _queue, _worker_tasks
    if _is_shutting_down and not _worker_tasks:
        return
    _is_shutting_down = True
    logger.info("Shutting down Ollama receiver: stopping accept of new work")
    settings = _get_receiver_settings()
    timeout = float(getattr(settings, "shutdown_timeout_seconds", 10.0))
    # Wait for active workers to finish up to timeout
    start = time.time()
    while time.time() - start < timeout:
        with _metrics_lock:
            active = _metrics.get("active_workers", 0)
            qsize = _queue.qsize() if _queue is not None else 0
        if active == 0:
            break
        logger.info(f"Shutdown waiting: active={active} queue_depth={qsize} remaining_timeout={timeout - (time.time()-start):.1f}s")
        await asyncio.sleep(0.2)
    # Discard remaining queued items without reporting as Ollama failure
    remaining = 0
    if _queue is not None:
        while not _queue.empty():
            try:
                _queue.get_nowait()
                _queue.task_done()
                remaining += 1
            except asyncio.QueueEmpty:
                break
        if remaining:
            logger.warning(f"Shutdown discarded {remaining} queued jobs (not reported as Ollama failure)")
            with _metrics_lock:
                _metrics["queue_depth"] = _queue.qsize() if _queue else 0
    # Cancel idle workers waiting on queue.get()
    for w in list(_worker_tasks):
        if not w.done():
            w.cancel()
    if _worker_tasks:
        try:
            await asyncio.wait_for(asyncio.gather(*_worker_tasks, return_exceptions=True), timeout=2.0)
        except asyncio.TimeoutError:
            logger.warning("Workers did not exit promptly after cancel, forcing")
        # Ensure all collected
        await asyncio.gather(*_worker_tasks, return_exceptions=True)
        logger.info("All workers stopped")
    _worker_tasks = []
    # Do not clear _queue to allow tests to reuse? But we keep queue cleared.
    # Keep queue object but empty; set to None only if we want lazy recreate next startup.
    # For clean shutdown we keep queue but will be recreated on next startup if needed.
    # To allow tests to re-start after shutdown, we reset queue to None.
    # But for normal server shutdown, process exits, so not needed.
    # We'll keep queue as empty to allow metric reads post-shutdown.
    # However to make _ensure_workers_started work after shutdown in tests, we reset.
    # Detect if we are in test context: if loop still running, keep None for restart.
    # Simpler: keep _queue but not None; _startup will reuse it.
    # So we don't set _queue = None here to preserve empty queue for metrics.
    # But we need _is_shutting_down True to block new accepts after shutdown until next startup.
    # That's fine.

@asynccontextmanager
async def lifespan(app: FastAPI):
    await _startup_workers()
    yield
    await _shutdown_workers()

app = FastAPI(title="CypherX Ollama Receiver", lifespan=lifespan)


def build_evidence_package(data: OllamaRequestModel) -> EvidencePackage:
    """Validate Subhom's payload and convert it to the AI pipeline contract."""

    email = EmailModel.model_validate(data.parsed_email)
    security_analysis = SecurityAnalysisModel.model_validate(
        data.security_analysis
    )
    threat_analysis = ThreatAnalysisModel.model_validate(
        data.threat_analysis
    )

    return EvidencePackage(
        case_id=data.email_id,
        email=email,
        security_analysis=security_analysis,
        threat_intelligence=threat_analysis,
        forensic_evidence={
            "attachments": email.attachments.model_dump(mode="json"),
            "originating_ip": email.originating_ip,
        },
    )


def _classify_ollama_failure(exc: Exception) -> tuple[str, str]:
    """
    Determine a useful (failure_stage, failure_type) for an Ollama-side exception.

    Priority:
    1. If the exception carries a ``stage`` attribute (PipelineError and its
       subclasses), use it verbatim.
    2. Otherwise map known exception types to their lifecycle stage.
    3. Fallback to "unknown" so the Logic Engine still receives a typed event.
    """
    stage = getattr(exc, "stage", None)
    if isinstance(stage, str) and stage.strip():
        return stage.strip(), type(exc).__name__

    exc_name = type(exc).__name__
    lower_name = exc_name.lower()
    msg_lower = str(exc).lower()

    # LLM output / validation failures
    if "llmschemavalidation" in lower_name or "pipelinervalidation" in lower_name:
        # If the message already mentions the stage, preserve it; otherwise
        # llm_output_schema is the correct stage for schema rejections such as
        # evidence_path generic labels.
        if "llm_output_schema" in msg_lower:
            return "llm_output_schema", exc_name
        if "evidence_path" in msg_lower or "provenance" in msg_lower:
            return "llm_output_schema", exc_name
        return "llm_output_schema", exc_name
    if "llmextraction" in lower_name or "llmjsonparse" in lower_name:
        return "llm_output_extraction", exc_name
    if isinstance(exc, ValidationError):
        # ValidationError inside the background task means the evidence package
        # that passed the synchronous pre-check now fails under the pipeline's
        # stricter view (e.g. forensic depth). Treat as input stage.
        return "evidence_package_build", exc_name

    # Pipeline LLM errors carry stage already, but fallback if not
    if "ollamaconnection" in lower_name:
        return "ollama_connection", exc_name
    if "ollamatimeout" in lower_name:
        return "ollama_timeout", exc_name
    if "ollamahttp" in lower_name:
        return "ollama_http", exc_name
    if "ollamamodelnotfound" in lower_name:
        return "ollama_model_not_found", exc_name
    if "ollamainvalidresponse" in lower_name:
        return "ollama_invalid_response", exc_name
    if "ollamaclient" in lower_name or "ollama" in lower_name:
        return "ollama_client", exc_name
    if "inputguard" in lower_name:
        return "input_guard", exc_name

    # Content isolation / normalization / understanding / prompt / grounding
    # do not currently have dedicated exception types; they surface as generic
    # exceptions with messages mentioning the stage. Use message hint.
    for hint, stage_name in (
        ("content isolation", "content_isolation"),
        ("normalization", "normalization"),
        ("understanding", "understanding"),
        ("prompt", "prompt_construction"),
        ("grounding", "grounding"),
        ("reconciliation", "reconciliation"),
        ("input_guard", "input_guard"),
        ("input guard", "input_guard"),
    ):
        if hint in msg_lower:
            return stage_name, exc_name

    return "unknown", exc_name


async def process_backend_payload(data: OllamaRequestModel) -> str:
    """
    Run the complete Saikat/Ollama pipeline outside the HTTP request lifecycle.

    Guarantees: for every case that enters Ollama processing (i.e. every
    data object that reached this background task), the Logic Engine receives
    EITHER:
      A) the normal successful analysis via /receive-ollama
      OR
      B) an explicit Ollama failure notification via /receive-ollama-failure
         whose semantic message is "Ollama has failed".

    Logic delivery failures (successful analysis but POST to Logic fails) are
    logged as logic-delivery failures and are NOT reported as Ollama failures.
    If the failure notification itself fails to deliver, that secondary failure
    is logged and not recursively retried as a new Ollama failure event.

    Returns a status string for worker observability:
      "success" | "ollama_failure" | "logic_failure" | "cancelled"
    The return value is ignored by legacy callers (they await without checking),
    so this is backward compatible.
    """

    # Preserve case_id before any build step; fallback to "unknown" if
    # extraction itself fails (should not happen for valid backend payloads,
    # but ensures unexpected task crashes still have an identifier).
    try:
        case_id = data.email_id
    except Exception:
        case_id = getattr(data, "email_id", "unknown")
        if not isinstance(case_id, str) or not case_id.strip():
            case_id = "unknown"

    # ------------------------------------------------------------------
    # OLLAMA PIPELINE (build -> analyze)
    # Any exception here is an Ollama failure and MUST be reported to Logic.
    # ------------------------------------------------------------------
    try:
        evidence_package = build_evidence_package(data)

        logger.info(
            "Starting Ollama analysis case_id=%s",
            evidence_package.case_id,
        )

        result = await asyncio.to_thread(
            analyze,
            evidence_package,
        )

    except asyncio.CancelledError:
        # Intentional shutdown cancellation is not an Ollama analysis failure.
        # Do not report as "Ollama has failed". Propagate so worker can handle.
        logger.warning(
            "Ollama pipeline cancelled case_id=%s (not reporting as Ollama failure)",
            case_id,
        )
        raise
    except Exception as exc:
        # Full traceback for local debugging
        tb = traceback.format_exc()
        failure_stage, failure_type = _classify_ollama_failure(exc)

        logger.exception(
            "Ollama pipeline failed case_id=%s stage=%s type=%s error=%s",
            case_id,
            failure_stage,
            failure_type,
            exc,
        )
        # Debug-level full traceback already captured by logger.exception;
        # also log the formatted traceback at debug for completeness.
        logger.debug("Ollama failure traceback case_id=%s:\n%s", case_id, tb)

        # Attempt to send explicit failure notification to Logic Engine.
        # This is the guaranteed failure propagation path. Do NOT fabricate a
        # normal AI assessment and do NOT wrap as LogicAnalysisReport.
        try:
            await asyncio.to_thread(
                send_ollama_failure,
                case_id,
                exc,
                failure_stage,
                failure_type,
            )
            logger.info(
                "Ollama failure notification delivered to Logic Engine case_id=%s stage=%s type=%s",
                case_id,
                failure_stage,
                failure_type,
            )
        except asyncio.CancelledError:
            logger.warning(
                "Ollama failure notification cancelled case_id=%s stage=%s (not retrying)",
                case_id,
                failure_stage,
            )
            # Still mark as notified to prevent duplicate via callback, but propagate cancellation
            _ollama_failure_notified.add(case_id)
            raise
        except Exception as notify_exc:
            # SECONDARY FAILURE: the failure notification itself failed to
            # deliver. Do NOT recursively generate another failure event.
            # Log and terminate this path safely.
            logger.exception(
                "Failed to send Ollama failure notification case_id=%s stage=%s notify_error=%s",
                case_id,
                failure_stage,
                notify_exc,
            )
        finally:
            # Mark as notified for idempotent done-callback (even if delivery
            # itself failed, we have already attempted reporting and must not
            # send a duplicate from the callback).
            _ollama_failure_notified.add(case_id)
        return "ollama_failure"

    # ------------------------------------------------------------------
    # LOGIC DELIVERY (only reached if Ollama succeeded)
    # A failure here is a Logic delivery failure, NOT an Ollama failure.
    # ------------------------------------------------------------------
    try:
        logic_response = await asyncio.to_thread(
            send_to_logic,
            result,
        )

        logger.info(
            "Ollama analysis delivered to Logic Engine case_id=%s response=%s",
            case_id,
            logic_response,
        )
        return "success"

    except asyncio.CancelledError:
        logger.warning(
            "Logic delivery cancelled case_id=%s (not reporting as Ollama failure)",
            case_id,
        )
        raise
    except Exception as logic_exc:
        logger.exception(
            "Logic delivery failed case_id=%s error=%s "
            "(Ollama analysis succeeded; NOT an Ollama failure - do not report as 'Ollama has failed')",
            case_id,
            logic_exc,
        )
        # Do not send an Ollama failure notification for a logic-delivery
        # failure. The Ollama component succeeded; the failure is downstream.
        return "logic_failure"


async def _worker_loop(worker_id: int) -> None:
    """Fixed worker that processes one queued case at a time."""
    logger.info(f"Worker {worker_id} started")
    assert _queue is not None
    while True:
        try:
            item = await _queue.get()
        except asyncio.CancelledError:
            logger.info(f"Worker {worker_id} cancelled while waiting for queue")
            break
        # Sentinel None could be used for shutdown, but we use cancellation + discard
        if item is None:
            _queue.task_done()
            logger.info(f"Worker {worker_id} received shutdown sentinel")
            break
        # Unpack
        try:
            data, enqueue_time = item  # type: ignore
        except Exception:
            logger.error(f"Worker {worker_id} got malformed queue item {item!r}")
            _queue.task_done()
            continue
        # Per-case isolation: deep copy to avoid cross-case mutation
        try:
            case_id = getattr(data, "email_id", "unknown")
            if not isinstance(case_id, str) or not case_id.strip():
                case_id = "unknown"
        except Exception:
            case_id = "unknown"
        # Isolate payload
        try:
            if hasattr(data, "model_copy"):
                data_isolated = data.model_copy(deep=True)  # type: ignore
            else:
                # fallback shallow copy
                import copy
                data_isolated = copy.deepcopy(data)
        except Exception:
            data_isolated = data

        queue_wait = time.time() - enqueue_time
        with _metrics_lock:
            _metrics["active_workers"] += 1
            cur_active = _metrics["active_workers"]
            if cur_active > _metrics["max_active_observed"]:
                _metrics["max_active_observed"] = cur_active
            _metrics["_queue_wait_sum"] += queue_wait
            _metrics["_queue_wait_count"] += 1
            _metrics["avg_queue_wait_ms"] = (_metrics["_queue_wait_sum"] / _metrics["_queue_wait_count"] * 1000) if _metrics["_queue_wait_count"] else 0.0
            _metrics["queue_depth"] = _queue.qsize()
        logger.info(
            f"Worker {worker_id} processing case_id={case_id} queue_wait={queue_wait:.3f}s queue_depth={_queue.qsize()} active={cur_active}"
        )
        analysis_start = time.time()
        status = "success"
        try:
            status = await process_backend_payload(data_isolated)
            analysis_time = time.time() - analysis_start
            with _metrics_lock:
                if status == "ollama_failure":
                    _metrics["total_failed"] += 1
                elif status == "logic_failure":
                    _metrics["total_logic_failed"] += 1
                    _metrics["total_completed"] += 1
                elif status == "success":
                    _metrics["total_completed"] += 1
                else:
                    _metrics["total_completed"] += 1
                _metrics["_analysis_sum"] += analysis_time
                _metrics["_analysis_count"] += 1
                _metrics["avg_analysis_time_ms"] = (_metrics["_analysis_sum"] / _metrics["_analysis_count"] * 1000) if _metrics["_analysis_count"] else 0.0
            logger.info(f"Worker {worker_id} finished case_id={case_id} status={status} analysis_time={analysis_time:.3f}s")
        except asyncio.CancelledError:
            logger.warning(f"Worker {worker_id} cancelled during processing case_id={case_id} (not reporting as Ollama failure)")
            analysis_time = time.time() - analysis_start
            with _metrics_lock:
                # Do not count cancelled as completed/failed
                _metrics["_analysis_sum"] += analysis_time
                _metrics["_analysis_count"] += 1
                _metrics["avg_analysis_time_ms"] = (_metrics["_analysis_sum"] / _metrics["_analysis_count"] * 1000) if _metrics["_analysis_count"] else 0.0
                # Decrement active before break
                _metrics["active_workers"] -= 1
                _metrics["queue_depth"] = _queue.qsize()
            _queue.task_done()
            # If shutting down, exit loop; else continue
            if _is_shutting_down:
                break
            else:
                continue
        except Exception as exc:
            logger.exception(f"Worker {worker_id} unexpected error case_id={case_id}: {exc}")
            # Ensure failure propagation if not already handled
            try:
                failure_stage, failure_type = _classify_ollama_failure(exc)  # type: ignore
                await asyncio.to_thread(send_ollama_failure, case_id, exc, failure_stage, failure_type)
                logger.info(f"Worker {worker_id} delivered unexpected failure notification case_id={case_id}")
            except asyncio.CancelledError:
                logger.warning(f"Worker {worker_id} cancelled while sending unexpected failure case_id={case_id}")
            except Exception as notify_exc:
                logger.exception(f"Worker {worker_id} failed to send unexpected failure notification case_id={case_id}: {notify_exc}")
            finally:
                with _metrics_lock:
                    _metrics["total_failed"] += 1
                    _metrics["active_workers"] -= 1
                    _metrics["queue_depth"] = _queue.qsize()
                    analysis_time = time.time() - analysis_start
                    _metrics["_analysis_sum"] += analysis_time
                    _metrics["_analysis_count"] += 1
                    _metrics["avg_analysis_time_ms"] = (_metrics["_analysis_sum"] / _metrics["_analysis_count"] * 1000) if _metrics["_analysis_count"] else 0.0
                _queue.task_done()
            continue
        else:
            # Normal completion, decrement active and mark done
            with _metrics_lock:
                _metrics["active_workers"] -= 1
                _metrics["queue_depth"] = _queue.qsize()
            _queue.task_done()
        # Continue loop; check shutdown flag? We let shutdown cancellation handle exit.
    logger.info(f"Worker {worker_id} exiting")


@app.post("/receive-backend", status_code=202)
async def receive_backend(data: OllamaRequestModel) -> dict[str, str]:
    """Accept Subhom's validated evidence package and queue AI processing with backpressure."""

    try:
        # Validate synchronously before acknowledging receipt, so malformed
        # transport data gets a useful 422 instead of disappearing in a task.
        build_evidence_package(data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(),
        ) from exc

    # Graceful shutdown check
    if _is_shutting_down:
        logger.warning(f"Rejecting case_id={getattr(data, 'email_id', 'unknown')} during shutdown")
        raise HTTPException(
            status_code=503,
            detail={"error": "Server is shutting down", "retry_after": 5},
            headers={"Retry-After": "5"},
        )

    # Ensure workers/queue are ready (lazy init for TestClient without lifespan)
    await _ensure_workers_started()
    assert _queue is not None

    # Backpressure: bounded queue, no silent loss
    # Use put_nowait to fail fast when full; do not use await put() which would wait unbounded.
    try:
        # Isolate payload before queueing to prevent caller mutation after accept
        try:
            if hasattr(data, "model_copy"):
                queued_data = data.model_copy(deep=True)  # type: ignore
            else:
                import copy
                queued_data = copy.deepcopy(data)
        except Exception:
            queued_data = data
        _queue.put_nowait((queued_data, time.time()))
        _update_metrics_on_enqueue()
        logger.info(
            f"Queued case_id={data.email_id} queue_depth={_queue.qsize()}/{_queue.maxsize} active={_metrics.get('active_workers',0)}"
        )
    except asyncio.QueueFull:
        _update_metrics_rejected()
        logger.warning(
            f"Queue full rejecting case_id={getattr(data, 'email_id', 'unknown')} queue_depth={_queue.qsize()}/{_queue.maxsize}"
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Server overloaded, queue full",
                "retry_after": 5,
                "queue_depth": _queue.qsize(),
                "queue_maxsize": _queue.maxsize,
            },
            headers={"Retry-After": "5"},
        ) from None

    return {
        "status": "accepted",
        "email_id": data.email_id,
        "message": "Backend evidence accepted for Ollama analysis.",
    }


# ============================================================
# Observability / Health
# ============================================================
@app.get("/health", status_code=200)
async def health() -> dict[str, Any]:
    """Health check with queue/worker summary."""
    with _metrics_lock:
        m = dict(_metrics)
    qsize = _queue.qsize() if _queue is not None else 0
    qmax = _queue.maxsize if _queue is not None else 0
    active = m.get("active_workers", 0)
    max_workers = m.get("max_workers", 0)
    return {
        "status": "ok" if not _is_shutting_down else "shutting_down",
        "service": "ollama-receiver",
        "queue_depth": qsize,
        "queue_maxsize": qmax,
        "active_workers": active,
        "max_workers": max_workers,
        "is_shutting_down": _is_shutting_down,
    }

@app.get("/metrics", status_code=200)
async def metrics() -> dict[str, Any]:
    """Lightweight internal observability."""
    with _metrics_lock:
        m = dict(_metrics)
    # hide internal sums
    out = {k: v for k, v in m.items() if not k.startswith("_")}
    out["queue_depth"] = _queue.qsize() if _queue is not None else 0
    out["is_shutting_down"] = _is_shutting_down
    # Add current maxsize/max_workers for completeness
    if _queue is not None:
        out["queue_maxsize"] = _queue.maxsize
    return out

@app.get("/debug/queue", status_code=200)
async def debug_queue() -> dict[str, Any]:
    """Debug queue snapshot for tests."""
    with _metrics_lock:
        m = dict(_metrics)
    return {
        "queue_depth": _queue.qsize() if _queue is not None else 0,
        "queue_maxsize": _queue.maxsize if _queue is not None else 0,
        "active_workers": m.get("active_workers", 0),
        "max_active_observed": m.get("max_active_observed", 0),
        "max_workers": m.get("max_workers", 0),
        "total_queued": m.get("total_queued", 0),
        "total_completed": m.get("total_completed", 0),
        "total_failed": m.get("total_failed", 0),
        "total_logic_failed": m.get("total_logic_failed", 0),
        "total_rejected": m.get("total_rejected", 0),
        "avg_queue_wait_ms": m.get("avg_queue_wait_ms", 0.0),
        "avg_analysis_time_ms": m.get("avg_analysis_time_ms", 0.0),
        "is_shutting_down": _is_shutting_down,
        "worker_count": len(_worker_tasks),
        "workers_alive": sum(1 for t in _worker_tasks if not t.done()),
    }

@app.post("/debug/clear", status_code=200)
async def debug_clear() -> dict[str, str]:
    """Clear metrics and drain queue (test helper). Does not kill workers."""
    drained = 0
    if _queue is not None:
        while not _queue.empty():
            try:
                _queue.get_nowait()
                _queue.task_done()
                drained += 1
            except asyncio.QueueEmpty:
                break
    with _metrics_lock:
        for k in list(_metrics.keys()):
            if k.startswith("_"):
                _metrics[k] = 0.0 if "sum" in k or "avg" in k else 0
            elif k in ("avg_queue_wait_ms", "avg_analysis_time_ms"):
                _metrics[k] = 0.0
            elif k in ("active_workers", "max_active_observed", "total_queued", "total_completed", "total_failed", "total_logic_failed", "total_rejected", "queue_depth"):
                _metrics[k] = 0
        # keep max_workers/queue_maxsize
        if _queue is not None:
            _metrics["queue_depth"] = _queue.qsize()
    _ollama_failure_notified.clear()
    logger.info(f"Debug clear drained {drained} queued items, metrics reset")
    return {"status": "cleared", "drained": str(drained)}

@app.get("/debug/cases", status_code=200)
async def debug_cases_alias() -> dict[str, Any]:
    """Alias for compatibility if needed; returns queue metrics."""
    return await debug_queue()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "ollama_receive:app",
        host="0.0.0.0",
        port=8002,
        log_level="info",
        reload=False,
    )
