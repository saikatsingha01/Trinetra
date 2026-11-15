from __future__ import annotations

import logging
import threading
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from logic_model import LogicAnalysisReport

# Reuse the Ollama failure contract defined in logic_send.py so both sides
# speak the same schema without duplicating definitions. Importing here is
# safe (logic_send does not import from this module).
try:
    from logic_send import OllamaFailureNotification  # type: ignore
except Exception:  # pragma: no cover - fallback if logic_send not importable at startup
    class OllamaFailureNotification(BaseModel):  # type: ignore[no-redef]
        model_config = ConfigDict(extra="forbid")
        case_id: str = Field(..., description="Original case identifier preserved from backend")
        component: str = Field(default="ollama")
        status: str = Field(default="failed")
        message: str = Field(default="Ollama has failed")
        failure_stage: str = Field(...)
        failure_type: str = Field(...)
        error: str = Field(...)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cypherx.logic.receive")

app = FastAPI(title="CypherX Logic Engine", version="1.0.0")

# ---------------------------------------------------------------------------
# In-memory stores - minimal compatible failure handling without disturbing
# normal analysis. In production these would be DB / state-machine updates.
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_received_ollama_reports: dict[str, dict[str, Any]] = {}
_received_failures: dict[str, dict[str, Any]] = {}
_failure_processed_ids: set[str] = set()  # idempotency for duplicate deliveries
_success_processed_ids: set[str] = set()


# ============================================================
# Normal success path - MUST remain exactly as before
# ============================================================
# POST /receive-ollama receives a validated LogicAnalysisReport.
# It does NOT calculate phishing/BEC - it just records and acknowledges.

@app.post("/receive-ollama", status_code=200)
async def receive_ollama(report: LogicAnalysisReport) -> dict[str, Any]:
    """
    Normal Ollama -> Logic success delivery.

    Expected payload: LogicAnalysisReport (strict, extra=forbid).
    Behaviour:
    - Validate case_id non-empty
    - Preserve original case_id
    - Record/log success
    - Return explicit HTTP 200 acknowledgement

    This endpoint MUST NOT be used for failure events.
    """
    if not report.case_id or not report.case_id.strip():
        raise HTTPException(status_code=422, detail="case_id must not be empty")

    case_id = report.case_id.strip()

    # Preserve original case_id - do not generate new id
    payload = report.model_dump(mode="json")

    with _lock:
        _received_ollama_reports[case_id] = {
            "report": payload,
            "received_at": time.time(),
        }
        _success_processed_ids.add(case_id)
        # If a previous failure existed for this case (edge: retry succeeds after failure),
        # we keep both records but success is authoritative for this delivery.
        # Do not clear failure - audit trail.

    logger.info(
        "Logic Engine received successful Ollama analysis case_id=%s phishing=%.2f bec=%.2f grounded=%s",
        case_id,
        report.ai_assessment.phishing_probability,
        report.ai_assessment.bec_probability,
        report.grounding.grounded,
    )

    # Do NOT re-calculate phishing/BEC, do NOT invent scores.
    return {
        "status": "acknowledged",
        "case_id": case_id,
        "message": "Ollama analysis received",
        "grounded": report.grounding.grounded,
    }


# ============================================================
# Failure path - explicit Ollama failure event
# ============================================================
# POST /receive-ollama-failure receives OllamaFailureNotification.
# MUST be distinct from /receive-ollama.

@app.post("/receive-ollama-failure", status_code=200)
async def receive_ollama_failure(event: OllamaFailureNotification) -> dict[str, Any]:
    """
    Explicit Ollama failure notification.

    Expected payload conceptually:
    {
        "case_id": "...",
        "component": "ollama",
        "status": "failed",
        "message": "Ollama has failed",
        "failure_stage": "llm_output_schema",
        "failure_type": "PipelineValidationError",
        "error": "..."
    }

    Requirements:
    1. Parse & validate event (Pydantic does this via OllamaFailureNotification)
    2. Validate case_id non-empty
    3. Preserve original case_id
    4. Record/log failure with stage/type/error
    5. Perform Logic Engine failure operation (state-machine placeholder)
    6. Return explicit HTTP 200 acknowledgement
    7. Idempotent - duplicate deliveries for same case_id do not create duplicate processing
    8. Do NOT execute normal AI-score processing, do NOT treat as LogicAnalysisReport
    """
    # Pydantic already validated extra=forbid, required fields, types.
    # Additional semantic checks:
    if not event.case_id or not event.case_id.strip():
        raise HTTPException(status_code=422, detail="case_id must not be empty")

    if event.component != "ollama":
        # We still accept but log - the spec says component="ollama" is expected
        logger.warning(
            "Logic Engine received failure with unexpected component case_id=%s component=%s",
            event.case_id,
            event.component,
        )

    if event.status != "failed":
        logger.warning(
            "Logic Engine received failure with unexpected status case_id=%s status=%s",
            event.case_id,
            event.status,
        )

    if event.message != "Ollama has failed":
        logger.warning(
            "Logic Engine received failure with unexpected message case_id=%s message=%r",
            event.case_id,
            event.message,
        )

    case_id = event.case_id.strip()
    # Idempotency: if already processed, return same ack without re-processing
    with _lock:
        if case_id in _failure_processed_ids:
            logger.info(
                "Logic Engine duplicate failure notification ignored (idempotent) case_id=%s stage=%s type=%s",
                case_id,
                event.failure_stage,
                event.failure_type,
            )
            return {
                "status": "acknowledged",
                "case_id": case_id,
                "component": event.component,
                "failure_stage": event.failure_stage,
                "failure_type": event.failure_type,
                "duplicate": True,
                "message": "Ollama failure already recorded",
            }

    # Log full failure context for triage - case_id, stage, type, error (truncated safe)
    # Do NOT log secrets/API keys (error is already truncated to 2000 chars in logic_send)
    logger.warning(
        "Logic Engine received Ollama failure case_id=%s stage=%s type=%s error=%s",
        case_id,
        event.failure_stage,
        event.failure_type,
        event.error[:500] if len(event.error) > 500 else event.error,
    )
    logger.info(
        "Logic Engine failure details case_id=%s component=%s status=%s message=%r",
        case_id,
        event.component,
        event.status,
        event.message,
    )

    # --- Minimal compatible failure operation ---
    # In a full Logic Engine this would:
    #   - update case status to 'ollama_failed'
    #   - persist failure to DB
    #   - trigger alert / fallback workflow
    #   - NOT calculate phishing/BEC
    # Here we store it in-memory and mark case as failed.
    with _lock:
        _received_failures[case_id] = {
            "case_id": case_id,
            "component": event.component,
            "status": event.status,
            "message": event.message,
            "failure_stage": event.failure_stage,
            "failure_type": event.failure_type,
            "error": event.error,
            "received_at": time.time(),
            # Explicitly do NOT store any phishing/BEC probabilities
        }
        _failure_processed_ids.add(case_id)

    logger.info(
        "Logic Engine recorded Ollama failure case_id=%s stage=%s type=%s (no AI scores calculated)",
        case_id,
        event.failure_stage,
        event.failure_type,
    )

    # Explicit HTTP 200 success acknowledgement to Ollama service
    return {
        "status": "acknowledged",
        "case_id": case_id,
        "component": event.component,
        "failure_stage": event.failure_stage,
        "failure_type": event.failure_type,
        "message": "Ollama failure recorded",
    }


# ============================================================
# Health / Debug helpers (not required but useful for ngrok checks)
# ============================================================

@app.get("/health", status_code=200)
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "logic-engine"}


@app.get("/debug/cases", status_code=200)
async def debug_cases() -> dict[str, Any]:
    with _lock:
        return {
            "success_cases": list(_success_processed_ids),
            "failure_cases": list(_failure_processed_ids),
            "failure_details": {k: v for k, v in _received_failures.items()},
            "success_count": len(_received_ollama_reports),
            "failure_count": len(_received_failures),
        }


@app.get("/debug/cases/{case_id}", status_code=200)
async def debug_case(case_id: str) -> dict[str, Any]:
    with _lock:
        if case_id in _received_failures:
            return {"case_id": case_id, "type": "failure", "data": _received_failures[case_id]}
        if case_id in _received_ollama_reports:
            return {"case_id": case_id, "type": "success", "data": _received_ollama_reports[case_id]}
        raise HTTPException(status_code=404, detail=f"case_id {case_id!r} not found")


# For programmatic testing - clear state (not exposed publicly in prod, but safe for tests)
@app.post("/debug/clear", status_code=200)
async def debug_clear() -> dict[str, str]:
    with _lock:
        _received_ollama_reports.clear()
        _received_failures.clear()
        _failure_processed_ids.clear()
        _success_processed_ids.clear()
    logger.info("Logic Engine debug state cleared")
    return {"status": "cleared"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "logic_receive:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        reload=False,
    )
