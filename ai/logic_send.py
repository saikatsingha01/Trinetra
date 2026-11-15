from __future__ import annotations

import os
from dataclasses import asdict, is_dataclass
from typing import Any

import time

import requests

from logic_model import LogicAnalysisReport


LOGIC_PUBLIC_URL = os.getenv(
    "LOGIC_PUBLIC_URL",
    "",
).rstrip("/")

LOGIC_TIMEOUT_SECONDS = float(
    os.getenv(
        "LOGIC_TIMEOUT_SECONDS",
        "30",
    )
)

LOGIC_FAILURE_PATH = os.getenv(
    "LOGIC_FAILURE_PATH",
    "/receive-ollama-failure",
)

# Ensure failure path starts with slash for consistent joining
if LOGIC_FAILURE_PATH and not LOGIC_FAILURE_PATH.startswith("/"):
    LOGIC_FAILURE_PATH = "/" + LOGIC_FAILURE_PATH


# ============================================================
# Ollama Failure Notification (SEPARATE from LogicAnalysisReport)
# ============================================================
# This model is intentionally NOT LogicAnalysisReport. A failed Ollama run
# must NOT be wrapped as a fake successful analysis with fabricated
# probabilities. It is a distinct event that tells the Logic Engine:
# "Ollama has failed" for this case_id, with machine-readable failure context.
#
# Logic Engine side requirement: expose POST {LOGIC_PUBLIC_URL}/receive-ollama-failure
# (or the path configured via LOGIC_FAILURE_PATH) that accepts this payload.
# If the existing Logic Engine only exposes /receive-ollama for
# LogicAnalysisReport, the minimum interface change is to add this single
# failure endpoint. Do NOT extend LogicAnalysisReport to carry failure flags.
from pydantic import BaseModel, ConfigDict, Field


class OllamaFailureNotification(BaseModel):
    """
    Explicit Ollama failure event sent to the Logic Engine.

    This is NOT a LogicAnalysisReport and must never be confused with one.
    It carries the semantic message "Ollama has failed" plus machine-readable
    context so the Logic Engine can correlate and diagnose.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., description="Original case identifier preserved from backend")
    component: str = Field(default="ollama", description="Component that failed")
    status: str = Field(default="failed", description="Status marker for this event")
    message: str = Field(default="Ollama has failed", description="Semantic failure message")
    failure_stage: str = Field(..., description="Pipeline stage where failure occurred, e.g. llm_output_schema")
    failure_type: str = Field(..., description="Exception type name, e.g. PipelineValidationError")
    error: str = Field(..., description="Human-readable error summary (truncated)")


def build_ollama_failure_payload(
    case_id: str,
    failure_stage: str,
    failure_type: str,
    error: str,
) -> OllamaFailureNotification:
    """Build a validated Ollama failure notification without fabricating analysis."""
    # Bound error length so one huge traceback cannot dominate the payload.
    err = str(error) if error is not None else failure_type
    if len(err) > 2000:
        err = err[:2000] + "..."
    stage = str(failure_stage).strip() or "unknown"
    ftype = str(failure_type).strip() or "UnknownError"
    return OllamaFailureNotification(
        case_id=str(case_id),
        component="ollama",
        status="failed",
        message="Ollama has failed",
        failure_stage=stage,
        failure_type=ftype,
        error=err,
    )


def send_ollama_failure(
    case_id: str,
    exc: Exception | None = None,
    failure_stage: str | None = None,
    failure_type: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """
    Send an explicit Ollama failure notification to the Logic Engine.

    This is the failure path for the Ollama component. It does NOT send a
    LogicAnalysisReport and does NOT fabricate probabilities.

    Endpoint: POST {LOGIC_PUBLIC_URL}{LOGIC_FAILURE_PATH}
    Default path is /receive-ollama-failure. Configure via LOGIC_FAILURE_PATH
    if the Logic Engine exposes a generic status/event endpoint instead.

    Raises on delivery failure so the caller can log the failure of the
    failure notification without recursively generating another event.
    """
    if not LOGIC_PUBLIC_URL:
        raise RuntimeError("LOGIC_PUBLIC_URL is not configured")

    # Resolve stage/type/error from explicit args or from the exception.
    # Clear precedence: 1) explicitly supplied failure_stage, 2) exc.stage, 3) None/unknown.
    if failure_stage:
        stage = failure_stage
    elif exc is not None:
        stage = getattr(exc, "stage", None)
    else:
        stage = None
    if not stage or not str(stage).strip():
        stage = "unknown"
    else:
        stage = str(stage).strip()

    ftype = failure_type or (type(exc).__name__ if exc is not None else "UnknownError")
    err_str = error if error is not None else (str(exc) if exc is not None else ftype)

    report = build_ollama_failure_payload(
        case_id=case_id,
        failure_stage=stage,
        failure_type=ftype,
        error=err_str,
    )

    payload = report.model_dump(mode="json")

    if not report.case_id or not report.case_id.strip():
        raise ValueError("Ollama failure notification case_id is empty")

    url = f"{LOGIC_PUBLIC_URL}{LOGIC_FAILURE_PATH}"

    response = None
    last_exc: Exception | None = None

    for attempt in range(5):
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=LOGIC_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            # Success - return parsed JSON if present, else minimal ack.
            if not response.content:
                return {
                    "status": "accepted",
                    "status_code": response.status_code,
                    "case_id": report.case_id,
                    "failure_stage": stage,
                }
            try:
                data = response.json()
            except ValueError:
                return {
                    "status": "accepted",
                    "status_code": response.status_code,
                    "case_id": report.case_id,
                    "failure_stage": stage,
                    "body": response.text,
                }
            if isinstance(data, dict):
                return data
            return {
                "status": "accepted",
                "status_code": response.status_code,
                "case_id": report.case_id,
                "failure_stage": stage,
                "result": data,
            }
        except requests.exceptions.RequestException as exc_req:
            last_exc = exc_req
            # Determine if this is a deterministic client error that should fail fast.
            # 404 means endpoint does not exist / route wrong - retrying is pointless.
            # Same for 400, 401, 403, 405, 422 etc. Only 408, 429 and 5xx / network are retryable.
            status_code: int | None = None
            # HTTPError carries response; ConnectionError/Timeout do not
            resp = getattr(exc_req, "response", None)
            if resp is not None:
                try:
                    status_code = int(resp.status_code)  # type: ignore[attr-defined]
                except Exception:
                    status_code = None
            elif response is not None:
                # Fallback if exception has no response but we have last response
                try:
                    status_code = int(response.status_code)  # type: ignore[attr-defined]
                except Exception:
                    status_code = None

            is_deterministic_client_error = (
                status_code is not None and 400 <= status_code < 500 and status_code not in (408, 429)
            )
            if is_deterministic_client_error:
                print(
                    f"Ollama failure delivery deterministic error {status_code} (attempt {attempt + 1}/5) case_id={case_id} stage={stage}: {exc_req} - failing fast, no retry",
                    flush=True,
                )
                # Do not retry deterministic errors - break out immediately
                break

            # Transient / retryable: 429, 5xx, timeout, connection errors, 408
            print(
                f"Ollama failure delivery failed (attempt {attempt + 1}/5) case_id={case_id} stage={stage}: {exc_req}",
                flush=True,
            )
            if attempt < 4:
                # Only sleep if we will retry (not for deterministic which already broke)
                time.sleep(3)
            # For 429 we could respect Retry-After, but keep bounded 3s for minimal change
            continue

    # All attempts exhausted
    if last_exc is not None:
        raise RuntimeError(
            f"Ollama failure delivery failed after 5 attempts case_id={case_id} stage={stage}: {last_exc}"
        ) from last_exc
    raise RuntimeError(
        f"Ollama failure delivery failed after 5 attempts case_id={case_id} stage={stage}"
    )


# ============================================================
# Generic serialization helpers
# ============================================================

def _to_jsonable(value: Any) -> Any:
    """
    Convert the Ollama PipelineResult and its nested objects into
    ordinary JSON-compatible Python structures.
    """

    # Pydantic v2 model
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return value.model_dump(
            mode="json"
        )

    # Dataclass
    if is_dataclass(value) and not isinstance(value, type):
        return _to_jsonable(
            asdict(value)
        )

    # Dictionary
    if isinstance(value, dict):
        return {
            str(key): _to_jsonable(item)
            for key, item in value.items()
        }

    # List / tuple
    if isinstance(value, (list, tuple)):
        return [
            _to_jsonable(item)
            for item in value
        ]

    # Set
    if isinstance(value, set):
        return [
            _to_jsonable(item)
            for item in value
        ]

    return value


# ============================================================
# Build Logic report
# ============================================================

def build_logic_report(
    result: Any,
) -> LogicAnalysisReport:
    """
    Convert the completed Ollama PipelineResult into the exact
    Pydantic structure defined by logic_model.py.

    The Logic model is the final source of truth for the outgoing
    Ollama -> Logic contract.
    """

    # ---------------------------------------------------------
    # Convert the Ollama result to ordinary JSON-compatible data.
    # ---------------------------------------------------------

    raw_result = _to_jsonable(result)

    if not isinstance(raw_result, dict):
        raise TypeError(
            "Ollama PipelineResult must serialize to a dictionary"
        )

    # ---------------------------------------------------------
    # Validate the complete outgoing structure using ONLY
    # logic_model.py.
    #
    # This is preferable to manually constructing nested model
    # dictionaries because Pydantic performs the actual type
    # validation here.
    # ---------------------------------------------------------

    try:
        return LogicAnalysisReport.model_validate(
            raw_result
        )

    except Exception as exc:
        raise ValueError(
            "Ollama result does not match the Logic Engine "
            "Pydantic contract: "
            f"{exc}"
        ) from exc


# ============================================================
# Send Ollama result -> Logic Engine
# ============================================================

def send_to_logic(
    result: Any,
) -> dict[str, Any]:
    """
    Send the completed Ollama analysis report to the Logic Engine.

    Direction:

        Ollama -> Logic

    No Logic analysis result is required in return.
    """

    if not LOGIC_PUBLIC_URL:
        raise RuntimeError(
            "LOGIC_PUBLIC_URL is not configured"
        )

    # ---------------------------------------------------------
    # 1. Convert + validate against logic_model.py.
    # ---------------------------------------------------------

    report = build_logic_report(
        result
    )

    # ---------------------------------------------------------
    # 2. Serialize the validated Pydantic model.
    # ---------------------------------------------------------

    payload = report.model_dump(
        mode="json"
    )

    # ---------------------------------------------------------
    # 3. Preserve the original case_id.
    #
    # This MUST remain the same ID produced by the backend and
    # carried through the Ollama pipeline.
    # ---------------------------------------------------------

    if not report.case_id:
        raise ValueError(
            "Logic report case_id is empty"
        )

    # ---------------------------------------------------------
    # 4. POST to the Logic Engine.
    # ---------------------------------------------------------

    response = None

    for attempt in range(5):
        try:
            response = requests.post(
                f"{LOGIC_PUBLIC_URL}/receive-ollama",
                json=payload,
                timeout=LOGIC_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            # A successful Logic Engine delivery is valid even when the
            # acknowledgement body is empty or not JSON. Do not convert that
            # successful HTTP status into a false delivery failure.
            if not response.content:
                return {
                    "status": "accepted",
                    "status_code": response.status_code,
                    "case_id": report.case_id,
                }

            try:
                response_data = response.json()
            except ValueError:
                return {
                    "status": "accepted",
                    "status_code": response.status_code,
                    "case_id": report.case_id,
                    "body": response.text,
                }

            if isinstance(response_data, dict):
                return response_data

            return {
                "status": "accepted",
                "status_code": response.status_code,
                "case_id": report.case_id,
                "result": response_data,
            }

        except requests.exceptions.RequestException as exc:
            print(
                f"Logic delivery failed (attempt {attempt + 1}/5): {exc}",
                flush=True,
            )
            if attempt < 4:
                time.sleep(3)

    raise RuntimeError(
        f"Logic delivery failed after 5 attempts for case_id={report.case_id}"
    )
