from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware

from integration.adapters import (
    adapt_ai_assessment,
    adapt_email,
    adapt_iocs,
    adapt_security_analysis,
    adapt_threat_intelligence,
)

from logic.engine import LogicEngine
from logic.models import AnalysisInput
from logic_models import EvidencePackage
from ollama_model import LogicAnalysisReport
from pdf_report import build_report_pdf



# Load env from multiple locations: root .env and logic/.env (logic/.env takes precedence if present)
for _env_path in [
    os.path.join(os.path.dirname(__file__), ".env"),
    os.path.join(os.path.dirname(__file__), "logic", ".env"),
]:
    if os.path.exists(_env_path):
        load_dotenv(_env_path, override=False)
# also allow override from logic/.env specifically (for backward compat, second load with override)
load_dotenv(os.path.join(os.path.dirname(__file__), "logic", ".env"), override=True)

app = FastAPI(title="TRINETRA Logic Engine Receiver")
logic_engine = LogicEngine()

BACKEND_PUBLIC_URL = (os.getenv("BACKEND_PUBLIC_URL") or os.getenv("SUBHOM_BACKEND_URL") or "").rstrip("/")
LOGIC_PUBLIC_BASE_URL = os.getenv("LOGIC_PUBLIC_BASE_URL", "").rstrip("/")
# Feature flag: if true, still POST final result back to Subhom. Default false per new architecture —
# Logic Receiver is the source of truth and frontend polls it directly.
ENABLE_BACKEND_CALLBACK = os.getenv("ENABLE_BACKEND_CALLBACK", "false").lower() in ("1", "true", "yes")

print(f"[logic_receiver] BACKEND_PUBLIC_URL={BACKEND_PUBLIC_URL or '(not set)'}")
print(f"[logic_receiver] LOGIC_PUBLIC_BASE_URL={LOGIC_PUBLIC_BASE_URL or '(not set)'}")
print(f"[logic_receiver] ENABLE_BACKEND_CALLBACK={ENABLE_BACKEND_CALLBACK}")

# CORS configured at FastAPI app level (not inside endpoint) — per spec #10.
# Frontend directly calls GET /analysis/{case_id} from browser, so Logic Receiver must allow frontend origin.
cors_origins_raw = os.getenv(
    "LOGIC_CORS_ORIGINS",
    "http://localhost:5173,"
    "http://127.0.0.1:5173,"
    "http://localhost:3000,"
    "http://127.0.0.1:3000",
)
cors_origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]
print(f"[logic_receiver] CORS origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cases: dict[str, dict[str, Any]] = {}
cases_lock = asyncio.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_case() -> dict[str, Any]:
    return {
        "backend": None,
        "ollama": None,
        "ollama_failed": False,
        "ollama_failure": None,
        "email_raw": None,
        "status": "waiting",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "result": None,
        "error": None,
    }


def _log(case_id: str, message: str) -> None:
    # Unified prefix for filtering: [case_id] message
    print(f"[{case_id}] {message}")

def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalised_distance_to_verdict_boundary(
    score: int,
    thresholds: Any,
) -> float:
    """Return a deterministic verdict-stability score in [0, 1].

    A score close to a verdict boundary is inherently less stable than a
    score comfortably inside its band. This measures proximity to the
    configured server-side boundaries; it is not a transformation of risk
    into confidence and is never `100 - risk_score`.
    """
    boundaries = [
        int(thresholds.low_max),
        int(thresholds.medium_max),
        int(thresholds.high_max),
        int(thresholds.critical_max),
    ]
    if not boundaries:
        return 0.5

    distance = min(abs(int(score) - boundary) for boundary in boundaries)
    return _clamp01(distance / 15.0)


def _parse_header_auth_result(
    authentication_results: Any,
    mechanism: str,
) -> str | None:
    """Extract an authentication result from Authentication-Results text.

    Authentication result (e.g. dmarc=pass) is deliberately kept separate
    from the DMARC policy (e.g. p=none).
    """
    import re

    results = authentication_results if isinstance(authentication_results, list) else []

    for item in results:
        if not isinstance(item, str):
            continue

        match = re.search(
            rf"\b{re.escape(mechanism)}\s*=\s*(pass|fail|softfail|neutral|none)\b",
            item,
            re.IGNORECASE,
        )

        if match:
            return match.group(1).lower()

    return None


def _calculate_analysis_confidence(
    *,
    analysis_input: AnalysisInput,
    final_report: dict[str, Any],
    raw_security: dict[str, Any],
    raw_threat: dict[str, Any],
    raw_ai: dict[str, Any],
    grounding: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute a transparent, deterministic confidence score.

    This is an evidence-confidence metric for the returned risk decision.
    It is intentionally independent from the risk score itself: it uses
    evidence completeness, cross-signal agreement, provider coverage,
    authentication consistency, grounding provenance, and distance from the
    configured verdict boundaries. No random value and no `100 - risk`.
    """
    risk_score = int(final_report.get("risk_score") or 0)
    risk_fraction = _clamp01(risk_score / 100.0)

    # --------------------------- evidence completeness -----------------
    auth = raw_security.get("authentication_analysis")
    auth = auth if isinstance(auth, dict) else {}
    spf = analysis_input.security_analysis.spf.result
    dkim = analysis_input.security_analysis.dkim.result
    dmarc = analysis_input.security_analysis.dmarc.result
    known_auth = sum(
        value not in {"unknown", ""}
        for value in (spf, dkim, dmarc)
    ) / 3.0

    ai_probability_keys = (
        "phishing_probability",
        "bec_probability",
        "social_engineering_probability",
    )
    ai_complete = sum(key in raw_ai and raw_ai.get(key) is not None for key in ai_probability_keys) / 3.0
    email_complete = 1.0 if analysis_input.email is not None else 0.0
    security_complete = 1.0 if isinstance(auth, dict) else 0.0

    evidence_coverage = (
        0.45 * security_complete
        + 0.35 * known_auth
        + 0.10 * ai_complete
        + 0.10 * email_complete
    )

    # --------------------------- provider coverage ---------------------
    total_iocs = (
        len(analysis_input.iocs.ips)
        + len(analysis_input.iocs.domains)
        + len(analysis_input.iocs.urls)
        + len(analysis_input.iocs.hashes)
    )

    known_provider_results = 0
    if total_iocs:
        for item in analysis_input.threat_intelligence.ips:
            if "reputation_unknown" not in item.categories:
                known_provider_results += 1
        for item in analysis_input.threat_intelligence.domains:
            if "reputation_unknown" not in item.categories:
                known_provider_results += 1
        for item in analysis_input.threat_intelligence.urls:
            if "reputation_unknown" not in item.categories:
                known_provider_results += 1
        for item in analysis_input.threat_intelligence.hashes:
            if "reputation_unknown" not in item.categories:
                known_provider_results += 1
        provider_coverage = _clamp01(known_provider_results / total_iocs)
    else:
        # No extracted indicators is a valid finding, not missing evidence.
        provider_coverage = 1.0

    # --------------------------- authentication consistency -------------
    header_auth = raw_security.get("header_analysis")
    header_auth = header_auth if isinstance(header_auth, dict) else {}
    auth_results = header_auth.get("authentication_results")

    pairs = [
        (spf, _parse_header_auth_result(auth_results, "spf")),
        (dkim, _parse_header_auth_result(auth_results, "dkim")),
        (dmarc, _parse_header_auth_result(auth_results, "dmarc")),
    ]
    compared = [(structured, header) for structured, header in pairs if header is not None]
    if compared:
        consistent = sum(structured == header for structured, header in compared)
        authentication_consistency = consistent / len(compared)
    else:
        authentication_consistency = known_auth

    # --------------------------- AI + threat agreement -----------------
    ai_values = []
    for key in ai_probability_keys:
        value = raw_ai.get(key)
        if value is not None:
            try:
                ai_values.append(_clamp01(float(value)))
            except (TypeError, ValueError):
                pass
    ai_risk = max(ai_values) if ai_values else None
    ai_agreement = (
        _clamp01(1.0 - abs(ai_risk - risk_fraction))
        if ai_risk is not None
        else 0.5
    )

    analysed_reputations = []
    for item in analysis_input.threat_intelligence.ips:
        if "reputation_unknown" not in item.categories:
            analysed_reputations.append(item.reputation_score)
    for item in analysis_input.threat_intelligence.domains:
        if "reputation_unknown" not in item.categories:
            analysed_reputations.append(item.reputation_score)
    for item in analysis_input.threat_intelligence.urls:
        if "reputation_unknown" not in item.categories:
            analysed_reputations.append(item.reputation_score)
    for item in analysis_input.threat_intelligence.hashes:
        if "reputation_unknown" not in item.categories:
            analysed_reputations.append(item.reputation_score)

    if analysed_reputations:
        mean_reputation = sum(analysed_reputations) / len(analysed_reputations) / 100.0
        threat_agreement = _clamp01(1.0 - abs(mean_reputation - risk_fraction))
    else:
        threat_agreement = 0.5

    signal_agreement = 0.65 * ai_agreement + 0.35 * threat_agreement

    # --------------------------- grounding ------------------------------
    if isinstance(grounding, dict):
        grounded = grounding.get("grounded")
        refs = grounding.get("evidence_references") if isinstance(grounding.get("evidence_references"), list) else []
        unsupported = grounding.get("unsupported_claims") if isinstance(grounding.get("unsupported_claims"), list) else []
        if grounded is True:
            grounding_quality = 1.0 if refs else 0.80
        elif grounded is False:
            grounding_quality = 0.30
        else:
            grounding_quality = 0.50
        if unsupported:
            grounding_quality = max(0.0, grounding_quality - min(0.20, 0.05 * len(unsupported)))
    else:
        grounding_quality = 0.50

    # --------------------------- final confidence -----------------------
    verdict_stability = _normalised_distance_to_verdict_boundary(
        risk_score,
        logic_engine.verdict_engine.thresholds,
    )

    score = round(100.0 * (
        0.24 * evidence_coverage
        + 0.24 * signal_agreement
        + 0.18 * provider_coverage
        + 0.12 * authentication_consistency
        + 0.10 * grounding_quality
        + 0.12 * verdict_stability
    ))
    score = max(0, min(100, score))

    ai_available = bool(raw_ai)
    if not ai_available:
        # No Ollama signal: cap confidence so the report clearly communicates
        # that the decision is based only on Subhom security/threat evidence.
        score = min(score, 45)

    if score >= 85:
        label = "Very high"
    elif score >= 70:
        label = "High"
    elif score >= 55:
        label = "Moderate"
    else:
        label = "Low"

    rationale: list[str] = []
    if not ai_available:
        rationale.append("Ollama AI assessment was unavailable; the risk score uses Subhom security and threat signals only.")
    if authentication_consistency >= 0.999:
        rationale.append("Structured authentication results agree with Authentication-Results.")
    elif authentication_consistency < 0.5:
        rationale.append("Authentication sources disagree or are incomplete.")
    else:
        rationale.append("Authentication evidence is partially corroborated.")

    if provider_coverage >= 0.999:
        rationale.append("All extracted indicators have a usable provider result, or no indicators required lookup.")
    elif provider_coverage > 0:
        rationale.append("Some extracted indicators have provider results while others remain unknown.")
    else:
        rationale.append("Extracted indicators lack usable provider reputation results.")

    if verdict_stability >= 0.8:
        rationale.append("The risk score is comfortably inside its configured verdict band.")
    elif verdict_stability < 0.35:
        rationale.append("The risk score is close to a verdict boundary, reducing decision stability.")
    else:
        rationale.append("The risk score has moderate distance from its nearest verdict boundary.")

    return {
        "score": score,
        "label": label,
        "rationale": rationale,
        "factors": {
            "evidence_coverage": round(evidence_coverage * 100),
            "signal_agreement": round(signal_agreement * 100),
            "provider_coverage": round(provider_coverage * 100),
            "authentication_consistency": round(authentication_consistency * 100),
            "grounding_quality": round(grounding_quality * 100),
            "verdict_stability": round(verdict_stability * 100),
            "ai_availability": 100 if ai_available else 0,
        },
    }


async def process_case(case_id: str) -> None:
    async with cases_lock:
        case = cases.get(case_id)

        if case is None:
            return

        if case.get("status") != "waiting":
            return

        backend = case.get("backend")
        ollama = case.get("ollama")
        ollama_failed = bool(case.get("ollama_failed"))
        email_raw = case.get("email_raw")

        if backend is None or (ollama is None and not ollama_failed):
            return

        case["status"] = "processing"
        case["updated_at"] = utc_now()

    _log(case_id, "Calculating risk — security + threat inputs%s" % (" + Ollama" if ollama is not None else "; Ollama unavailable"))

    try:
        security = adapt_security_analysis(
            backend.security_analysis.model_dump(
                by_alias=True,
                mode="python",
            )
        )

        # Workflow 3 transport model -> internal ThreatIntelligence model.
        # IMPORTANT: do not instantiate the external ThreatAnalysisModel()
        # with no fields here. The backend payload has already been validated
        # into backend.threat_intelligence by EvidencePackage.
        raw_threat_intelligence = backend.threat_intelligence.model_dump(
            mode="python",
        )

        preliminary_threat = adapt_threat_intelligence(
            raw_threat_intelligence,
        )

        # Extract the authoritative IOC lists from the raw email when present;
        # otherwise adapt_iocs() falls back to the preliminary threat model.
        extracted_iocs = adapt_iocs(
            email_raw if isinstance(email_raw, dict) else None,
            preliminary_threat,
        )

        # Re-run the threat adapter with extracted_iocs so every extracted IOC
        # survives even when a provider returns no reputation result.
        threat = adapt_threat_intelligence(
            raw_threat_intelligence,
            extracted_iocs=extracted_iocs,
        )

        iocs = extracted_iocs

        if ollama is not None:
            ai_data = ollama.ai_assessment.model_dump(mode="python")

            model_info = dict(ai_data.get("model_info") or {})
            model_info["grounding"] = ollama.grounding.model_dump(mode="python")
            model_info["processing_time_seconds"] = ollama.processing_time_seconds
            model_info["processing_model_info"] = ollama.model_info.model_dump(mode="python")
            ai_data["model_info"] = model_info
            ai_assessment = adapt_ai_assessment(ai_data)
        else:
            ai_data = {}
            ai_assessment = adapt_ai_assessment({})

        email_meta = None

        if isinstance(email_raw, dict):
            try:
                email_meta = adapt_email(email_raw)
            except Exception:
                email_meta = None

        analysis_input = AnalysisInput(
            case_id=backend.case_id.strip(),
            email=email_meta,
            iocs=iocs,
            security_analysis=security,
            threat_intelligence=threat,
            ai_assessment=ai_assessment,
        )

        final_report = await asyncio.to_thread(
            logic_engine.get_detailed_report,
            analysis_input,
        )

        # Preserve the DNS payload for display without changing the internal
        # Pydantic SecurityAnalysis model. DNS is intentionally kept as an
        # additive response field because the internal schema does not define
        # a DNS property.
        security_for_frontend = security.model_dump(
            mode="json",
            by_alias=True,
        )
        raw_security = backend.security_analysis.model_dump(
            by_alias=True,
            mode="python",
        )
        raw_authentication = raw_security.get("authentication_analysis")
        if isinstance(raw_authentication, dict) and isinstance(raw_authentication.get("dns"), dict):
            security_for_frontend["dns"] = raw_authentication["dns"]

        confidence = _calculate_analysis_confidence(
            analysis_input=analysis_input,
            final_report=final_report,
            raw_security=raw_security,
            raw_threat=raw_threat_intelligence,
            raw_ai=ollama.ai_assessment.model_dump(mode="python") if ollama is not None else {},
            grounding=ollama.grounding.model_dump(mode="python") if ollama is not None else None,
        )

        # Enrich final_report with raw inputs for frontend display — not re-calculating risk.
        final_report.update({
            "analysis_confidence": confidence,
            "analysis_mode": "subhom_only" if ollama is None else "full",
            "confidence_explanation": (
                "Confidence is lower because Saikat's Ollama assessment failed, so TRINETRA used Subhom security/threat evidence without the independent AI signal. The risk score remains valid for the evidence received, but the report has less independent corroboration. Re-upload the email for a more precise report."
                if ollama is None else
                "Confidence measures how strongly the available evidence supports the risk decision. It combines evidence coverage, signal agreement, provider coverage, authentication consistency, grounding quality, verdict stability, and AI availability. It is not the probability that the email is safe or malicious."
            ),
            "security_analysis": security_for_frontend,
            "threat_intelligence": threat.model_dump(
                mode="json",
            ),
            "ai_assessment": (
                ollama.ai_assessment.model_dump(mode="json")
                if ollama is not None else ai_assessment.model_dump(mode="json")
            ),
            "iocs": iocs.model_dump(
                mode="json",
            ),
            "grounding": (
                ollama.grounding.model_dump(mode="json")
                if ollama is not None else None
            ),
            "processing_time_seconds": (ollama.processing_time_seconds if ollama is not None else final_report.get("processing_time_ms", 0) / 1000),
            "model_info": (
                ollama.model_info.model_dump(mode="json")
                if ollama is not None else {"model": "unavailable", "provider": "ollama", "version": "failed"}
            ),
            "email": (
                email_meta.model_dump(mode="json")
                if email_meta
                else None
            ),
            # Flatten aliases for spec compliance — frontend expects these at top in some integrations
            "case_id": backend.case_id.strip(),
            "analyzed_at": utc_now(),
        })

        # --- Store final result FIRST — Logic Receiver is source of truth (#5) ---
        async with cases_lock:
            case = cases.get(case_id)

            if case is not None:
                case["status"] = "completed"
                case["result"] = final_report
                case["updated_at"] = utc_now()
                case.pop("error", None)
                case.pop("callback_error", None)

        _log(case_id, f"Final risk calculated: score={final_report.get('risk_score')} verdict={final_report.get('verdict')}")
        _log(case_id, f"Final result stored — available via GET /analysis/{case_id}")

        # --- Optional backward-compat callback to Subhom (disabled by default) ---
        # The frontend MUST NOT depend on Subhom's /analysis/{case_id} (#4).
        # Only attempt callback if explicitly enabled via ENABLE_BACKEND_CALLBACK=true.
        if ENABLE_BACKEND_CALLBACK and BACKEND_PUBLIC_URL:
            try:
                _log(case_id, f"Callback enabled — POST {BACKEND_PUBLIC_URL}/receive-logic-result")
                response = await asyncio.to_thread(
                    requests.post,
                    f"{BACKEND_PUBLIC_URL}/receive-logic-result",
                    json={
                        "email_id": case_id,
                        "case_id": case_id,
                        "logic_analysis": final_report,
                    },
                    timeout=15,
                )
                response.raise_for_status()
                _log(case_id, "Backend callback succeeded")
            except Exception as exc:
                # Do not mark case as failed if callback fails — result is already stored.
                async with cases_lock:
                    c = cases.get(case_id)
                    if c is not None:
                        c["callback_error"] = str(exc)
                print(f"[logic_receiver] [{case_id}] Backend callback failed: {exc}")
        elif BACKEND_PUBLIC_URL and not ENABLE_BACKEND_CALLBACK:
            # Inform operator that result is NOT being pushed back — this is intentional per architecture.
            print(f"[logic_receiver] [{case_id}] Backend callback skipped (ENABLE_BACKEND_CALLBACK=false) — Logic Receiver retains result.")
        elif ENABLE_BACKEND_CALLBACK and not BACKEND_PUBLIC_URL:
            print(f"[logic_receiver] [{case_id}] ENABLE_BACKEND_CALLBACK=true but BACKEND_PUBLIC_URL not configured — skipping callback.")

    except Exception as exc:
        async with cases_lock:
            case = cases.get(case_id)

            if case is not None:
                case["status"] = "failed"
                case["error"] = str(exc)
                case["updated_at"] = utc_now()

        _log(case_id, f"Analysis failed: {exc}")
        print(f"[logic_receiver] process_case failed for {case_id}: {exc}")


async def handle_backend_evidence(
    data: dict[str, Any],
) -> dict[str, Any]:

    # New Main Backend contract preserves the original Workflow-1 parsed
    # email/IOC source inside the existing forensic_evidence field.
    # No Pydantic schema change is required.
    forensic_evidence = data.get("forensic_evidence")

    email_raw = None

    if isinstance(forensic_evidence, dict):
        candidate = forensic_evidence.get("parsed_email")
        if isinstance(candidate, dict):
            email_raw = candidate

    # Backward compatibility with older senders.
    if email_raw is None and isinstance(data.get("email"), dict):
        email_raw = data.get("email")

    # EvidencePackage may use extra="forbid". Remove only the legacy top-level
    # email key; preserve forensic_evidence exactly as received.
    data_for_validation = {
        k: v
        for k, v in data.items()
        if k != "email"
    }
    evidence = EvidencePackage.model_validate(data_for_validation)

    case_id = evidence.case_id.strip()

    if not case_id:
        raise HTTPException(
            status_code=422,
            detail="case_id cannot be empty.",
        )

    _log(case_id, "Security analysis received (backend evidence)")
    if email_raw is not None:
        _log(case_id, "Email metadata received")

    async with cases_lock:

        if case_id not in cases:
            cases[case_id] = create_case()

        case = cases[case_id]

        if case["status"] == "completed":
            _log(case_id, "Duplicate backend evidence — already completed, returning cached result")
            return {
                "case_id": case_id,
                "status": "already_completed",
                "result": case.get("result"),
            }

        case["backend"] = evidence

        if email_raw is not None:
            case["email_raw"] = email_raw

        case["updated_at"] = utc_now()

        should_process = case.get("ollama") is not None or bool(case.get("ollama_failed"))

        if should_process:
            case["status"] = "waiting"
            _log(case_id, "Backend + Ollama outcome present — will calculate final risk")
        elif case["status"] != "processing":
            case["status"] = "waiting"
            _log(case_id, "Backend stored, waiting for Ollama analysis")

    if should_process:
        asyncio.create_task(process_case(case_id))

    return {
        "case_id": case_id,
        "status": "accepted",
        "message": "Backend evidence accepted.",
    }


async def handle_ollama_report(
    data: dict[str, Any],
) -> dict[str, Any]:

    def contains_ollama_failure(value: Any, depth: int = 0) -> bool:
        if depth > 8 or value is None:
            return False
        if isinstance(value, str):
            return value.strip().upper() == "OLLAMA FAILED"
        if isinstance(value, list):
            return any(contains_ollama_failure(item, depth + 1) for item in value)
        if isinstance(value, dict):
            return any(contains_ollama_failure(item, depth + 1) for item in value.values())
        return False

    if contains_ollama_failure(data):
        case_id = str(data.get("case_id") or data.get("email_id") or "").strip()
        if not case_id:
            raise HTTPException(status_code=422, detail="OLLAMA Failed signal must include case_id.")
        _log(case_id, "Ollama returned OLLAMA Failed — falling back to Subhom-only scoring")
        async with cases_lock:
            if case_id not in cases:
                cases[case_id] = create_case()
            case = cases[case_id]
            if case["status"] == "completed":
                return {"case_id": case_id, "status": "already_completed", "result": case.get("result")}
            case["ollama"] = None
            case["ollama_failed"] = True
            case["updated_at"] = utc_now()
            should_process = case.get("backend") is not None
            if should_process:
                case["status"] = "waiting"
        if should_process:
            asyncio.create_task(process_case(case_id))
        return {"case_id": case_id, "status": "accepted", "message": "Ollama failure accepted; Subhom-only fallback enabled.", "ollama_failed": True}

    report = LogicAnalysisReport.model_validate(data)

    case_id = report.case_id.strip()

    if not case_id:
        raise HTTPException(
            status_code=422,
            detail="case_id cannot be empty.",
        )

    _log(case_id, "Ollama analysis received")

    async with cases_lock:

        if case_id not in cases:
            cases[case_id] = create_case()

        case = cases[case_id]

        if case["status"] == "completed":
            _log(case_id, "Duplicate Ollama report — already completed")
            return {
                "case_id": case_id,
                "status": "already_completed",
                "result": case.get("result"),
            }

        case["ollama"] = report
        case["updated_at"] = utc_now()

        should_process = case.get("backend") is not None

        if should_process:
            case["status"] = "waiting"
            _log(case_id, "Both backend and Ollama present — will calculate final risk")

        else:
            _log(case_id, "Ollama stored, waiting for backend evidence")

    if should_process:
        asyncio.create_task(process_case(case_id))

    return {
        "case_id": case_id,
        "status": "accepted",
        "message": "Ollama analysis accepted.",
    }


@app.post("/receive-analysis", status_code=202)
async def receive_analysis(
    data: dict[str, Any],
) -> dict[str, Any]:

    # Do not log the complete email/security payload.
    print(
        "[logic_receiver] POST /receive-analysis received",
        flush=True,
    )

    try:
        return await handle_backend_evidence(data)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid backend evidence.",
        ) from exc





@app.post("/receive-ollama", status_code=202)
async def receive_ollama_analysis(
    data: dict[str, Any],
) -> dict[str, Any]:

    # Do not log the complete AI payload.
    print(
        "[logic_receiver] POST /receive-ollama received",
        flush=True,
    )

    try:
        return await handle_ollama_report(data)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid Ollama analysis.",
        ) from exc


@app.post("/receive-ollama-failure", status_code=202)
async def receive_ollama_failure(
    data: dict[str, Any],
) -> dict[str, Any]:
    """Receive an explicit Ollama failure without fabricating AI evidence."""

    case_id = str(
        data.get("case_id")
        or data.get("email_id")
        or ""
    ).strip()

    if not case_id:
        raise HTTPException(
            status_code=422,
            detail="Ollama failure event must include case_id.",
        )

    _log(
        case_id,
        "Ollama failure received; deterministic fallback enabled.",
    )

    async with cases_lock:
        if case_id not in cases:
            cases[case_id] = create_case()

        case = cases[case_id]

        if case["status"] == "completed":
            return {
                "case_id": case_id,
                "status": "already_completed",
                "result": case.get("result"),
            }

        case["ollama"] = None
        case["ollama_failed"] = True
        case["ollama_failure"] = {
            "failure_stage": data.get("failure_stage", "unknown"),
            "failure_type": data.get("failure_type", "UnknownError"),
            "error": str(data.get("error", "Ollama failed"))[:2000],
        }
        case["updated_at"] = utc_now()

        should_process = case.get("backend") is not None

        if should_process:
            case["status"] = "waiting"

    if should_process:
        asyncio.create_task(process_case(case_id))

    return {
        "case_id": case_id,
        "status": "accepted",
        "message": "Ollama failure accepted; deterministic fallback enabled.",
        "ollama_failed": True,
    }


# Aliases for alternative naming (README mentions /receive-subhom-analysis and /receive-ai-analysis)
@app.post("/receive-subhom-analysis", status_code=202)
async def receive_subhom_analysis_alias(data: dict[str, Any]) -> dict[str, Any]:
    try:
        return await handle_backend_evidence(data)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid Subhom analysis.") from exc


@app.post("/receive-ai-analysis", status_code=202)
async def receive_ai_analysis_alias(data: dict[str, Any]) -> dict[str, Any]:
    try:
        return await handle_ollama_report(data)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid AI analysis.") from exc





@app.post("/receive-backend", status_code=202)
async def receive_backend_alias(
    data: dict[str, Any],
) -> dict[str, Any]:

    if "ai_assessment" in data:
        try:
            return await handle_ollama_report(data)
        except Exception:
            pass

    try:
        return await handle_backend_evidence(data)

    except Exception:
        try:
            return await handle_ollama_report(data)

        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail="Invalid payload for /receive-backend.",
            ) from exc


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "service": "trinetra-logic-engine",
        "status": "healthy",
    }


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "service": "trinetra-logic-engine",
        "status": "healthy",
        "endpoints": [
            "/health",
            "/analysis/{case_id}",
            "/cases",
            "/pending",
            "/receive-analysis",
            "/receive-ollama",
            "/receive-ollama-failure",
        ],
    }


@app.get("/cases")
async def list_cases() -> dict[str, Any]:

    async with cases_lock:

        summary = {
            case_id: {
                "status": case.get("status"),
                "has_backend": (
                    case.get("backend") is not None
                ),
                "has_ollama": (
                    case.get("ollama") is not None
                ),
                "has_result": (
                    case.get("result") is not None
                ),
                "created_at": case.get("created_at"),
                "updated_at": case.get("updated_at"),
                "error": case.get("error"),
                "callback_error": case.get(
                    "callback_error"
                ),
                "ollama_failed": bool(
                    case.get("ollama_failed")
                ),
            }
            for case_id, case in cases.items()
        }

    return {
        "count": len(summary),
        "cases": summary,
    }


@app.get("/pending")
async def list_pending() -> dict[str, Any]:
    """Backward-compat alias for /cases — shows pending summary."""
    return await list_cases()



async def _build_case_pdf(case_id: str, client_payload: dict[str, Any] | None = None):
    case_id = case_id.strip()
    if not case_id:
        raise HTTPException(status_code=422, detail="case_id cannot be empty.")
    async with cases_lock:
        case = cases.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
        if case.get("status") != "completed" or not case.get("result"):
            raise HTTPException(status_code=409, detail="The analysis is not complete yet.")
        result = dict(case["result"])
    # The browser owns the original EML bytes. Accept them only as display input
    # for the PDF; all scored analysis fields remain sourced from the stored result.
    if isinstance(client_payload, dict):
        provided = client_payload.get("provided_email")
        if isinstance(provided, str) and provided:
            result["provided_email"] = provided
    try:
        pdf_bytes = await asyncio.to_thread(build_report_pdf, result)
    except Exception as exc:
        _log(case_id, f"PDF export failed: {exc}")
        raise HTTPException(status_code=500, detail="Unable to generate the PDF report.") from exc
    safe_id = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="TRINETRA_Report_{safe_id}.pdf"'},
    )


@app.get("/analysis/{case_id}/pdf")
async def export_analysis_pdf(case_id: str):
    return await _build_case_pdf(case_id)


@app.post("/analysis/{case_id}/pdf")
async def export_analysis_pdf_with_email(case_id: str, data: dict[str, Any] | None = None):
    return await _build_case_pdf(case_id, data)


@app.get("/analysis/{case_id}")
async def get_analysis(case_id: str) -> dict[str, Any]:
    """
    Source of truth for final result — per architecture #5.
    Frontend polls this directly (no Subhom round-trip).

    Processing: 200 {status:"processing", case_id}
    Completed: 200 {status:"completed", case_id, risk_score, verdict, ...result}
    Failed:    200 {status:"failed", case_id, error}
    Not found: 404
    """

    case_id = case_id.strip()

    if not case_id:
        raise HTTPException(
            status_code=422,
            detail="case_id cannot be empty.",
        )

    print(f"[{case_id}] GET /analysis")

    async with cases_lock:

        case = cases.get(case_id)

        if case is None:
            raise HTTPException(
                status_code=404,
                detail=f"Case {case_id} not found.",
            )

        status = case.get("status")

        if status == "completed":
            result = case.get("result") or {}
            # Ensure top-level risk_score/verdict plus full payload for frontend compatibility.
            # Frontend normalizeReport handles both `result` nesting and top-level fields.
            response: dict[str, Any] = {
                "case_id": case_id,
                "status": "completed",
                "risk_score": result.get("risk_score"),
                "verdict": result.get("verdict"),
                "result": result,
                # Aliases that frontend and spec may expect
                "analysis": result,
                "logic_analysis": result,
                "email": result.get("email"),
                "security_analysis": result.get("security_analysis"),
                "threat_intelligence": result.get("threat_intelligence"),
                "threat_analysis": result.get("threat_intelligence"),
                "ai_assessment": result.get("ai_assessment"),
                "iocs": result.get("iocs"),
                "grounding": result.get("grounding"),
                "model_info": result.get("model_info"),
                "reasons": result.get("reasons"),
                "correlations": result.get("correlations"),
                "correlations_by_severity": result.get("correlations_by_severity"),
                "score_breakdown": result.get("score_breakdown"),
                "triggered_rules": result.get("triggered_rules"),
                "verdict_info": result.get("verdict_info"),
                "analysis_confidence": result.get("analysis_confidence"),
                "analysis_mode": result.get("analysis_mode"),
                "confidence_explanation": result.get("confidence_explanation"),
                "processing_time_ms": result.get("processing_time_ms"),
                "analyzed_at": result.get("analyzed_at") or case.get("updated_at"),
                "updated_at": case.get("updated_at"),
                "created_at": case.get("created_at"),
            }
            # Include source_file if present in result, otherwise minimal
            if result.get("source_file"):
                response["source_file"] = result["source_file"]
            if case.get("callback_error"):
                response["callback_error"] = case.get("callback_error")
            # Prune None verdict/risk_score keys if somehow missing (should not happen)
            return response

        if status == "failed":
            return {
                "case_id": case_id,
                "status": "failed",
                "error": case.get(
                    "error",
                    "Analysis failed.",
                ),
                "updated_at": case.get("updated_at"),
                "created_at": case.get("created_at"),
            }

        # processing / waiting
        print(f"[{case_id}] Analysis status: processing (has_backend={case.get('backend') is not None}, has_ollama={case.get('ollama') is not None})")
        return {
            "case_id": case_id,
            "status": "processing",
            "detail": "Analysis is still processing.",
            "updated_at": case.get("updated_at"),
            "created_at": case.get("created_at"),
            "has_backend": (
                case.get("backend") is not None
            ),
            "has_ollama": (case.get("ollama") is not None),
            "ollama_failed": bool(case.get("ollama_failed")),
        }


