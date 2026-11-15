# from __future__ import annotations

# from dataclasses import dataclass, replace
# from typing import Any
# import time

# from src.ai.contracts import EvidencePackage, AIAssessment, ForensicFinding
# from src.ai.security import (
#     InputGuardError,
#     validate_evidence_package,
#     isolate_evidence,
#     IsolatedEvidence,
# )
# from src.ai.normalization import normalize_evidence, NormalizedEvidence
# from src.ai.understanding import analyze_email, UnderstandingResult
# from src.ai.prompting import build_analysis_context, build_prompt_request, AnalysisContext, PromptRequest
# from src.ai.llm import create_ollama_client, LLMResponse, OllamaClientError, OllamaConnectionError, OllamaTimeoutError, OllamaHTTPError, OllamaModelNotFoundError
# from src.ai.validation import validate_llm_output, LLMExtractionError, LLMJSONParseError, LLMSchemaValidationError
# from src.ai.results import check_grounding, GroundingResult


# class PipelineError(Exception):
#     def __init__(self, message: str, stage: str | None = None):
#         super().__init__(message)
#         self.stage = stage


# class PipelineInputError(PipelineError):
#     pass


# class PipelineLLMError(PipelineError):
#     pass


# class PipelineValidationError(PipelineError):
#     pass


# @dataclass(frozen=True)
# class PipelineResult:
#     case_id: str
#     ai_assessment: AIAssessment
#     grounding: GroundingResult
#     processing_time_seconds: float
#     model_info: dict[str, Any]


# def analyze(evidence_package: EvidencePackage) -> PipelineResult:
#     """
#     Main entry point: run the complete AI forensic analysis pipeline.
#     """

#     start_time = time.time()

#     # 1. INPUT SECURITY
#     t = time.time()
#     try:
#         validate_evidence_package(evidence_package)
#     except InputGuardError as e:
#         raise PipelineInputError(
#             f"Input validation failed: {e}",
#             stage="input_guard"
#         ) from e
#     print(f"[PIPELINE] Input validation: {time.time() - t:.3f}s", flush=True)

#     # 2. CONTENT ISOLATION
#     t = time.time()
#     isolated_evidence = isolate_evidence(evidence_package)
#     print(f"[PIPELINE] Content isolation: {time.time() - t:.3f}s", flush=True)

#     # 3. NORMALIZATION
#     t = time.time()
#     normalized_evidence = normalize_evidence(isolated_evidence)
#     print(f"[PIPELINE] Normalization: {time.time() - t:.3f}s", flush=True)

#     # 4. UNDERSTANDING
#     t = time.time()
#     understanding = analyze_email(normalized_evidence)
#     print(f"[PIPELINE] Understanding: {time.time() - t:.3f}s", flush=True)

#     # 5. CONTEXT
#     t = time.time()
#     context = build_analysis_context(
#         normalized_evidence,
#         understanding
#     )
#     print(f"[PIPELINE] Context building: {time.time() - t:.3f}s", flush=True)

#     # 6. PROMPT
#     t = time.time()
#     prompt_request = build_prompt_request(context)
#     prompt_time = time.time() - t

#     print(
#         f"[PIPELINE] Prompt building: {prompt_time:.3f}s",
#         flush=True
#     )

#     print(
#         f"[PIPELINE] System prompt chars: "
#         f"{len(prompt_request.system_prompt):,}",
#         flush=True
#     )

#     print(
#         f"[PIPELINE] User prompt chars: "
#         f"{len(prompt_request.user_prompt):,}",
#         flush=True
#     )

#     # 7. LLM
#     print("[PIPELINE] >>> START OLLAMA INFERENCE", flush=True)
#     t = time.time()

#     llm_response = _call_llm(prompt_request)

#     llm_time = time.time() - t

#     print(
#         f"[PIPELINE] <<< OLLAMA INFERENCE FINISHED: "
#         f"{llm_time:.3f}s",
#         flush=True
#     )

#     print(
#         f"[PIPELINE] LLM response chars: "
#         f"{len(llm_response.content):,}",
#         flush=True
#     )

#     # 8. VALIDATION
#     t = time.time()

#     try:
#         ai_assessment = validate_llm_output(
#             llm_response.content
#         )
#     except (LLMExtractionError, LLMJSONParseError) as e:
#         raise PipelineValidationError(
#             f"Failed to extract/parse LLM output: {e}",
#             stage="llm_output_extraction"
#         ) from e
#     except LLMSchemaValidationError as e:
#         raise PipelineValidationError(
#             f"LLM output failed schema validation: {e}",
#             stage="llm_output_schema"
#         ) from e

#     print(
#         f"[PIPELINE] Output validation: "
#         f"{time.time() - t:.3f}s",
#         flush=True
#     )

#     # 9. GROUNDING
#     t = time.time()

#     grounding = check_grounding(
#         ai_assessment,
#         context,
#         understanding
#     )

#     # print(
#     #     f"[PIPELINE] Grounding: "
#     #     f"{time.time() - t:.3f}s",
#     #     flush=True
#     # )
#     print(
#     f"[PIPELINE] Grounding: "
#     f"{time.time() - t:.3f}s | "
#     f"grounded={grounding.grounded} | "
#     f"unsupported_claims={len(grounding.unsupported_claims)} | "
#     f"evidence_refs={len(grounding.evidence_references)}",
#     flush=True
# )

#     # 10. RECONCILIATION
#     t = time.time()

#     ai_assessment = _reconcile_assessment(
#         ai_assessment,
#         context,
#         understanding,
#         grounding
#     )

#     print(
#         f"[PIPELINE] Reconciliation: "
#         f"{time.time() - t:.3f}s",
#         flush=True
#     )

#     # 11. RE-GROUND
#     if grounding and not grounding.grounded:
#         t = time.time()

#         grounding = check_grounding(
#             ai_assessment,
#             context,
#             understanding
#         )

#         print(
#             f"[PIPELINE] Re-grounding: "
#             f"{time.time() - t:.3f}s",
#             flush=True
#         )

#     elapsed = time.time() - start_time

#     print(
#         f"[PIPELINE] TOTAL: {elapsed:.3f}s",
#         flush=True
#     )

#     return PipelineResult(
#         case_id=evidence_package.case_id,
#         ai_assessment=ai_assessment,
#         grounding=grounding,
#         processing_time_seconds=elapsed,
#         model_info={
#             "model": (
#                 ai_assessment.model_info.model_name
#                 if ai_assessment.model_info
#                 else "unknown"
#             ),
#             "provider": (
#                 ai_assessment.model_info.provider
#                 if ai_assessment.model_info
#                 else "unknown"
#             ),
#             "version": (
#                 ai_assessment.model_info.model_version
#                 if ai_assessment.model_info
#                 else "unknown"
#             ),
#         },
#     )

# def _reconcile_assessment(
#     ai_assessment: AIAssessment,
#     context: AnalysisContext,
#     understanding: UnderstandingResult,
#     grounding: GroundingResult,
# ) -> AIAssessment:
#     """
#     Reconcile AI assessment with forensic evidence and grounding results.
    
#     Corrects boolean fields and findings that the LLM may have missed or gotten wrong,
#     based on the forensic evidence and grounding results.
#     """
#     # Use replace to create a new instance with corrected values
#     updates = {}

#     # Deterministic credential reconciliation — understanding layer is authoritative
#     # Banking/account update (financial/phishing) is NOT credential harvesting
#     if ai_assessment.credential_request_detected and not understanding.credential_request:
#         updates["credential_request_detected"] = False
    
#     # Check malicious_attachment_detected
#     forensic_evidence = getattr(context, "forensic_evidence", {})
#     if not ai_assessment.malicious_attachment_detected:
#         # Check if forensic evidence explicitly indicates malicious attachment
#         attachments = forensic_evidence.get("attachments", [])
#         if isinstance(attachments, list):
#             for attachment in attachments:
#                 if isinstance(attachment, dict):
#                     # Check direct malicious flag
#                     if attachment.get("malicious") is True:
#                         updates["malicious_attachment_detected"] = True
#                         break
#                     # Check nested malicious flag in embedded files
#                     analysis = attachment.get("analysis", {})
#                     if isinstance(analysis, dict):
#                         embedded = analysis.get("embedded_files", [])
#                         if isinstance(embedded, list):
#                             for embedded in embedded:
#                                 if isinstance(embedded, dict) and embedded.get("malicious") is True:
#                                     updates["malicious_attachment_detected"] = True
#                                     break
#                             if updates.get("malicious_attachment_detected"):
#                                 break
    
#     # Check attachment_risk_detected
#     if not ai_assessment.attachment_risk_detected:
#         # Risk exists if any forensic indicator suggests risk
#         if understanding.forensic_indicators:
#             risk_indicators = {
#                 "malicious_attachment", "suspicious_attachment", "known_malicious_hash",
#                 "attachment_threat_intelligence_match", "malware_detected",
#                 "high_abuse_confidence", "sandbox_verdict_malicious"
#             }
#             for indicator in understanding.forensic_indicators:
#                 if indicator.indicator in risk_indicators:
#                     updates["attachment_risk_detected"] = True
#                     break
#         # Also consider attachment threat intelligence (VirusTotal) for risk
#         # 6/68 positives with Suspicious.Zip/Trojan.Generic is risk but NOT explicit malicious
#         if not updates.get("attachment_risk_detected"):
#             ti = getattr(context, "threat_intelligence", {}) or {}
#             if isinstance(ti, dict):
#                 attachment_analysis = ti.get("attachment_analysis", {})
#                 if isinstance(attachment_analysis, dict):
#                     vt_reports = attachment_analysis.get("virusTotal_report", [])
#                     if isinstance(vt_reports, list):
#                         for report in vt_reports:
#                             if not isinstance(report, dict):
#                                 continue
#                             positives = report.get("positives", 0)
#                             try:
#                                 pos_val = int(positives)
#                             except (TypeError, ValueError):
#                                 pos_val = 0
#                             if pos_val > 0:
#                                 scan_results = report.get("scan_results", {})
#                                 if isinstance(scan_results, dict) and scan_results:
#                                     for eng in scan_results.values():
#                                         if isinstance(eng, dict) and eng.get("detected") is True:
#                                             result_str = str(eng.get("result", "")).lower()
#                                             if any(k in result_str for k in ("suspicious", "trojan", "malicious", "phish", "malware")) or result_str:
#                                                 updates["attachment_risk_detected"] = True
#                                                 break
#                                     if updates.get("attachment_risk_detected"):
#                                         break
#                                 else:
#                                     # positives>0 alone indicates risk when no detailed scan_results
#                                     updates["attachment_risk_detected"] = True
#                                     break
    
#     # Check attachment_findings - convert forensic indicators to findings
#     if not ai_assessment.attachment_findings:
#         findings = []
#         for indicator in understanding.forensic_indicators:
#             # Map indicator to finding type
#             finding_type_map = {
#                 "malicious_attachment": "malicious_attachment",
#                 "suspicious_attachment": "suspicious_attachment",
#                 "known_malicious_hash": "known_malicious_hash",
#                 "attachment_threat_intelligence_match": "attachment_threat_intelligence_match",
#                 "malware_detected": "malware_detected",
#                 "high_abuse_confidence": "high_abuse_confidence",
#                 "suspicious_file_type": "suspicious_file_type",
#                 "sandbox_verdict_malicious": "sandbox_verdict_malicious",
#             }
#             finding_type = finding_type_map.get(indicator.indicator)
#             if finding_type:
#                 # Determine evidence strength
#                 strength_map = {
#                     "malicious_attachment": "explicit_detection",
#                     "malware_detected": "explicit_detection",
#                     "known_malicious_hash": "explicit_detection",
#                     "attachment_threat_intelligence_match": "reported_indicator",
#                     "suspicious_attachment": "reported_indicator",
#                     "high_abuse_confidence": "reported_indicator",
#                     "suspicious_file_type": "weak_observation",
#                     "sandbox_verdict_malicious": "explicit_detection",
#                 }
#                 findings.append(ForensicFinding(
#                     finding_type=finding_type,
#                     evidence_path=indicator.source,
#                     explanation=indicator.context,
#                     evidence_strength=strength_map.get(finding_type, "weak_observation"),
#                 ))
#         if findings:
#             updates["attachment_findings"] = findings
    
#     if updates:
#         # Use model_copy to create a new instance with corrected values (Pydantic model)
#         return ai_assessment.model_copy(update=updates)
    
#     return ai_assessment


# def _call_llm(prompt_request: PromptRequest) -> LLMResponse:
#     """Call Ollama with the prompt request."""
#     client = create_ollama_client()
#     try:
#         return client.generate(prompt_request)
#     except OllamaConnectionError as e:
#         raise PipelineLLMError(f"Cannot connect to Ollama: {e}", stage="ollama_connection") from e
#     except OllamaTimeoutError as e:
#         raise PipelineLLMError(f"Ollama request timed out: {e}", stage="ollama_timeout") from e
#     except OllamaModelNotFoundError as e:
#         raise PipelineLLMError(f"Model not found: {e}", stage="ollama_model_not_found") from e
#     except OllamaHTTPError as e:
#         raise PipelineLLMError(f"Ollama HTTP error: {e}", stage="ollama_http") from e
#     except OllamaClientError as e:
#         raise PipelineLLMError(f"Ollama client error: {e}", stage="ollama_client") from e
#     finally:
#         client.close()


# def analyze_from_dict(data: dict[str, Any]) -> PipelineResult:
#     """
#     Convenience entry point that accepts a dictionary and validates it as EvidencePackage.
#     """
#     evidence_package = EvidencePackage.model_validate(data)
#     return analyze(evidence_package)

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any
import time

from src.ai.contracts import EvidencePackage, AIAssessment, ForensicFinding
from src.ai.security import (
    InputGuardError,
    validate_evidence_package,
    isolate_evidence,
    IsolatedEvidence,
)
from src.ai.normalization import normalize_evidence, NormalizedEvidence
from src.ai.understanding import analyze_email, UnderstandingResult
from src.ai.prompting import build_analysis_context, build_prompt_request, AnalysisContext, PromptRequest
from src.ai.prompting.prompt_builder import build_provenance_retry_prompt
from src.ai.llm import create_ollama_client, LLMResponse, OllamaClientError, OllamaConnectionError, OllamaTimeoutError, OllamaHTTPError, OllamaModelNotFoundError
from src.ai.validation import validate_llm_output, LLMExtractionError, LLMJSONParseError, LLMSchemaValidationError
from src.ai.results import check_grounding, GroundingResult, compute_probability_ceilings
from src.ai.results.grounding import resolve_forensic_path
from src.ai.provenance import extract_allowed_provenance_paths, is_provenance_validation_error


class PipelineError(Exception):
    def __init__(self, message: str, stage: str | None = None):
        super().__init__(message)
        self.stage = stage


class PipelineInputError(PipelineError):
    pass


class PipelineLLMError(PipelineError):
    pass


class PipelineValidationError(PipelineError):
    pass


@dataclass(frozen=True)
class PipelineResult:
    case_id: str
    ai_assessment: AIAssessment
    grounding: GroundingResult
    processing_time_seconds: float
    model_info: dict[str, Any]


def analyze(evidence_package: EvidencePackage) -> PipelineResult:
    """
    Main entry point: run the complete AI forensic analysis pipeline.
    """

    start_time = time.time()

    # 1. INPUT SECURITY
    t = time.time()
    try:
        validate_evidence_package(evidence_package)
    except InputGuardError as e:
        raise PipelineInputError(
            f"Input validation failed: {e}",
            stage="input_guard"
        ) from e
    print(f"[PIPELINE] Input validation: {time.time() - t:.3f}s", flush=True)

    # 2. CONTENT ISOLATION
    t = time.time()
    isolated_evidence = isolate_evidence(evidence_package)
    print(f"[PIPELINE] Content isolation: {time.time() - t:.3f}s", flush=True)

    # 3. NORMALIZATION
    t = time.time()
    normalized_evidence = normalize_evidence(isolated_evidence)
    print(f"[PIPELINE] Normalization: {time.time() - t:.3f}s", flush=True)

    # 4. UNDERSTANDING
    t = time.time()
    understanding = analyze_email(normalized_evidence)
    print(f"[PIPELINE] Understanding: {time.time() - t:.3f}s", flush=True)

    # 5. CONTEXT
    t = time.time()
    context = build_analysis_context(
        normalized_evidence,
        understanding
    )
    print(f"[PIPELINE] Context building: {time.time() - t:.3f}s", flush=True)

    # 5b. EXTRACT REQUEST-SPECIFIC ALLOWED PROVENANCE PATHS
    # Derived from canonical forensic indicators for this specific case.
    # Scoped to this request; never shared across cases.
    try:
        allowed_provenance_paths = extract_allowed_provenance_paths(context, understanding)
    except Exception:
        allowed_provenance_paths = []
    print(
        f"[PIPELINE] Allowed provenance paths: {len(allowed_provenance_paths)} "
        f"({', '.join(allowed_provenance_paths[:3])}{'...' if len(allowed_provenance_paths) > 3 else ''})",
        flush=True,
    )

    # 6. PROMPT (request-specific: prompt + dynamic schema both use allowed paths)
    t = time.time()
    prompt_request = build_prompt_request(context, allowed_provenance_paths)
    prompt_time = time.time() - t

    print(
        f"[PIPELINE] Prompt building: {prompt_time:.3f}s",
        flush=True
    )

    print(
        f"[PIPELINE] System prompt chars: "
        f"{len(prompt_request.system_prompt):,}",
        flush=True
    )

    print(
        f"[PIPELINE] User prompt chars: "
        f"{len(prompt_request.user_prompt):,}",
        flush=True
    )

    # 7. LLM
    print("[PIPELINE] >>> START OLLAMA INFERENCE", flush=True)
    t = time.time()

    llm_response = _call_llm(prompt_request)

    llm_time = time.time() - t

    print(
        f"[PIPELINE] <<< OLLAMA INFERENCE FINISHED: "
        f"{llm_time:.3f}s",
        flush=True
    )

    print(
        f"[PIPELINE] LLM response chars: "
        f"{len(llm_response.content):,}",
        flush=True
    )

    # 8. VALIDATION with ONE targeted provenance retry
    # Strict validation remains authoritative. If provenance validation fails
    # (generic evidence_path like "attachments"), we perform exactly one
    # targeted regeneration using the same evidence, same case_id, same
    # allowed path set, with explicit correction instruction. All other
    # failures (connection, timeout, extraction) fail fast without retry.
    t = time.time()

    try:
        ai_assessment = validate_llm_output(
            llm_response.content
        )
    except (LLMExtractionError, LLMJSONParseError) as e:
        raise PipelineValidationError(
            f"Failed to extract/parse LLM output: {e}",
            stage="llm_output_extraction"
        ) from e
    except LLMSchemaValidationError as e:
        # Only provenance errors get one retry; others fail immediately
        if not is_provenance_validation_error(e):
            raise PipelineValidationError(
                f"LLM output failed schema validation: {e}",
                stage="llm_output_schema"
            ) from e

        # Provenance error -> one targeted retry
        print(
            f"[PIPELINE] Provenance validation failed ({str(e)[:200]}), attempting one targeted retry...",
            flush=True,
        )
        try:
            retry_request = build_provenance_retry_prompt(
                prompt_request, e, allowed_provenance_paths
            )
            print("[PIPELINE] >>> START OLLAMA RETRY FOR PROVENANCE", flush=True)
            retry_t = time.time()
            retry_response = _call_llm(retry_request)
            retry_time = time.time() - retry_t
            print(
                f"[PIPELINE] <<< RETRY FINISHED: {retry_time:.3f}s",
                flush=True,
            )
            print(
                f"[PIPELINE] Retry response chars: {len(retry_response.content):,}",
                flush=True,
            )
            # Re-validate retry output with same strict validation
            ai_assessment = validate_llm_output(
                retry_response.content
            )
            print("[PIPELINE] Retry validation succeeded", flush=True)
            # Use retry response for downstream timing? Keep original timing for overall
        except (LLMExtractionError, LLMJSONParseError) as retry_e:
            raise PipelineValidationError(
                f"Failed to extract/parse LLM retry output: {retry_e}",
                stage="llm_output_extraction"
            ) from retry_e
        except LLMSchemaValidationError as retry_e:
            raise PipelineValidationError(
                f"LLM retry output failed schema validation: {retry_e}",
                stage="llm_output_schema"
            ) from retry_e

    print(
        f"[PIPELINE] Output validation: "
        f"{time.time() - t:.3f}s",
        flush=True
    )

    # 9. GROUNDING
    t = time.time()

    grounding = check_grounding(
        ai_assessment,
        context,
        understanding
    )

    # print(
    #     f"[PIPELINE] Grounding: "
    #     f"{time.time() - t:.3f}s",
    #     flush=True
    # )
    print(
    f"[PIPELINE] Grounding: "
    f"{time.time() - t:.3f}s | "
    f"grounded={grounding.grounded} | "
    f"unsupported_claims={len(grounding.unsupported_claims)} | "
    f"evidence_refs={len(grounding.evidence_references)}",
    flush=True
)

    # 10. RECONCILIATION
    t = time.time()

    ai_assessment = _reconcile_assessment(
        ai_assessment,
        context,
        understanding,
        grounding
    )

    print(
        f"[PIPELINE] Reconciliation: "
        f"{time.time() - t:.3f}s",
        flush=True
    )

    # 11. RE-GROUND
    # Final grounded must reflect FINAL assessment after reconciliation.
    # Previously only re-grounded when initial was not grounded, which left
    # a window where reconciliation clamped probabilities but final grounded
    # still reflected the pre-reconciliation (potentially grounded=True) state.
    # Now always re-ground after reconciliation so the returned grounding is
    # authoritative for the returned assessment.
    t = time.time()

    new_grounding = check_grounding(
        ai_assessment,
        context,
        understanding
    )

    # Only log re-grounding time if the result actually changed or if initial
    # was not grounded, to avoid noisy logs when nothing changed; but the
    # grounding used downstream is always the new one.
    if new_grounding != grounding:
        print(
            f"[PIPELINE] Re-grounding: "
            f"{time.time() - t:.3f}s | "
            f"grounded={new_grounding.grounded} | "
            f"unsupported_claims={len(new_grounding.unsupported_claims)}",
            flush=True
        )
    else:
        # Still update timing for consistency.
        print(
            f"[PIPELINE] Re-grounding: "
            f"{time.time() - t:.3f}s | "
            f"grounded={new_grounding.grounded} (unchanged)",
            flush=True
        )
    grounding = new_grounding

    elapsed = time.time() - start_time

    print(
        f"[PIPELINE] TOTAL: {elapsed:.3f}s",
        flush=True
    )

    return PipelineResult(
        case_id=evidence_package.case_id,
        ai_assessment=ai_assessment,
        grounding=grounding,
        processing_time_seconds=elapsed,
        model_info={
            "model": (
                ai_assessment.model_info.model_name
                if ai_assessment.model_info
                else "unknown"
            ),
            "provider": (
                ai_assessment.model_info.provider
                if ai_assessment.model_info
                else "unknown"
            ),
            "version": (
                ai_assessment.model_info.model_version
                if ai_assessment.model_info
                else "unknown"
            ),
        },
    )

def _reconcile_assessment(
    ai_assessment: AIAssessment,
    context: AnalysisContext,
    understanding: UnderstandingResult,
    grounding: GroundingResult,
) -> AIAssessment:
    """
    Reconcile AI assessment with forensic evidence and grounding results.
    
    Corrects boolean fields and findings that the LLM may have missed or gotten wrong,
    based on the forensic evidence and grounding results.
    """
    # Use replace to create a new instance with corrected values
    updates = {}

    # Deterministic credential reconciliation — understanding layer is authoritative
    # Banking/account update (financial/phishing) is NOT credential harvesting
    if ai_assessment.credential_request_detected and not understanding.credential_request:
        updates["credential_request_detected"] = False

    # Same deterministic correction, applied consistently to the other two
    # boolean flags that have an equivalent understanding-layer signal list.
    # Only ever turns a flag off when nothing in the evidence supports it -
    # never turns one on, since the LLM may reasonably see support the
    # keyword-based understanding layer's fixed pattern list does not cover.
    if ai_assessment.urgency_detected and not understanding.urgency:
        updates["urgency_detected"] = False
    if ai_assessment.financial_request_detected and not understanding.financial_request:
        updates["financial_request_detected"] = False
    
    # Check malicious_attachment_detected
    forensic_evidence = getattr(context, "forensic_evidence", {})
    if not ai_assessment.malicious_attachment_detected:
        # Check if forensic evidence explicitly indicates malicious attachment
        attachments = forensic_evidence.get("attachments", [])
        if isinstance(attachments, list):
            for attachment in attachments:
                if isinstance(attachment, dict):
                    # Check direct malicious flag
                    if attachment.get("malicious") is True:
                        updates["malicious_attachment_detected"] = True
                        break
                    # Check nested malicious flag in embedded files
                    analysis = attachment.get("analysis", {})
                    if isinstance(analysis, dict):
                        embedded = analysis.get("embedded_files", [])
                        if isinstance(embedded, list):
                            for embedded in embedded:
                                if isinstance(embedded, dict) and embedded.get("malicious") is True:
                                    updates["malicious_attachment_detected"] = True
                                    break
                            if updates.get("malicious_attachment_detected"):
                                break
    
    # Check attachment_risk_detected
    if not ai_assessment.attachment_risk_detected:
        # Risk exists if any forensic indicator suggests risk
        if understanding.forensic_indicators:
            risk_indicators = {
                "malicious_attachment", "suspicious_attachment", "known_malicious_hash",
                "attachment_threat_intelligence_match", "malware_detected",
                "high_abuse_confidence", "sandbox_verdict_malicious"
            }
            for indicator in understanding.forensic_indicators:
                if indicator.indicator in risk_indicators:
                    updates["attachment_risk_detected"] = True
                    break
        # Also consider attachment threat intelligence (VirusTotal) for risk
        # 6/68 positives with Suspicious.Zip/Trojan.Generic is risk but NOT explicit malicious
        if not updates.get("attachment_risk_detected"):
            ti = getattr(context, "threat_intelligence", {}) or {}
            if isinstance(ti, dict):
                attachment_analysis = ti.get("attachment_analysis", {})
                if isinstance(attachment_analysis, dict):
                    vt_reports = attachment_analysis.get("virusTotal_report", [])
                    if isinstance(vt_reports, list):
                        for report in vt_reports:
                            if not isinstance(report, dict):
                                continue
                            positives = report.get("positives", 0)
                            try:
                                pos_val = int(positives)
                            except (TypeError, ValueError):
                                pos_val = 0
                            if pos_val > 0:
                                scan_results = report.get("scan_results", {})
                                if isinstance(scan_results, dict) and scan_results:
                                    for eng in scan_results.values():
                                        if isinstance(eng, dict) and eng.get("detected") is True:
                                            result_str = str(eng.get("result", "")).lower()
                                            if any(k in result_str for k in ("suspicious", "trojan", "malicious", "phish", "malware")) or result_str:
                                                updates["attachment_risk_detected"] = True
                                                break
                                    if updates.get("attachment_risk_detected"):
                                        break
                                else:
                                    # positives>0 alone indicates risk when no detailed scan_results
                                    updates["attachment_risk_detected"] = True
                                    break
    
    # Check attachment_findings - convert forensic indicators to findings
    if not ai_assessment.attachment_findings:
        findings = []
        for indicator in understanding.forensic_indicators:
            # Map indicator to finding type
            finding_type_map = {
                "malicious_attachment": "malicious_attachment",
                "suspicious_attachment": "suspicious_attachment",
                "known_malicious_hash": "known_malicious_hash",
                "attachment_threat_intelligence_match": "attachment_threat_intelligence_match",
                "malware_detected": "malware_detected",
                "high_abuse_confidence": "high_abuse_confidence",
                "suspicious_file_type": "suspicious_file_type",
                "sandbox_verdict_malicious": "sandbox_verdict_malicious",
            }
            finding_type = finding_type_map.get(indicator.indicator)
            if finding_type:
                # Determine evidence strength
                strength_map = {
                    "malicious_attachment": "explicit_detection",
                    "malware_detected": "explicit_detection",
                    "known_malicious_hash": "explicit_detection",
                    "attachment_threat_intelligence_match": "reported_indicator",
                    "suspicious_attachment": "reported_indicator",
                    "high_abuse_confidence": "reported_indicator",
                    "suspicious_file_type": "weak_observation",
                    "sandbox_verdict_malicious": "explicit_detection",
                }
                findings.append(ForensicFinding(
                    finding_type=finding_type,
                    evidence_path=indicator.source,
                    explanation=indicator.context,
                    evidence_strength=strength_map.get(finding_type, "weak_observation"),
                ))
        if findings:
            updates["attachment_findings"] = findings

    # Deterministic probability ceiling reconciliation.
    # The LLM's raw phishing/BEC/social-engineering probabilities are only
    # clamped down, never raised, and only when they exceed what the supplied
    # evidence tier supports (the same tiers the grounding calibration check
    # already computes). This stops an ungrounded 0.97 from reaching the
    # logic engine unchanged just because grounding merely flagged it.
    ceilings = compute_probability_ceilings(ai_assessment, context, understanding)
    for field_name, ceiling in ceilings.items():
        current_value = getattr(ai_assessment, field_name)
        if current_value > ceiling:
            updates[field_name] = ceiling

    # BEC lower-bound / evidence floor: strong BEC evidence cannot remain at 0.0.
    # This is the smallest BEC-specific mechanism: only raises BEC, never phishing.
    # Uses same semantic tiers as grounding (deduplicated by indicator) to avoid count inflation.
    try:
        # Use effective BEC after potential ceiling clamping
        effective_bec = float(updates.get("bec_probability", ai_assessment.bec_probability))
        # Recompute BEC tiers (mirrors grounding logic, deduped)
        bec_indicator_set_floor = set([s.indicator for s in getattr(understanding, "bec_indicators", [])])
        bec_texts_floor = []
        for s in getattr(understanding, "bec_indicators", []):
            parts = []
            for attr in ("indicator", "context", "source"):
                v = getattr(s, attr, "")
                if v:
                    parts.append(str(v))
            bec_texts_floor.append(" ".join(parts).lower())
        financial_texts_floor = []
        for s in getattr(understanding, "financial_request", []):
            v = getattr(s, "context", "")
            if v:
                financial_texts_floor.append(str(v).lower())
        def _contains_any_floor(texts, needles):
            return any(needle in text for text in texts for needle in needles)
        strong_bec_floor = _contains_any_floor(
            bec_texts_floor,
            ("payment change", "payment redirection", "bank change", "bank details",
             "new bank", "new account details",
             "executive impersonation", "ceo impersonation", "reply-to manipulation", "executive_name_in_sender"),
        )
        moderate_bec_floor = strong_bec_floor or len(bec_indicator_set_floor) >= 2
        weak_bec_floor = (bool(bec_texts_floor) or bool(financial_texts_floor)) and not strong_bec_floor and not moderate_bec_floor
        # Apply floors only for moderate/strong; weak/none may legitimately stay low
        bec_floor = None
        if strong_bec_floor:
            bec_floor = 0.70
        elif moderate_bec_floor:
            bec_floor = 0.35
        if bec_floor is not None and effective_bec < bec_floor:
            updates["bec_probability"] = float(bec_floor)
            # Ensure explanation does not contradict elevated BEC: append BEC evidence reference if missing
            expl = updates.get("explanation", ai_assessment.explanation)
            expl_lower = expl.lower()
            bec_keywords = ("vendor", "bank account", "beneficiary", "new account", "new bank", "supplier", "invoice", "payment diversion", "executive")
            if not any(kw in expl_lower for kw in bec_keywords):
                # Collect actual BEC indicators for factual reference
                bec_indicators = [s.indicator for s in getattr(understanding, "bec_indicators", [])]
                # Deduplicate and factual
                distinct = sorted(set(bec_indicators))
                if distinct:
                    suffix = " BEC evidence: " + ", ".join(distinct[:4]) + "."
                    # Avoid duplicating if already at limit
                    if len(expl) < 1900:
                        expl = expl.rstrip() + suffix
                        updates["explanation"] = expl
    except Exception:
        pass

    # Drop attachment findings whose cited evidence_path does not actually
    # resolve against the supplied forensic evidence. A finding that names a
    # path that was never supplied (e.g. an "analysis" object the backend
    # never sent) is not a downgraded observation - it is fabricated, and
    # forwarding it downstream misrepresents what the evidence actually
    # contains. Grounding already detects this; this makes reconciliation act
    # on it instead of only reporting it.
    # Also filter findings with finding_type outside the deterministic
    # vocabulary - an LLM-invented type like "weak_observation" (which is an
    # evidence_strength value, not a finding_type) must not be treated as
    # positive security evidence for attachment_risk (Bug 10).
    if ai_assessment.attachment_findings:
        forensic_evidence = getattr(context, "forensic_evidence", {})
        _allowed_finding_types = {
            "malware_detected",
            "malicious_attachment",
            "known_malicious_hash",
            "attachment_threat_intelligence_match",
            "suspicious_attachment",
            "high_abuse_confidence",
            "suspicious_file_type",
            "sandbox_verdict_malicious",
        }
        kept_findings = []
        for f in ai_assessment.attachment_findings:
            if not resolve_forensic_path(forensic_evidence, f.evidence_path).resolved:
                continue
            if f.finding_type.strip().lower() not in _allowed_finding_types:
                # Unknown type outside vocabulary - not verifiable, do not count as support.
                continue
            kept_findings.append(f)
        if len(kept_findings) != len(ai_assessment.attachment_findings):
            updates["attachment_findings"] = kept_findings
            if ai_assessment.malicious_attachment_detected:
                still_supports_malicious = any(
                    f.finding_type in ("malware_detected", "malicious_attachment", "known_malicious_hash")
                    for f in kept_findings
                )
                if not still_supports_malicious:
                    updates["malicious_attachment_detected"] = False
            # If risk was claimed but no verifiable finding remains, correct it.
            if ai_assessment.attachment_risk_detected and not kept_findings:
                # Also check forensic_indicators and VT as alternative support; if none, clear risk.
                has_forensic_risk = False
                if understanding.forensic_indicators:
                    risk_indicators = {
                        "malicious_attachment", "suspicious_attachment", "known_malicious_hash",
                        "attachment_threat_intelligence_match", "malware_detected",
                        "high_abuse_confidence", "sandbox_verdict_malicious"
                    }
                    for ind in understanding.forensic_indicators:
                        if ind.indicator in risk_indicators:
                            has_forensic_risk = True
                            break
                has_vt_risk = False
                ti = getattr(context, "threat_intelligence", {}) or {}
                if isinstance(ti, dict):
                    att = ti.get("attachment_analysis", {})
                    if isinstance(att, dict):
                        vt = att.get("virusTotal_report", [])
                        if isinstance(vt, list):
                            for report in vt:
                                if not isinstance(report, dict):
                                    continue
                                try:
                                    pos = int(report.get("positives", 0))
                                except (TypeError, ValueError):
                                    pos = 0
                                if pos > 0:
                                    has_vt_risk = True
                                    break
                if not has_forensic_risk and not has_vt_risk:
                    updates["attachment_risk_detected"] = False
        # Also correct false-positive risk when LLM claimed risk but no evidence at all supports it
        # (even if kept_findings == original but all were verifiable, we still need to check if risk has support)
        elif ai_assessment.attachment_risk_detected and not kept_findings:
            # No findings at all after filtering (original had findings but all filtered) already handled above;
            # this branch handles case where original had findings and kept == original but risk still unsupported because
            # those findings were weak_observation types already filtered to empty.
            # The above length check already covers it when len differs, but if original had 0 findings and risk true,
            # we need to correct as well. That case is handled below.
            pass
    # Correct false-positive attachment risk when LLM set risk true but no verifiable evidence supports it at all
    # (covers case where attachment_findings was empty or all filtered, and forensic_indicators empty)
    if ai_assessment.attachment_risk_detected and "attachment_risk_detected" not in updates:
        # If we already decided to keep findings, check if those kept findings actually support risk
        kept = updates.get("attachment_findings", ai_assessment.attachment_findings)
        has_support = False
        if kept:
            # Any kept finding is by definition verifiable and supports risk (risk indicators include weak_observation? No, weak alone not in risk set)
            # For risk, any verifiable finding should be considered support, but weak_observation type filtered above,
            # so remaining are at least weak but risk-relevant. However to be precise, check if any kept supports risk:
            # For this correction we treat any remaining verifiable finding as support; if none remain, check forensic indicators/VT.
            has_support = True
        else:
            # No findings remain - check forensic indicators and VT
            if understanding.forensic_indicators:
                risk_indicators = {
                    "malicious_attachment", "suspicious_attachment", "known_malicious_hash",
                    "attachment_threat_intelligence_match", "malware_detected",
                    "high_abuse_confidence", "sandbox_verdict_malicious"
                }
                for ind in understanding.forensic_indicators:
                    if ind.indicator in risk_indicators:
                        has_support = True
                        break
            if not has_support:
                ti = getattr(context, "threat_intelligence", {}) or {}
                if isinstance(ti, dict):
                    att = ti.get("attachment_analysis", {})
                    if isinstance(att, dict):
                        vt = att.get("virusTotal_report", [])
                        if isinstance(vt, list):
                            for report in vt:
                                if not isinstance(report, dict):
                                    continue
                                try:
                                    pos = int(report.get("positives", 0))
                                except (TypeError, ValueError):
                                    pos = 0
                                if pos > 0:
                                    has_support = True
                                    break
        if not has_support:
            updates["attachment_risk_detected"] = False
            # Also ensure malicious is consistent
            if ai_assessment.malicious_attachment_detected:
                updates["malicious_attachment_detected"] = False
                if "attachment_findings" not in updates:
                    updates["attachment_findings"] = []

    if updates:
        # Use model_copy to create a new instance with corrected values (Pydantic model)
        return ai_assessment.model_copy(update=updates)
    
    return ai_assessment


def _call_llm(prompt_request: PromptRequest) -> LLMResponse:
    """Call Ollama with the prompt request."""
    client = create_ollama_client()
    try:
        return client.generate(prompt_request)
    except OllamaConnectionError as e:
        raise PipelineLLMError(f"Cannot connect to Ollama: {e}", stage="ollama_connection") from e
    except OllamaTimeoutError as e:
        raise PipelineLLMError(f"Ollama request timed out: {e}", stage="ollama_timeout") from e
    except OllamaModelNotFoundError as e:
        raise PipelineLLMError(f"Model not found: {e}", stage="ollama_model_not_found") from e
    except OllamaHTTPError as e:
        raise PipelineLLMError(f"Ollama HTTP error: {e}", stage="ollama_http") from e
    except OllamaClientError as e:
        raise PipelineLLMError(f"Ollama client error: {e}", stage="ollama_client") from e
    finally:
        client.close()


def analyze_from_dict(data: dict[str, Any]) -> PipelineResult:
    """
    Convenience entry point that accepts a dictionary and validates it as EvidencePackage.
    """
    evidence_package = EvidencePackage.model_validate(data)
    return analyze(evidence_package)