from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from src.ai.contracts import AIAssessment, ForensicFinding
from src.ai.contracts.assessment import (
    EXPLICIT_DETECTION,
    REPORTED_INDICATOR,
    WEAK_OBSERVATION,
)
from src.ai.prompting import AnalysisContext
from src.ai.understanding import UnderstandingResult

from src.ai.understanding import email_analyzer as _ea


@dataclass(frozen=True)
class GroundingResult:
    """
    Result of evidence grounding check.

    Indicates whether the AI assessment is grounded in the supplied evidence.
    Does not modify the assessment - only reports inconsistencies.
    """
    grounded: bool
    unsupported_claims: list[str] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "grounded": self.grounded,
            "unsupported_claims": self.unsupported_claims,
            "evidence_references": self.evidence_references,
        }


def _is_describing_discrepancy(text: str, keyword: str) -> bool:
    """
    Check if the text is describing a discrepancy about the keyword
    rather than making a false claim.
    
    Returns True if the text acknowledges a contradiction/discrepancy.
    """
    text_lower = text.lower()
    # Patterns that indicate the text is describing a discrepancy
    discrepancy_patterns = [
        f"{keyword} claim",
        f"email claim",
        f"email says",
        f"email states",
        f"email claims",
        f"sender claims",
        f"message claims",
        f"message says",
        f"but evidence",
        f"but security",
        f"but threat",
        f"however",
        f"contradicts",
        f"contrary",
        f"despite",
        f"discrepancy",
        f"inconsistent",
        f"incorrectly claims",
        f"falsely claims",
        f"wrongly claims",
    ]
    return any(pattern in text_lower for pattern in discrepancy_patterns)


def _signal_text(signal: Any) -> str:
    """Return searchable text for one deterministic Understanding signal."""
    parts = []
    for attr in ("indicator", "context", "source"):
        value = getattr(signal, attr, "")
        if value:
            parts.append(str(value))
    return " ".join(parts).strip().lower()


def _signal_texts(signals: Any) -> list[str]:
    if not isinstance(signals, list):
        return []
    return [_signal_text(signal) for signal in signals if _signal_text(signal)]


def _signal_contexts(signals: Any) -> list[str]:
    """
    Return only the observed context text for each signal - never the
    indicator label or the source path. ``_signal_text``/``_signal_texts``
    concatenate indicator+context+source, which is useful for some lookups,
    but is unsafe for keyword-content matching: an indicator label like
    "phishing_analysis" (the backend's field name for this signal category,
    not an actual claim) contains the substring "phishing", and a source path
    like "threat_intelligence.domain_analysis.virustotal_report" contains
    "threat" - both would be mistaken for the model actually having said
    those words. Matching on context alone avoids that.
    """
    if not isinstance(signals, list):
        return []
    texts = []
    for signal in signals:
        value = getattr(signal, "context", "")
        if value:
            texts.append(str(value).strip().lower())
    return texts


def _contains_any(texts: list[str], needles: tuple[str, ...]) -> bool:
    return any(needle in text for text in texts for needle in needles)


def _all_vt_reports(value: Any) -> list[dict[str, Any]]:
    """Keep only dict-shaped VirusTotal reports from an existing backend list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _vt_report_counts(reports: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Return (malicious, suspicious, clean-ish) counts without changing the payload."""
    malicious = 0
    suspicious = 0
    clean = 0
    for report in reports:
        stats = report.get("last_analysis_stats")
        if not isinstance(stats, dict):
            stats = report.get("analysis_stats")
        if not isinstance(stats, dict):
            # Some backends expose top-level counts instead.
            stats = report

        try:
            malicious += max(0, int(stats.get("malicious", 0)))
        except (TypeError, ValueError):
            pass
        try:
            suspicious += max(0, int(stats.get("suspicious", 0)))
        except (TypeError, ValueError):
            pass
        try:
            clean += max(0, int(stats.get("harmless", 0)))
        except (TypeError, ValueError):
            pass

    return malicious, suspicious, clean


def _collect_reputation_semantics(context: AnalysisContext, evidence_refs: list[str]) -> dict[str, int]:
    """
    Interpret existing VT URL/domain reports semantically for grounding only.

    Report presence is never treated as maliciousness. Only explicit VT malicious/
    suspicious counts contribute to the returned support level. The original
    backend structures are left untouched.
    """
    ti = getattr(context, "threat_intelligence", {}) or {}
    if not isinstance(ti, dict):
        return {"malicious": 0, "suspicious": 0, "clean": 0}

    totals = {"malicious": 0, "suspicious": 0, "clean": 0}
    for location, label in (("url_analysis", "URL"), ("domain_analysis", "domain")):
        section = ti.get(location, {})
        if not isinstance(section, dict):
            continue
        reports = _all_vt_reports(section.get("virusTotal_report", []))
        if not reports:
            continue

        malicious, suspicious, clean = _vt_report_counts(reports)
        totals["malicious"] += malicious
        totals["suspicious"] += suspicious
        totals["clean"] += clean

        if malicious > 0:
            evidence_refs.append(
                f"VirusTotal {label} analysis explicitly reports "
                f"{malicious} malicious detection(s)"
            )
        elif suspicious > 0:
            evidence_refs.append(
                f"VirusTotal {label} analysis explicitly reports "
                f"{suspicious} suspicious detection(s)"
            )
        else:
            evidence_refs.append(
                f"VirusTotal {label} analysis supplied reports with no explicit "
                "malicious or suspicious detections"
            )

    return totals


def _auth_pass_count(context: AnalysisContext) -> int:
    """Count how many of SPF/DKIM/DMARC are explicitly passing for counter-evidence."""
    sec = getattr(context, "security_evidence", {}) or {}
    if not isinstance(sec, dict):
        return 0
    auth = sec.get("authentication_analysis", {})
    if not isinstance(auth, dict):
        return 0
    count = 0
    # SPF: list of [status, explanation]
    spf_results = auth.get("spf", [])
    if isinstance(spf_results, list):
        for r in spf_results:
            if isinstance(r, (list, tuple)) and r and str(r[0]).strip().lower() == "pass":
                count += 1
                break
        # Some pipelines put SPF result in header findings rather than spf list;
        # also check security_evidence header findings for SPF pass as fallback,
        # but only count once.
        if count == 0:
            header = sec.get("header_analysis", {})
            if isinstance(header, dict):
                findings = header.get("findings", [])
                if isinstance(findings, list):
                    for f in findings:
                        if "spf" in str(f).lower() and "pass" in str(f).lower():
                            count += 1
                            break
    # DKIM boolean
    dkim = auth.get("dkim")
    if dkim is True:
        count += 1
    # DMARC text contains pass
    dmarc = auth.get("dmarc")
    if dmarc is not None and "pass" in str(dmarc).lower():
        count += 1
    return count


def _check_probability_calibration(
    assessment: AIAssessment,
    context: AnalysisContext,
    understanding: UnderstandingResult,
    evidence_refs: list[str],
) -> list[str]:
    """
    Deterministically check whether high model probabilities have sufficiently
    strong underlying evidence. This does not alter the assessment or its schema.

    Calibration bands (evidence-driven, not arbitrary ceilings):
      NO meaningful attack evidence      -> generally <= 0.20
      WEAK / CONTEXTUAL only             -> roughly 0.10 - 0.35
      MODERATE corroborated evidence     -> roughly 0.35 - 0.70
      STRONG independent evidence        -> roughly 0.70 - 0.90
      MULTIPLE strong independent        -> can exceed 0.90

    Generic actions such as ``click_link`` and ``visit_website`` are weak context,
    not proof of phishing. A clean VirusTotal report is also not positive evidence.
    Authentication pass (SPF/DKIM/DMARC) is counter-evidence against simple spoofing
    but does not prove safety; it materially offsets weak generic observations.
    """
    problems: list[str] = []

    phishing_texts = _signal_contexts(getattr(understanding, "phishing_indicators", []))
    credential_texts = _signal_contexts(getattr(understanding, "credential_request", []))
    financial_texts = _signal_contexts(getattr(understanding, "financial_request", []))
    urgency_texts = _signal_contexts(getattr(understanding, "urgency", []))
    social_texts = _signal_contexts(getattr(understanding, "social_engineering", []))
    bec_texts = _signal_texts(getattr(understanding, "bec_indicators", []))
    bec_contexts = _signal_contexts(getattr(understanding, "bec_indicators", []))

    phishing_analysis = []
    sec = getattr(context, "security_evidence", {}) or {}
    if isinstance(sec, dict):
        raw = sec.get("phishing_analysis", [])
        if isinstance(raw, list):
            phishing_analysis = [str(item).strip().lower() for item in raw if str(item).strip()]

    vt = _collect_reputation_semantics(context, evidence_refs)
    auth_passes = _auth_pass_count(context)

    # Phishing strength tiers - use only contextual content, not indicator labels like "phishing_analysis".
    # Otherwise "phishing_analysis" label would falsely trigger explicit_phish via substring "phishing".
    weak_phish = _contains_any(
        phishing_analysis + phishing_texts,
        ("click_link", "visit_website", "click link", "visit website", "link present"),
    )
    explicit_phish = _contains_any(
        phishing_analysis + phishing_texts,
        ("phishing", "credential theft", "malicious link", "malicious url", "credential harvesting", "deceptive login", "malicious attachment"),
    )
    credential_lure = _contains_any(
        phishing_analysis + phishing_texts + credential_texts,
        ("sign_in_request", "password_update", "password request", "login credentials",
         "credential request", "pin request", "verify your account", "confirm your identity",
         "account verification", "login link", "sign in link"),
    )
    strong_url_ti = vt["malicious"] > 0
    suspicious_url_ti = vt["suspicious"] > 0

    # Evidence polarity: attack vs contextual vs legitimacy
    # Strong requires independent malicious evidence.
    phishing_strong = strong_url_ti or explicit_phish or (credential_lure and suspicious_url_ti and (bool(social_texts) or bool(urgency_texts)))
    # Require corroboration for moderate: credential lure alone is not enough.
    phishing_moderate = phishing_strong or (credential_lure and (bool(credential_texts) or suspicious_url_ti or bool(social_texts) or bool(urgency_texts))) or (len(phishing_analysis) >= 2 and not weak_phish)
    # Weak: any generic phishing observation without moderate/strong support. This includes the generic backend tags that appear in the VIT sample.
    phishing_weak = (weak_phish or credential_lure or bool(phishing_texts) or len(phishing_analysis) >= 1) and not phishing_moderate and not phishing_strong
    phishing_none = not phishing_strong and not phishing_moderate and not phishing_weak

    # Authentication counter-evidence offsets weak generic signals.
    # If strong authentication passes and evidence is only weak, downgrade weak->none so ceiling drops to 0.20.
    if auth_passes >= 2 and phishing_weak:
        # Treat weak generic login/link observations as no meaningful attack when authentication strongly passes.
        phishing_none = True
        phishing_weak = False
        evidence_refs.append("Authentication SPF/DKIM/DMARC pass is counter-evidence offsetting weak generic phishing signals")
    elif auth_passes >= 1 and phishing_weak and vt["clean"] > 0 and vt["malicious"] == 0 and vt["suspicious"] == 0:
        # Clean VT plus any auth pass also suggests no meaningful attack.
        phishing_none = True
        phishing_weak = False
        evidence_refs.append("Clean VirusTotal plus authentication pass suggests no meaningful phishing evidence")

    # Apply band thresholds.
    p = float(assessment.phishing_probability)
    # No meaningful attack evidence should be <=0.20; weak <=0.35; moderate <=0.70; strong <=0.90
    if p > 0.90 and not phishing_strong:
        problems.append(
            "phishing_probability is above 0.90 but the supplied evidence does not "
            "contain strong corroborating phishing evidence; generic link/action "
            "signals are insufficient for a very-high phishing probability"
        )
    elif p > 0.70 and not (phishing_strong or phishing_moderate):
        problems.append(
            "phishing_probability is above 0.70 but the supplied evidence does not "
            "contain moderate corroborating phishing evidence"
        )
    elif p > 0.35 and not (phishing_strong or phishing_moderate or phishing_weak):
        problems.append(
            "phishing_probability is above 0.35 but the supplied evidence does not "
            "contain even weak phishing evidence"
        )
    elif p > 0.20 and phishing_none:
        problems.append(
            "phishing_probability is above 0.20 but the supplied evidence contains no meaningful phishing evidence; weak generic signals and clean threat intel do not support >0.20"
        )

    # Social engineering needs manipulation context, not merely a link/payment.
    manipulation = (
        bool(urgency_texts)
        or bool(social_texts)
        or _contains_any(social_texts + phishing_texts, (
            "authority", "impersonat", "fear", "threat", "secrecy", "pressure",
            "urgent", "immediate", "suspend", "suspension", "act now",
        ))
    )
    social_request_pair = bool(credential_texts or financial_texts) and manipulation
    social_strong = social_request_pair or len(social_texts) >= 2
    social_moderate = (social_strong or len(social_texts) >= 1 or manipulation) and not social_strong
    # Weak social is manipulation alone without request pair, or single social indicator.
    social_weak = (bool(manipulation) or bool(social_texts)) and not social_strong and not social_moderate
    social_none = not social_strong and not social_moderate and not social_weak

    se = float(assessment.social_engineering_probability)
    if se > 0.90 and not social_strong:
        problems.append(
            "social_engineering_probability is above 0.90 but the supplied evidence "
            "does not contain multiple strong manipulation signals"
        )
    elif se > 0.70 and not (social_strong or social_moderate):
        problems.append(
            "social_engineering_probability is above 0.70 but the supplied evidence "
            "does not contain moderate social-engineering evidence"
        )
    elif se > 0.35 and social_none:
        problems.append(
            "social_engineering_probability is above 0.35 but the supplied evidence "
            "does not contain even weak social-engineering evidence"
        )
    elif se > 0.15 and social_none:
        # Very low threshold for social when no evidence.
        problems.append(
            "social_engineering_probability is above 0.15 but the supplied evidence contains no meaningful social-engineering evidence"
        )

    # BEC is intentionally strict: a payment/financial request alone is not BEC.
    # Deduplicate by indicator to avoid counting duplicate "vendor payment" strings as independent evidence.
    # Vendor/supplier payment alone is weak/contextual; strong requires new bank/account or executive impersonation etc.
    bec_indicator_set = set([s.indicator for s in getattr(understanding, "bec_indicators", [])])
    strong_bec = _contains_any(
        bec_texts,
        ("payment change", "payment redirection", "bank change", "bank details",
         "new bank", "new account details",
         "executive impersonation", "ceo impersonation", "reply-to manipulation", "executive_name_in_sender"),
    )
    moderate_bec = strong_bec or len(bec_indicator_set) >= 2
    weak_bec = (bool(bec_texts) or bool(financial_texts)) and not strong_bec and not moderate_bec
    none_bec = not strong_bec and not moderate_bec and not weak_bec

    bec = float(assessment.bec_probability)
    if bec > 0.90 and not strong_bec:
        problems.append(
            "bec_probability is above 0.90 but there are not enough BEC-specific "
            "indicators to support a very-high BEC probability"
        )
    elif bec > 0.60 and not (strong_bec or moderate_bec):
        problems.append(
            "bec_probability is above 0.60 but the supplied evidence does not "
            "contain moderate BEC-specific evidence"
        )
    elif bec > 0.30 and none_bec:
        problems.append(
            "bec_probability is above 0.30 but the supplied evidence does not contain even weak BEC evidence"
        )
    elif bec > 0.05 and none_bec:
        problems.append(
            "bec_probability is above 0.05 but the supplied evidence contains no meaningful BEC-specific evidence"
        )
    # Lower-bound / evidence-floor for BEC only: strong evidence cannot coexist with near-zero probability.
    if strong_bec and bec < 0.60:
        problems.append(
            "bec_probability is below 0.60 but strong BEC-specific evidence exists; BEC should be meaningfully elevated"
        )
    elif moderate_bec and bec < 0.30:
        problems.append(
            "bec_probability is below 0.30 but moderate BEC evidence exists; BEC should not remain near zero"
        )

    # Helpful positive references without changing any existing fields.
    if phishing_strong:
        evidence_refs.append("Phishing probability has strong corroborating evidence")
    elif phishing_moderate:
        evidence_refs.append("Phishing probability has moderate corroborating evidence")
    elif phishing_weak:
        evidence_refs.append("Phishing probability has only weak contextual evidence")
    else:
        evidence_refs.append("Phishing probability has no meaningful phishing evidence")

    if social_strong:
        evidence_refs.append("Social-engineering probability has strong manipulation evidence")
    elif social_moderate:
        evidence_refs.append("Social-engineering probability has moderate manipulation evidence")
    elif social_weak:
        evidence_refs.append("Social-engineering probability has only weak manipulation evidence")
    else:
        evidence_refs.append("Social-engineering probability has no meaningful manipulation evidence")

    if strong_bec:
        evidence_refs.append("BEC probability has strong BEC-specific evidence")
    elif moderate_bec:
        evidence_refs.append("BEC probability has moderate BEC-specific evidence")
    elif weak_bec:
        evidence_refs.append("BEC probability has only weak contextual BEC evidence")
    else:
        evidence_refs.append("BEC probability has no meaningful BEC-specific evidence")

    return problems


def compute_probability_ceilings(
    assessment: AIAssessment,
    context: AnalysisContext,
    understanding: UnderstandingResult,
) -> dict[str, float]:
    """
    Deterministically compute the maximum value each probability field can
    carry, using the exact same evidence-strength tiers that
    ``_check_probability_calibration`` already uses to flag unsupported
    claims (strong / moderate / weak / none).

     Calibration bands:
      NO meaningful attack evidence      -> 0.20 (phish), 0.05 (BEC), 0.15 (social)
      WEAK / CONTEXTUAL only             -> 0.35 (phish/social), 0.25 (BEC)
      MODERATE corroborated evidence     -> 0.70 (phish), 0.60 (BEC), 0.65 (social)
      STRONG independent evidence        -> 0.90
      MULTIPLE strong                    -> 1.0

    Authentication pass offsets weak generic signals for phishing.

    This function does not modify anything and does not replace
    ``_check_probability_calibration`` - it exists so a caller (the
    pipeline's reconciliation step) can clamp a probability the LLM produced
    down to a value the supplied evidence actually supports, instead of the
    unsupported claim only being recorded and then ignored.

    Returns a dict keyed by the three probability field names on
    ``AIAssessment``, each mapped to its ceiling.
    """
    evidence_refs: list[str] = []

    phishing_texts = _signal_contexts(getattr(understanding, "phishing_indicators", []))
    credential_texts = _signal_contexts(getattr(understanding, "credential_request", []))
    financial_texts = _signal_contexts(getattr(understanding, "financial_request", []))
    urgency_texts = _signal_contexts(getattr(understanding, "urgency", []))
    social_texts = _signal_contexts(getattr(understanding, "social_engineering", []))
    bec_texts = _signal_texts(getattr(understanding, "bec_indicators", []))

    phishing_analysis = []
    sec = getattr(context, "security_evidence", {}) or {}
    if isinstance(sec, dict):
        raw = sec.get("phishing_analysis", [])
        if isinstance(raw, list):
            phishing_analysis = [str(item).strip().lower() for item in raw if str(item).strip()]

    vt = _collect_reputation_semantics(context, evidence_refs)
    auth_passes = _auth_pass_count(context)

    weak_phish = _contains_any(
        phishing_analysis + phishing_texts,
        ("click_link", "visit_website", "click link", "visit website", "link present"),
    )
    explicit_phish = _contains_any(
        phishing_analysis + phishing_texts,
        ("phishing", "credential theft", "malicious link", "malicious url", "credential harvesting", "deceptive login", "malicious attachment"),
    )
    credential_lure = _contains_any(
        phishing_analysis + phishing_texts + credential_texts,
        ("sign_in_request", "password_update", "password request", "login credentials",
         "credential request", "pin request", "verify your account", "confirm your identity",
         "account verification", "login link", "sign in link"),
    )
    strong_url_ti = vt["malicious"] > 0
    suspicious_url_ti = vt["suspicious"] > 0

    phishing_strong = bool(
        strong_url_ti or explicit_phish or (credential_lure and suspicious_url_ti and (bool(social_texts) or bool(urgency_texts)))
    )
    phishing_moderate = bool(
        phishing_strong
        or (credential_lure and (bool(credential_texts) or suspicious_url_ti or bool(social_texts) or bool(urgency_texts)))
        or (len(phishing_analysis) >= 2 and not weak_phish)
    )
    phishing_weak = bool((weak_phish or credential_lure or bool(phishing_texts) or len(phishing_analysis) >= 1) and not phishing_moderate and not phishing_strong)
    phishing_none = not phishing_strong and not phishing_moderate and not phishing_weak
    if auth_passes >= 2 and phishing_weak:
        phishing_none = True
        phishing_weak = False
    elif auth_passes >= 1 and phishing_weak and vt["clean"] > 0 and vt["malicious"] == 0 and vt["suspicious"] == 0:
        phishing_none = True
        phishing_weak = False

    manipulation = bool(
        urgency_texts
        or social_texts
        or _contains_any(social_texts + phishing_texts, (
            "authority", "impersonat", "fear", "threat", "secrecy", "pressure",
            "urgent", "immediate", "suspend", "suspension", "act now",
        ))
    )
    social_request_pair = bool((credential_texts or financial_texts) and manipulation)
    social_strong = bool(social_request_pair or len(social_texts) >= 2)
    social_moderate = bool((social_strong or len(social_texts) >= 1 or manipulation) and not social_strong)
    social_weak = bool((bool(manipulation) or bool(social_texts)) and not social_strong and not social_moderate)
    social_none = not social_strong and not social_moderate and not social_weak

    strong_bec = bool(_contains_any(
        bec_texts,
        ("payment change", "payment redirection", "bank change", "bank details",
         "new bank", "new account details",
         "executive impersonation", "ceo impersonation", "reply-to manipulation", "executive_name_in_sender"),
    ))
    # Deduplicate by indicator for moderate to avoid duplicate "vendor payment" inflation
    # Vendor/supplier payment alone is weak; moderate requires distinct types
    bec_indicator_set = set([s.indicator for s in getattr(understanding, "bec_indicators", [])])
    moderate_bec = bool(strong_bec or len(bec_indicator_set) >= 2)
    weak_bec = bool((bool(bec_texts) or bool(financial_texts)) and not strong_bec and not moderate_bec)
    none_bec = not strong_bec and not moderate_bec and not weak_bec

    def _phish_ceiling() -> float:
        if phishing_strong:
            # Multiple strong could be 1.0, but single strong caps at 0.90
            # For simplicity, strong alone is 0.90, multiple would need extra check.
            # We treat strong as 0.90; very high >0.90 requires multiple strong signals
            # which we approximate by requiring malicious VT + explicit.
            if strong_url_ti and explicit_phish:
                return 1.0
            return 0.90
        if phishing_moderate:
            return 0.70
        if phishing_weak:
            return 0.35
        return 0.20

    def _social_ceiling() -> float:
        if social_strong:
            return 0.90
        if social_moderate:
            return 0.65
        if social_weak:
            return 0.35
        return 0.15

    def _bec_ceiling() -> float:
        if strong_bec:
            return 0.90
        if moderate_bec:
            return 0.60
        if weak_bec:
            return 0.25
        return 0.05

    return {
        "phishing_probability": _phish_ceiling(),
        "social_engineering_probability": _social_ceiling(),
        "bec_probability": _bec_ceiling(),
    }


def check_grounding(
    assessment: AIAssessment,
    context: AnalysisContext,
    understanding: UnderstandingResult,
) -> GroundingResult:
    """
    Check if the AI assessment is grounded in the supplied evidence.

    Conservative, deterministic checks for obvious inconsistencies.
    Does NOT modify the assessment - only reports problems.

    Returns GroundingResult with:
    - grounded: True if no unsupported claims found
    - unsupported_claims: List of human-readable descriptions
      of inconsistencies
    - evidence_references: List of evidence that supports
      the assessment
    """

    unsupported = []
    evidence_refs = []

    explanation = assessment.explanation.lower()

    # ==========================================================
    # SECURITY ANALYSIS
    # ==========================================================

    sec_evidence = context.security_evidence

    if isinstance(sec_evidence, dict):
        authentication = sec_evidence.get(
            "authentication_analysis",
            {},
        )

        if isinstance(authentication, dict):

            # --------------------------------------------------
            # SPF
            # --------------------------------------------------

            spf_results = authentication.get(
                "spf",
                [],
            )

            if isinstance(spf_results, list):
                for spf_result in spf_results:

                    if not isinstance(
                        spf_result,
                        (list, tuple),
                    ):
                        continue

                    if not spf_result:
                        continue

                    spf_status = str(
                        spf_result[0]
                    ).strip().lower()

                    spf_context = (
                        str(spf_result[1])
                        if len(spf_result) > 1
                        else str(spf_result)
                    )

                    if "spf" not in explanation:
                        continue

                    if spf_status == "fail":
                        if (
                            "pass" in explanation
                            and not _is_describing_discrepancy(
                                explanation,
                                "spf",
                            )
                        ):
                            unsupported.append(
                                "Explanation claims SPF passed "
                                "but security evidence shows SPF failed"
                            )
                        else:
                            evidence_refs.append(
                                f"SPF result: {spf_context} "
                                "(acknowledges failure)"
                            )

                    elif spf_status == "pass":
                        if (
                            "fail" in explanation
                            and not _is_describing_discrepancy(
                                explanation,
                                "spf",
                            )
                        ):
                            unsupported.append(
                                "Explanation claims SPF failed "
                                "but security evidence shows SPF passed"
                            )
                        else:
                            evidence_refs.append(
                                f"SPF result: {spf_context} "
                                "(acknowledges pass)"
                            )

                    else:
                        evidence_refs.append(
                            f"SPF result: {spf_result}"
                        )

            # --------------------------------------------------
            # DKIM
            # --------------------------------------------------

            dkim_result = authentication.get(
                "dkim"
            )

            if dkim_result is not None and "dkim" in explanation:

                if dkim_result is False:

                    if (
                        "pass" in explanation
                        and not _is_describing_discrepancy(
                            explanation,
                            "dkim",
                        )
                    ):
                        unsupported.append(
                            "Explanation claims DKIM passed "
                            "but security evidence shows DKIM failed"
                        )
                    else:
                        evidence_refs.append(
                            "DKIM result: fail "
                            "(acknowledges failure)"
                        )

                elif dkim_result is True:

                    if (
                        "fail" in explanation
                        and not _is_describing_discrepancy(
                            explanation,
                            "dkim",
                        )
                    ):
                        unsupported.append(
                            "Explanation claims DKIM failed "
                            "but security evidence shows DKIM passed"
                        )
                    else:
                        evidence_refs.append(
                            "DKIM result: pass "
                            "(acknowledges pass)"
                        )

                else:

                    evidence_refs.append(
                        f"DKIM result: {dkim_result}"
                    )

            # --------------------------------------------------
            # DMARC
            # --------------------------------------------------

            dmarc_result = authentication.get(
                "dmarc"
            )

            if dmarc_result is not None and "dmarc" in explanation:

                dmarc_text = str(
                    dmarc_result
                ).lower()

                if "fail" in dmarc_text:

                    if (
                        "pass" in explanation
                        and not _is_describing_discrepancy(
                            explanation,
                            "dmarc",
                        )
                    ):
                        unsupported.append(
                            "Explanation claims DMARC passed "
                            "but security evidence shows DMARC failed"
                        )
                    else:
                        evidence_refs.append(
                            "DMARC result indicates failure"
                        )

                elif "pass" in dmarc_text:

                    if (
                        "fail" in explanation
                        and not _is_describing_discrepancy(
                            explanation,
                            "dmarc",
                        )
                    ):
                        unsupported.append(
                            "Explanation claims DMARC failed "
                            "but security evidence shows DMARC passed"
                        )
                    else:
                        evidence_refs.append(
                            "DMARC result indicates pass"
                        )

                else:

                    evidence_refs.append(
                        f"DMARC result: {dmarc_result}"
                    )

            # --------------------------------------------------
            # DNS ANALYSIS
            # --------------------------------------------------

            dns = authentication.get(
                "dns",
                {},
            )

            if isinstance(dns, dict):

                dns_reports = dns.get(
                    "dns_report",
                    [],
                )

                if (
                    isinstance(dns_reports, list)
                    and dns_reports
                ):
                    evidence_refs.append(
                        "DNS analysis contains "
                        f"{len(dns_reports)} domain report(s)"
                    )

                reverse_dns_reports = dns.get(
                    "reverse_dns_report",
                    [],
                )

                if (
                    isinstance(reverse_dns_reports, list)
                    and reverse_dns_reports
                ):
                    evidence_refs.append(
                        "Reverse-DNS analysis contains "
                        f"{len(reverse_dns_reports)} report(s)"
                    )

        # ======================================================
        # SENDER ANALYSIS
        # ======================================================

        sender_analysis = sec_evidence.get(
            "sender_analysis",
            {},
        )

        if isinstance(sender_analysis, dict):

            findings = sender_analysis.get(
                "findings",
                [],
            )

            if isinstance(findings, list):
                for finding in findings:
                    evidence_refs.append(
                        "Sender analysis finding: "
                        f"{finding}"
                    )

        # ======================================================
        # HEADER ANALYSIS
        # ======================================================

        header_analysis = sec_evidence.get(
            "header_analysis",
            {},
        )

        if isinstance(header_analysis, dict):

            findings = header_analysis.get(
                "findings",
                [],
            )

            if isinstance(findings, list):
                for finding in findings:
                    evidence_refs.append(
                        "Header analysis finding: "
                        f"{finding}"
                    )

        # ======================================================
        # PHISHING ANALYSIS
        # ======================================================

        phishing_analysis = sec_evidence.get(
            "phishing_analysis",
            [],
        )

        if isinstance(phishing_analysis, list):
            for finding in phishing_analysis:
                evidence_refs.append(
                    "Phishing analysis finding: "
                    f"{finding}"
                )

    # ==========================================================
    # THREAT ANALYSIS
    # ==========================================================

    threat_intel = context.threat_intelligence

    if isinstance(threat_intel, dict):

        # ------------------------------------------------------
        # IP ANALYSIS
        # ------------------------------------------------------

        ip_analysis = threat_intel.get(
            "ip_analysis",
            {},
        )

        if isinstance(ip_analysis, dict):

            originating_ip = ip_analysis.get(
                "originating_ip"
            )

            if originating_ip:
                evidence_refs.append(
                    "Threat intelligence originating IP: "
                    f"{originating_ip}"
                )

            abuse_reports = ip_analysis.get(
                "iocs_ip_abuseIPDB",
                [],
            )

            if (
                isinstance(abuse_reports, list)
                and abuse_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(abuse_reports)} AbuseIPDB IOC report(s)"
                )

            otx_reports = ip_analysis.get(
                "iocs_ip_alienvaultOTX",
                [],
            )

            if (
                isinstance(otx_reports, list)
                and otx_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(otx_reports)} AlienVault OTX IOC report(s)"
                )

            originating_abuse_reports = ip_analysis.get(
                "originating_ip_abuseIPDB",
                [],
            )

            if (
                isinstance(originating_abuse_reports, list)
                and originating_abuse_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(originating_abuse_reports)} "
                    "originating-IP AbuseIPDB report(s)"
                )

            originating_otx_reports = ip_analysis.get(
                "originating_ip_alienvaultOTX",
                [],
            )

            if (
                isinstance(originating_otx_reports, list)
                and originating_otx_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(originating_otx_reports)} "
                    "originating-IP AlienVault OTX report(s)"
                )

        # ------------------------------------------------------
        # URL VIRUSTOTAL
        # ------------------------------------------------------

        url_analysis = threat_intel.get(
            "url_analysis",
            {},
        )

        if isinstance(url_analysis, dict):

            url_reports = url_analysis.get(
                "virusTotal_report",
                [],
            )

            if (
                isinstance(url_reports, list)
                and url_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(url_reports)} VirusTotal URL report(s)"
                )

        # ------------------------------------------------------
        # DOMAIN VIRUSTOTAL
        # ------------------------------------------------------

        domain_analysis = threat_intel.get(
            "domain_analysis",
            {},
        )

        if isinstance(domain_analysis, dict):

            domain_reports = domain_analysis.get(
                "virusTotal_report",
                [],
            )

            if (
                isinstance(domain_reports, list)
                and domain_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(domain_reports)} VirusTotal domain report(s)"
                )

        # ------------------------------------------------------
        # ATTACHMENT VIRUSTOTAL
        # ------------------------------------------------------

        attachment_analysis = threat_intel.get(
            "attachment_analysis",
            {},
        )

        if isinstance(attachment_analysis, dict):

            attachment_reports = attachment_analysis.get(
                "virusTotal_report",
                [],
            )

            if (
                isinstance(attachment_reports, list)
                and attachment_reports
            ):
                evidence_refs.append(
                    "Threat intelligence contains "
                    f"{len(attachment_reports)} VirusTotal "
                    "attachment report(s)"
                )

    # ==========================================================
    # DETERMINISTIC SIGNAL ALIGNMENT
    # ==========================================================

    # ----------------------------------------------------------
    # Urgency detected
    # ----------------------------------------------------------

    if assessment.urgency_detected:

        if understanding.urgency:

            evidence_refs.append(
                "Urgency signals: "
                f"{[s.indicator for s in understanding.urgency]}"
            )

        else:

            unsupported.append(
                "Assessment claims urgency_detected=true "
                "but no urgency signals were extracted "
                "by the understanding layer"
            )

    # ----------------------------------------------------------
    # Credential request detected
    # ----------------------------------------------------------

    if assessment.credential_request_detected:

        if understanding.credential_request:

            evidence_refs.append(
                "Credential signals: "
                f"{[s.indicator for s in understanding.credential_request]}"
            )

        else:

            unsupported.append(
                "Assessment claims credential_request_detected=true "
                "but no credential signals were extracted "
                "by the understanding layer"
            )

    # ----------------------------------------------------------
    # Financial request detected
    # ----------------------------------------------------------

    if assessment.financial_request_detected:

        if understanding.financial_request:

            evidence_refs.append(
                "Financial signals: "
                f"{[s.indicator for s in understanding.financial_request]}"
            )

        else:

            unsupported.append(
                "Assessment claims financial_request_detected=true "
                "but no financial signals were extracted "
                "by the understanding layer"
            )

    # ----------------------------------------------------------
    # Social engineering signals
    # ----------------------------------------------------------

    if understanding.social_engineering:

        evidence_refs.append(
            "Social engineering signals: "
            f"{[s.indicator for s in understanding.social_engineering]}"
        )

    # ----------------------------------------------------------
    # Phishing indicators
    # ----------------------------------------------------------

    if understanding.phishing_indicators:

        evidence_refs.append(
            "Phishing indicators: "
            f"{[s.indicator for s in understanding.phishing_indicators]}"
        )

    # ----------------------------------------------------------
    # BEC indicators
    # ----------------------------------------------------------

    if understanding.bec_indicators:

        evidence_refs.append(
            "BEC indicators: "
            f"{[s.indicator for s in understanding.bec_indicators]}"
        )

    # ==========================================================
    # PROBABILITY CALIBRATION / SEMANTIC GROUNDING
    # ==========================================================

    probability_unsupported = _check_probability_calibration(
        assessment,
        context,
        understanding,
        evidence_refs,
    )
    unsupported.extend(probability_unsupported)

    # ==========================================================
    # FORENSIC / ATTACHMENT GROUNDING
    # ==========================================================

    forensic_unsupported, forensic_refs = (
        _check_forensic_grounding(
            assessment,
            context,
        )
    )

    # ----------------------------------------------------------
    # Attachment risk can also be supported by VirusTotal
    # threat intelligence.
    # ----------------------------------------------------------

    if forensic_unsupported and any(
        "attachment_risk_detected=true but no forensic finding"
        in claim
        for claim in forensic_unsupported
    ):

        ti = getattr(
            context,
            "threat_intelligence",
            {},
        ) or {}

        if isinstance(ti, dict):

            att = ti.get(
                "attachment_analysis",
                {},
            )

            if isinstance(att, dict):

                vt = att.get(
                    "virusTotal_report",
                    [],
                )

                if isinstance(vt, list):

                    has_vt_risk = False

                    for report in vt:

                        if not isinstance(
                            report,
                            dict,
                        ):
                            continue

                        try:
                            positives = int(
                                report.get(
                                    "positives",
                                    0,
                                )
                            )
                        except (
                            TypeError,
                            ValueError,
                        ):
                            positives = 0

                        if positives <= 0:
                            continue

                        scan_results = report.get(
                            "scan_results",
                            {},
                        )

                        if isinstance(
                            scan_results,
                            dict,
                        ) and scan_results:

                            for engine in scan_results.values():

                                if (
                                    isinstance(
                                        engine,
                                        dict,
                                    )
                                    and engine.get(
                                        "detected"
                                    ) is True
                                ):
                                    has_vt_risk = True
                                    break

                            if has_vt_risk:
                                break

                        else:

                            has_vt_risk = True
                            break

                    if has_vt_risk:

                        forensic_unsupported = [
                            claim
                            for claim in forensic_unsupported
                            if (
                                "attachment_risk_detected=true "
                                "but no forensic finding"
                            ) not in claim
                        ]

                        forensic_refs.append(
                            "attachment_risk_detected is supported "
                            "by attachment threat intelligence "
                            "VirusTotal positives"
                        )

    unsupported.extend(
        forensic_unsupported
    )

    evidence_refs.extend(
        forensic_refs
    )

    # ==========================================================
    # FINAL RESULT
    # ==========================================================

    grounded = len(unsupported) == 0

    return GroundingResult(
        grounded=grounded,
        unsupported_claims=unsupported,
        evidence_references=evidence_refs,
    )

# ---------------------------------------------------------------------------
# Forensic / attachment grounding
#
# Deterministic QC only. No LLM is called from here, nothing is looked up
# externally, and no score, probability or verdict is produced. The question
# answered is narrow and it is worth stating precisely:
#
#   "Does the value at the exact evidence path this finding cites actually
#    state what the finding claims?"
#
# It is NOT "is the file really malicious". The backend payload remains
# untrusted evidence; grounding validates support for a claim, never the
# truthfulness of the evidence behind it.
# ---------------------------------------------------------------------------

# Every provenance path the understanding layer emits begins with this prefix,
# while ``context.forensic_evidence`` holds the tree *without* the wrapper. The
# prefix is therefore stripped before walking.
_FORENSIC_ROOT = _ea._FORENSIC_ROOT

# weak_observation < reported_indicator < explicit_detection. Used only to
# detect an over-claim - a finding declaring more certainty than the cited
# evidence can carry. Not a score: the ordering is never reported, summed, or
# compared against a threshold.
_STRENGTH_RANK = {
    WEAK_OBSERVATION: 0,
    REPORTED_INDICATOR: 1,
    EXPLICIT_DETECTION: 2,
}

# A path longer than this is not a provenance path. The input guard caps
# evidence nesting well below it; the bound exists because an assessment is
# model output, so a pathological path must stay cheap to reject.
_MAX_PATH_TOKENS = 200

# Backtracking budget for dotted-key resolution (see _resolve_tokens). Bounds
# the worst case when many key prefixes match; ordinary paths use one step per
# segment.
_MAX_RESOLUTION_STEPS = 4096

# Longest evidence value rendered into a claim or reference, so one huge blob
# cannot dominate the output.
_MAX_VALUE_LENGTH = 200


@dataclass(frozen=True)
class ForensicPathResolution:
    """
    Outcome of resolving one provenance path against the forensic evidence tree.

    ``parent`` and ``key`` are carried deliberately. Some checks need the object
    the value sits in - a ``known_malicious_hash`` finding is only correctly
    named when a hash is present in the same evidence object, exactly as the
    understanding layer requires - and ``key`` is the *effective* final key,
    which can differ from the last path segment when a dotted key had to be
    re-joined. ``parent`` is a reference into the caller's evidence, never a
    copy, and is only ever read.

    ``error`` is one of "" (resolved), "malformed", "not_rooted", "too_long" or
    "missing". It is a reason code for a human-readable message, not a rank.
    """

    resolved: bool
    path: str
    value: Any = None
    parent: dict[str, Any] | None = None
    key: str = ""
    error: str = ""


def _tokenize_path(path: str) -> list[tuple[str, Any]] | None:
    """
    Split a provenance path into ``("key", name)`` / ``("index", n)`` tokens.

    Accepts exactly the vocabulary the understanding layer emits: dotted keys
    and ``[n]`` list indices, e.g.
    ``forensic_evidence.attachments[0].analysis.embedded_files[0].malicious``.

    Returns None for anything that is not a well-formed path - an empty segment
    ("a..b"), a leading or trailing dot, a leading index, a negative or
    non-numeric index, an unterminated bracket, or text wedged directly after
    "]" ("a[0]b"). Nothing is repaired and nothing is guessed: a malformed path
    is reported as malformed, because silently rewriting it would destroy the
    provenance the path exists to carry.
    """
    if not isinstance(path, str) or not path.strip():
        return None

    tokens: list[tuple[str, Any]] = []
    index = 0
    length = len(path)
    expect_key = True

    while index < length:
        char = path[index]
        if char == "[":
            close = path.find("]", index + 1)
            if close == -1:
                return None
            digits = path[index + 1:close]
            # ASCII digits only: rejects "", "-1", "1a", " 1" and any exotic
            # numeral form that int() would either accept surprisingly or reject.
            if not (digits.isascii() and digits.isdigit()):
                return None
            if not tokens:
                return None
            tokens.append(("index", int(digits)))
            index = close + 1
            expect_key = False
            continue
        if char == ".":
            if expect_key:
                return None
            expect_key = True
            index += 1
            continue
        if not expect_key:
            return None
        start = index
        while index < length and path[index] not in ".[":
            index += 1
        segment = path[start:index]
        if not segment:
            return None
        tokens.append(("key", segment))
        expect_key = False

    if expect_key:
        return None
    return tokens


def _resolve_tokens(
    node: Any,
    tokens: list[tuple[str, Any]],
    start: int,
    budget: list[int],
) -> tuple[Any, dict[str, Any] | None, str] | None:
    """
    Walk ``tokens[start:]`` from ``node``, returning ``(value, parent, key)``.

    Only the exact route named by the tokens is followed. There is no search:
    a missing key or an out-of-range index fails immediately rather than looking
    for the same field elsewhere, which is what makes
    ``attachments[0].malicious`` unsatisfiable by ``attachments[3].malicious``.

    The one place this backtracks is a dict key that itself contains dots. The
    understanding layer builds child paths as ``f"{path}.{key}"`` with no
    escaping, so evidence shaped ``{"files": {"invoice.pdf.exe": {...}}}``
    legitimately emits ``forensic_evidence.files.invoice.pdf.exe.malicious``.
    Consecutive key segments are therefore re-joined shortest-first: the common
    case costs one step per segment, and shortest-first is also the deterministic
    tie-break when several joins would match. An ``[n]`` segment is always an
    index and never part of a key name.
    """
    if budget[0] <= 0:
        return None
    budget[0] -= 1

    kind, token = tokens[start]

    if kind == "index":
        if not isinstance(node, list) or token >= len(node):
            return None
        child = node[token]
        if start + 1 == len(tokens):
            # The value sits in a list, so there is no dict object to inspect
            # around it.
            return child, None, ""
        return _resolve_tokens(child, tokens, start + 1, budget)

    if not isinstance(node, dict):
        return None

    end = start
    candidate = ""
    while end < len(tokens) and tokens[end][0] == "key":
        candidate = tokens[end][1] if end == start else f"{candidate}.{tokens[end][1]}"
        if candidate in node:
            child = node[candidate]
            if end + 1 == len(tokens):
                return child, node, candidate
            found = _resolve_tokens(child, tokens, end + 1, budget)
            if found is not None:
                return found
        if budget[0] <= 0:
            return None
        end += 1

    return None


def resolve_forensic_path(forensic_evidence: Any, path: str) -> ForensicPathResolution:
    """
    Resolve one provenance path against the supplied forensic evidence.

    Public because it is the substance of forensic grounding and is worth
    exercising directly. ``forensic_evidence`` is the unwrapped tree as carried
    on ``AnalysisContext.forensic_evidence``, while every path the understanding
    layer emits is rooted at ``forensic_evidence``; the root segment is therefore
    required and then stripped before walking.

    The evidence is only read. Nothing is flattened, nothing is copied, nothing
    is added or removed, and no value is searched for anywhere other than the
    single location the path names.
    """
    tokens = _tokenize_path(path)
    if tokens is None:
        return ForensicPathResolution(resolved=False, path=path, error="malformed")
    if len(tokens) > _MAX_PATH_TOKENS:
        return ForensicPathResolution(resolved=False, path=path, error="too_long")
    if tokens[0] != ("key", _FORENSIC_ROOT):
        return ForensicPathResolution(resolved=False, path=path, error="not_rooted")
    if len(tokens) == 1:
        # The bare root names the whole tree rather than a field. The assessment
        # contract already rejects it as a collapsed label; rejecting it here too
        # keeps the layers consistent if a path ever arrives from elsewhere.
        return ForensicPathResolution(resolved=False, path=path, error="not_rooted")
    if not isinstance(forensic_evidence, dict) or not forensic_evidence:
        return ForensicPathResolution(resolved=False, path=path, error="missing")

    found = _resolve_tokens(forensic_evidence, tokens, 1, [_MAX_RESOLUTION_STEPS])
    if found is None:
        return ForensicPathResolution(resolved=False, path=path, error="missing")

    value, parent, key = found
    return ForensicPathResolution(
        resolved=True,
        path=path,
        value=value,
        parent=parent,
        key=key,
    )


def _render_value(value: Any) -> str:
    """
    Render an evidence value for a human-readable claim or reference.

    ``json.dumps`` so a boolean reads as ``true`` rather than ``True`` - the
    reference then matches the shape of the evidence it came from - and so a
    nested value renders as JSON instead of a Python repr. ``ensure_ascii=False``
    keeps Unicode evidence legible. The result is text in a report only: it is
    bounded, never parsed, and never treated as an instruction, however much a
    hostile filename or extracted string may look like one.
    """
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(value)
    if len(text) > _MAX_VALUE_LENGTH:
        return text[:_MAX_VALUE_LENGTH] + "..."
    return text


# ---------------------------------------------------------------------------
# Per-finding support checks
#
# Each check answers one question about the *single* field the finding cites:
# "can this value carry this kind of claim, and how strongly at most?" It
# returns the strongest category the cited evidence supports, or None when the
# evidence does not support the claim at all.
#
# The field-name vocabularies come from the understanding layer, so a finding the
# extractor legitimately produced is never rejected here. No new backend field
# name is invented anywhere in this section.
# ---------------------------------------------------------------------------


def _flag_says(canon_key: str, value: Any, keys: tuple[str, ...]) -> bool:
    """Cited field is one of ``keys`` and explicitly affirmative."""
    return canon_key in keys and _ea._is_affirmative(value)


def _reputation_says(canon_key: str, value: Any, vocabulary: frozenset[str]) -> bool:
    """Cited field is a reputation field stating one of ``vocabulary``."""
    if canon_key not in _ea._REPUTATION_KEYS or not isinstance(value, str):
        return False
    return value.strip().lower() in vocabulary


def _supports_malware_detected(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """Explicit backend malware flag, e.g. ``{"malware_detected": true}``."""
    if _flag_says(canon_key, value, _ea._MALWARE_FLAG_KEYS):
        return EXPLICIT_DETECTION
    return None


def _supports_malicious_attachment(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """
    Explicit maliciousness statement about the file, e.g. ``{"malicious": true}``.

    An explicit malware flag counts too: it states strictly more than "this
    attachment is malicious", so a finding citing it is not over-claiming.
    """
    if _flag_says(canon_key, value, _ea._MALICIOUS_FLAG_KEYS):
        return EXPLICIT_DETECTION
    if _flag_says(canon_key, value, _ea._MALWARE_FLAG_KEYS):
        return EXPLICIT_DETECTION
    return None


def _supports_known_malicious_hash(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """
    An explicit known-bad statement *and* a hash in the same evidence object.

    Both halves matter. The hash requirement is why a bare digest grounds
    nothing: a SHA-256 is an identifier and a fingerprint, so a path resolving
    to the digest itself supports no claim at all, and a finding named after a
    hash must cite a field that explicitly says the hash is known malicious,
    blacklisted, or malicious by reputation. Conversely, an explicit known-bad
    flag in an object that holds no hash supports a generic intelligence match
    rather than a hash finding - the same degradation the extractor performs -
    so it is not accepted under this name.
    """
    explicit = (
        _flag_says(canon_key, value, _ea._KNOWN_MALICIOUS_FLAG_KEYS)
        or _reputation_says(canon_key, value, _ea._MALICIOUS_REPUTATIONS)
    )
    if not explicit:
        return None
    if parent is None or _ea._find_hash(parent) is None:
        return None
    return EXPLICIT_DETECTION


def _supports_threat_intelligence_match(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """
    A non-empty findings/matches/detections list, or an explicit known-bad flag.

    The list form is a reported intelligence result: the backend says it matched
    something. The flag form mirrors the extractor's degradation - an explicit
    known-bad statement with no hash in the same object is reported under this
    generic name - and is an explicit statement, so it is not downgraded.
    """
    if canon_key in _ea._TI_MATCH_LIST_KEYS and isinstance(value, list) and value:
        return REPORTED_INDICATOR
    if _flag_says(canon_key, value, _ea._KNOWN_MALICIOUS_FLAG_KEYS):
        return EXPLICIT_DETECTION
    if _reputation_says(canon_key, value, _ea._MALICIOUS_REPUTATIONS):
        return EXPLICIT_DETECTION
    return None


def _supports_suspicious_attachment(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """
    Explicit suspicion flag, or a reputation stating suspicion/poor.

    An explicit maliciousness statement also supports the weaker claim of
    suspicion: under-claiming is never an unsupported claim.
    """
    if _flag_says(canon_key, value, _ea._SUSPICIOUS_FLAG_KEYS):
        return REPORTED_INDICATOR
    if _reputation_says(canon_key, value, _ea._SUSPICIOUS_REPUTATIONS):
        return REPORTED_INDICATOR
    if _reputation_says(canon_key, value, _ea._MALICIOUS_REPUTATIONS):
        return REPORTED_INDICATOR
    stronger = (
        _ea._MALICIOUS_FLAG_KEYS + _ea._MALWARE_FLAG_KEYS + _ea._KNOWN_MALICIOUS_FLAG_KEYS
    )
    if _flag_says(canon_key, value, stronger):
        return REPORTED_INDICATOR
    return None


def _supports_high_abuse_confidence(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """
    The abuse-confidence score itself, at or above the existing high threshold.

    Only the confidence value is read, and only from the field the finding cites.
    A country, country code, ISP, usage type or report count grounds nothing, and
    a mid-range score grounds nothing either. This never becomes a malware claim:
    the strongest it can carry is a reported indicator about the hosting IP.
    """
    if canon_key not in _ea._ABUSE_CONFIDENCE_KEYS:
        return None
    score = _ea._as_number(value)
    if score is None or score < _ea._ABUSE_CONFIDENCE_HIGH_THRESHOLD:
        return None
    return REPORTED_INDICATOR


def _supports_suspicious_file_type(canon_key: str, value: Any, parent: dict[str, Any] | None) -> str | None:
    """
    An executable/script extension on the cited value - and nothing more.

    Keyed on the *value* rather than on a field name, deliberately. The extractor
    reads filenames from five different keys and a backend may report the type
    under a name neither layer has seen yet, so demanding a particular key would
    mean either missing real evidence or inventing field names the understanding
    layer does not use. Capped at ``weak_observation``, which is the whole point:
    an extension is metadata, so a finding citing a filename can never ground an
    explicit detection, and a ``malware_detected`` finding pointing at a filename
    fails its own check rather than being quietly accepted here.
    """
    if not isinstance(value, str):
        return None
    if _ea._file_extension(value) in _ea._SUSPICIOUS_EXTENSIONS:
        return WEAK_OBSERVATION
    # A bare type token such as "exe" or ".exe", as opposed to a whole filename.
    if value.strip().lower().lstrip(".") in _ea._SUSPICIOUS_EXTENSIONS:
        return WEAK_OBSERVATION
    return None


# finding_type -> support check. Keyed on the canonical vocabulary documented on
# ``ForensicFinding`` and produced by the extractor. A type outside this table is
# not judged (see _check_forensic_grounding): the contract leaves finding_type an
# open string so the extractor's vocabulary can grow, and accusing an unknown
# type of being unsupported would turn a future indicator into a false alarm.
_SUPPORT_CHECKS = {
    "malware_detected": _supports_malware_detected,
    "malicious_attachment": _supports_malicious_attachment,
    "known_malicious_hash": _supports_known_malicious_hash,
    "attachment_threat_intelligence_match": _supports_threat_intelligence_match,
    "suspicious_attachment": _supports_suspicious_attachment,
    "high_abuse_confidence": _supports_high_abuse_confidence,
    "suspicious_file_type": _supports_suspicious_file_type,
}

# Finding types that state maliciousness outright. Used only for the
# assessment-level ``malicious_attachment_detected`` cross-check.
_MALICIOUSNESS_FINDING_TYPES = (
    "malware_detected",
    "malicious_attachment",
    "known_malicious_hash",
)


def _unresolved_claim(
    label: str,
    finding: ForensicFinding,
    resolution: ForensicPathResolution,
) -> str:
    """Human-readable description of a finding whose cited path does not resolve."""
    path = finding.evidence_path
    if resolution.error == "malformed":
        return (
            f"{label} cites evidence_path {path!r}, which is not a well-formed "
            f"provenance path and cannot be resolved against the supplied "
            f"forensic evidence"
        )
    if resolution.error == "too_long":
        return (
            f"{label} cites evidence_path {path!r}, which has more than "
            f"{_MAX_PATH_TOKENS} segments and is not a provenance path into the "
            f"supplied forensic evidence"
        )
    if resolution.error == "not_rooted":
        return (
            f"{label} cites evidence_path {path!r}, which does not name a field "
            f"under '{_FORENSIC_ROOT}' and so points at no forensic evidence location"
        )
    return (
        f"{label} claims '{finding.finding_type}' from evidence_path {path!r}, "
        f"but no such field exists in the supplied forensic evidence"
    )


def _unsupported_claim(
    label: str,
    finding: ForensicFinding,
    resolution: ForensicPathResolution,
    rendered: str,
) -> str:
    """Human-readable description of a finding the cited evidence does not support."""
    field_name = resolution.key or "the cited value"
    message = (
        f"{label} claims '{finding.finding_type}' from evidence_path "
        f"{finding.evidence_path!r}, but the evidence there states "
        f"{field_name} = {rendered}, which does not support that finding"
    )
    negative = resolution.value is False or (
        isinstance(resolution.value, str)
        and resolution.value.strip().lower() in ("false", "no")
    )
    if negative:
        return message + "; the supplied evidence explicitly states the opposite"
    if _ea._looks_like_hash(resolution.value):
        return (
            message
            + "; a hash value is an identifier of the file, not a statement about it"
        )
    return message


def _check_forensic_grounding(
    assessment: AIAssessment,
    context: AnalysisContext,
) -> tuple[list[str], list[str]]:
    """
    Check every forensic finding against the exact evidence path it cites.

    Returns ``(unsupported_claims, evidence_references)`` for the caller to merge
    into the single ``GroundingResult``. Purely deterministic: same assessment and
    same evidence produce the same two lists, in the same order, every time. No
    model is consulted, nothing is looked up externally, and neither the
    assessment, the findings, nor the evidence tree is modified in any way - every
    structure here is read, and the only objects created are strings.

    Each finding is judged independently and on its own terms:

    - the cited path must resolve, at exactly the location named;
    - the value there must actually support the kind of claim being made;
    - the declared ``evidence_strength`` must not exceed what that value can
      carry, so a weak observation is never promoted into a detection.

    What this does NOT do is decide whether the file is malicious. The backend
    payload remains untrusted evidence; the question answered is only whether the
    AI's finding has support in what was supplied.
    """
    unsupported: list[str] = []
    refs: list[str] = []

    findings = assessment.attachment_findings or []
    evidence = context.forensic_evidence
    if not isinstance(evidence, dict):
        evidence = {}

    # (finding_type, strength actually supported) for each grounded finding.
    grounded: list[tuple[str, str]] = []
    unverifiable = 0

    for position, finding in enumerate(findings):
        label = f"attachment_findings[{position}]"
        finding_type = finding.finding_type.strip().lower()
        resolution = resolve_forensic_path(evidence, finding.evidence_path)

        if not resolution.resolved:
            unsupported.append(_unresolved_claim(label, finding, resolution))
            continue

        rendered = _render_value(resolution.value)
        check = _SUPPORT_CHECKS.get(finding_type)
        if check is None:
            unverifiable += 1
            refs.append(
                f"{label} ({finding.finding_type}): {finding.evidence_path} = "
                f"{rendered} (path resolves; finding_type is outside the "
                f"vocabulary this layer can verify)"
            )
            continue

        supported = check(_ea._canon_key(resolution.key), resolution.value, resolution.parent)
        if supported is None:
            unsupported.append(_unsupported_claim(label, finding, resolution, rendered))
            continue

        declared = finding.evidence_strength
        if _STRENGTH_RANK.get(declared, 0) > _STRENGTH_RANK[supported]:
            unsupported.append(
                f"{label} declares evidence_strength '{declared}' for "
                f"'{finding.finding_type}', but the evidence at "
                f"{finding.evidence_path} = {rendered} supports no more than "
                f"'{supported}'"
            )
            continue

        grounded.append((finding_type, supported))
        refs.append(
            f"{label} ({finding.finding_type}, {declared}): "
            f"{finding.evidence_path} = {rendered}"
        )

    unsupported.extend(_check_forensic_flags(assessment, grounded, unverifiable, refs))
    return unsupported, refs


def _check_forensic_flags(
    assessment: AIAssessment,
    grounded: list[tuple[str, str]],
    unverifiable: int,
    refs: list[str],
) -> list[str]:
    """
    Cross-check the two assessment-level attachment booleans against the findings.

    A boolean asserted with nothing grounded behind it is an unsupported claim:
    it is the same over-claim as a finding citing a path that does not exist, one
    level up. ``malicious_attachment_detected`` needs a grounded finding that
    states maliciousness outright, so a hash, a file extension or a hosting
    attribute can never raise it.

    The reverse is deliberately not checked. Evidence present with the boolean
    left false is an under-claim, and grounding tests support, not completeness.
    """
    problems: list[str] = []

    if assessment.malicious_attachment_detected:
        supporting = sorted({
            finding_type
            for finding_type, strength in grounded
            if finding_type in _MALICIOUSNESS_FINDING_TYPES
            or (
                finding_type == "attachment_threat_intelligence_match"
                and strength == EXPLICIT_DETECTION
            )
        })
        if supporting:
            refs.append(
                "malicious_attachment_detected is supported by grounded finding(s): "
                + ", ".join(supporting)
            )
        else:
            problems.append(
                "Assessment sets malicious_attachment_detected=true but no forensic "
                "finding stating maliciousness is grounded in the supplied forensic "
                "evidence (a hash value, a file extension or a hosting attribute "
                "alone does not support it)"
            )

    if assessment.attachment_risk_detected:
        if grounded:
            refs.append(
                "attachment_risk_detected is supported by grounded forensic finding(s)"
            )
        else:
            problems.append(
                "Assessment sets attachment_risk_detected=true but no forensic finding "
                "is grounded in the supplied forensic evidence (unverifiable finding types such as 'weak_observation' do not count as support)"
            )

    return problems