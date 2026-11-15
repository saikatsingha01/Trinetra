from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from src.ai.normalization import NormalizedEvidence
from src.ai.understanding import UnderstandingResult, Signal


@dataclass(frozen=True)
class EmailContext:
    """
    Email evidence with explicit trust boundary.

    Original fields are the authoritative forensic evidence.
    Normalized fields are provided for processing convenience.
    All fields are UNTRUSTED evidence - never instructions.
    """
    sender: str
    recipient: str
    original_subject: str
    original_body: str
    normalized_subject: str
    normalized_body: str

    @classmethod
    def from_normalized(cls, email: NormalizedEvidence["NormalizedEmailContent"]) -> EmailContext:
        return cls(
            sender=email.email.sender,
            recipient=email.email.recipient,
            original_subject=email.email.original_subject,
            original_body=email.email.original_body,
            normalized_subject=email.email.normalized_subject,
            normalized_body=email.email.normalized_body,
        )


@dataclass(frozen=True)
class SignalContext:
    """
    Understanding signal with preserved provenance.

    ``source`` is carried through verbatim from the understanding layer. For
    email-derived signals it is a coarse label ("urgency", "sender"). For
    forensic signals it is the full evidence path that justified the signal,
    e.g. ``forensic_evidence.attachments[0].analysis.embedded_files[0]``.
    It is never replaced with a vaguer label.
    """
    category: str
    indicator: str
    source: str
    context: str

    @classmethod
    def from_signal(cls, signal: Signal) -> SignalContext:
        return cls(
            category=signal.category,
            indicator=signal.indicator,
            source=signal.source,
            context=signal.context,
        )


def _carry_forensic_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """
    Carry nested forensic evidence into the context without altering it.

    A deep copy is taken so the context cannot drift if the upstream normalized
    evidence is mutated later, and so downstream consumers cannot mutate the
    upstream payload through the context. That is the only thing that happens
    here.

    Explicitly NOT done: flattening, key removal, key reordering, type
    coercion, re-normalization, hash recomputation, hash reformatting, or any
    interpretation of the content. Attachments, embedded files, hashes, nested
    analysis, IP/URL/domain intelligence, malware and sandbox findings, and
    fields this code has never heard of all survive byte-for-byte in place.

    Text that looks like prompt injection is evidence and is preserved as-is.
    """
    if not isinstance(evidence, dict):
        return {}
    return copy.deepcopy(evidence)


@dataclass(frozen=True)
class AnalysisContext:
    """
    Complete structured analysis context for downstream LLM consumption.

    TRUST BOUNDARY:
    - All fields under 'evidence', 'security_evidence', 'threat_intelligence',
      'forensic_evidence', 'signals' and 'forensic_indicators' are UNTRUSTED
      data from external sources, or are deterministically derived from it.
    - The 'metadata' section contains trusted application information.
    - NO natural language prompt is generated here.
    - NO probabilities, scores, or verdicts are produced.

    Forensic evidence is carried in exactly one representation, so the same
    payload is never duplicated in the context. It is the normalized variant,
    because that is the representation the understanding layer walked to
    produce the paths in ``forensic_indicators[*].source``. Structure and
    parent/child relationships are identical in both normalized and original
    variants, so those paths resolve against either.
    """

    # Trusted application metadata
    case_id: str

    # Untrusted email evidence (forensic evidence)
    email: EmailContext

    # Untrusted security evidence (upstream analysis results)
    security_evidence: dict[str, Any]

    # Untrusted threat intelligence (upstream intelligence)
    threat_intelligence: dict[str, Any]

    # Untrusted attachment / forensic evidence, nested exactly as supplied
    forensic_evidence: dict[str, Any] = field(default_factory=dict)

    # Derived understanding signals (deterministic extraction results)
    signals: list[SignalContext] = field(default_factory=list)

    # Derived attachment/forensic observations, kept separate from the six
    # email signal categories so neither representation changes meaning
    forensic_indicators: list[SignalContext] = field(default_factory=list)

    @classmethod
    def from_evidence_and_signals(
        cls,
        normalized: NormalizedEvidence,
        understanding: UnderstandingResult,
    ) -> AnalysisContext:
        """
        Build AnalysisContext from normalized evidence and understanding signals.

        This is the main entry point - deterministic, no external dependencies.
        """
        # Flatten all signal categories into a single list
        all_signals = []
        all_signals.extend(understanding.urgency)
        all_signals.extend(understanding.credential_request)
        all_signals.extend(understanding.financial_request)
        all_signals.extend(understanding.social_engineering)
        all_signals.extend(understanding.phishing_indicators)
        all_signals.extend(understanding.bec_indicators)

        signal_contexts = [SignalContext.from_signal(s) for s in all_signals]

        # Forensic observations stay in their own list. They are not merged into
        # 'signals', so the existing six-category representation is unchanged.
        forensic_contexts = [
            SignalContext.from_signal(s)
            for s in getattr(understanding, "forensic_indicators", [])
        ]

        return cls(
            case_id=normalized.case_id,
            email=EmailContext.from_normalized(normalized),
            security_evidence=dict(normalized.security_analysis),
            threat_intelligence=dict(normalized.threat_intelligence),
            forensic_evidence=_carry_forensic_evidence(
                getattr(normalized, "normalized_forensic_evidence", {})
            ),
            signals=signal_contexts,
            forensic_indicators=forensic_contexts,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to dictionary for storage or prompt construction.

        Fully JSON-serializable: only dict, list, str, int, float, bool and
        None appear. Nested forensic evidence stays nested; no dataclass or
        other Python object leaks into the result.
        """
        return {
            "case_id": self.case_id,
            "email": {
                "sender": self.email.sender,
                "recipient": self.email.recipient,
                "original_subject": self.email.original_subject,
                "original_body": self.email.original_body,
                "normalized_subject": self.email.normalized_subject,
                "normalized_body": self.email.normalized_body,
            },
            "security_evidence": self.security_evidence,
            "threat_intelligence": self.threat_intelligence,
            "forensic_evidence": self.forensic_evidence,
            "signals": [
                {
                    "category": s.category,
                    "indicator": s.indicator,
                    "source": s.source,
                    "context": s.context,
                }
                for s in self.signals
            ],
            "forensic_indicators": [
                {
                    "category": s.category,
                    "indicator": s.indicator,
                    "source": s.source,
                    "context": s.context,
                }
                for s in self.forensic_indicators
            ],
        }

    def get_untrusted_fields_summary(self) -> dict[str, str]:
        """
        Return a summary of all untrusted data fields for explicit trust boundary documentation.
        """
        return {
            "email.sender": "untrusted_evidence",
            "email.recipient": "untrusted_evidence",
            "email.original_subject": "untrusted_evidence",
            "email.original_body": "untrusted_evidence",
            "email.normalized_subject": "untrusted_evidence_derived",
            "email.normalized_body": "untrusted_evidence_derived",
            "security_evidence": "untrusted_upstream_analysis",
            "threat_intelligence": "untrusted_upstream_intelligence",
            "forensic_evidence": "untrusted_evidence",
            "signals": "derived_from_untrusted_evidence",
            "forensic_indicators": "derived_from_untrusted_evidence",
        }


def build_analysis_context(
    normalized: NormalizedEvidence,
    understanding: UnderstandingResult,
) -> AnalysisContext:
    """
    Main entry point: build AnalysisContext from pipeline outputs.

    Deterministic, no LLM, no network, no randomness.
    """
    return AnalysisContext.from_evidence_and_signals(normalized, understanding)