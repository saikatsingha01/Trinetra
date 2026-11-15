from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field, ConfigDict, field_validator


class ModelInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    model_name: str = Field(default="", description="Name of the model used")
    model_version: str = Field(default="", description="Version of the model")
    provider: str = Field(default="", description="Model provider")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Model parameters")


# How strongly the supplied evidence backs a forensic finding.
#
# Deliberately categorical and deliberately tiny. This is NOT a score and NOT a
# probability: no numeric confidence is introduced anywhere in this contract.
# Scoring and the final verdict belong to the downstream Green Logic Engine.
#
# The distinction exists because the prohibitions on this component are
# asymmetric: an explicit backend malware detection and a filename ending in
# ".exe" must not be representable as the same kind of claim.
EXPLICIT_DETECTION = "explicit_detection"
REPORTED_INDICATOR = "reported_indicator"
WEAK_OBSERVATION = "weak_observation"

FORENSIC_EVIDENCE_STRENGTHS: tuple[str, ...] = (
    EXPLICIT_DETECTION,
    REPORTED_INDICATOR,
    WEAK_OBSERVATION,
)

# Generic labels that destroy provenance. A finding must point at the evidence
# field it came from, not at the subsystem it came from: "attachment" and
# "backend" identify nothing and cannot be resolved back into the evidence tree.
_COLLAPSED_PROVENANCE_LABELS = frozenset({
    "attachment",
    "attachments",
    "attachment_analysis",
    "attachment_evidence",
    "backend",
    "backend_analysis",
    "backend_evidence",
    "forensic",
    "forensics",
    "forensic_evidence",
    "forensic_analysis",
    "evidence",
    "email",
    "upstream",
    "unknown",
    "n/a",
    "na",
    "none",
    "-",
})


class ForensicFinding(BaseModel):
    """
    One attachment/forensic conclusion drawn by the AI, with provenance.

    This is interpretation, not evidence. The raw nested forensic payload
    already exists upstream (``EvidencePackage.forensic_evidence``, carried
    through ``AnalysisContext.forensic_evidence``) and is deliberately NOT
    duplicated here: every field on this model is a plain string, so no
    attachment tree, hash table, sandbox report or IP-intelligence blob can be
    copied into the assessment.

    ``evidence_path`` is the whole point of the model. It is the dotted/indexed
    path to the exact field that justified the finding, for example
    ``forensic_evidence.attachments[0].analysis.embedded_files[0].malicious``.
    It is the same path vocabulary the understanding layer emits in
    ``Signal.source``, so a finding can be resolved straight back into the
    evidence tree. It is named ``evidence_path`` rather than ``source``
    precisely to discourage the collapse this contract forbids: "source" invites
    a subsystem name, "evidence_path" does not.

    ``finding_type`` is intentionally an open string rather than a closed enum.
    The forensic extraction layer is schema-agnostic by design and its indicator
    vocabulary can grow, so pinning an enum here would force a contract change
    every time the backend grows a field. The canonical values, matching the
    indicators the understanding layer already produces, are:

    - ``malware_detected``                          (explicit malware finding)
    - ``malicious_attachment``                      (attachment/file explicitly malicious)
    - ``known_malicious_hash``                      (hash explicitly known-bad)
    - ``attachment_threat_intelligence_match``      (explicit intelligence match)
    - ``suspicious_attachment``                     (explicitly flagged suspicious)
    - ``high_abuse_confidence``                     (high IP abuse-confidence score)
    - ``suspicious_file_type``                      (executable/script extension only)

    Nothing here is a verdict and nothing here is a score. A finding records
    "the evidence at this path supports this observation, this strongly".
    """

    model_config = ConfigDict(extra="forbid")

    finding_type: str = Field(
        ...,
        description=(
            "Kind of forensic finding, e.g. 'malware_detected', "
            "'malicious_attachment', 'known_malicious_hash', "
            "'attachment_threat_intelligence_match', 'suspicious_attachment', "
            "'high_abuse_confidence', 'suspicious_file_type'"
        ),
    )
    evidence_path: str = Field(
        ...,
        description=(
            "Full dotted/indexed path to the forensic evidence field that "
            "justified this finding, e.g. "
            "'forensic_evidence.attachments[0].analysis.embedded_files[0].malicious'. "
            "Must not be collapsed to a generic label such as 'attachment' or 'backend'"
        ),
    )
    explanation: str = Field(
        ...,
        description=(
            "Grounded explanation of the finding, referencing what the evidence "
            "at evidence_path actually states"
        ),
    )
    evidence_strength: str = Field(
        default=WEAK_OBSERVATION,
        description=(
            "How strongly the supplied evidence backs this finding: "
            "'explicit_detection' (the backend explicitly reported it), "
            "'reported_indicator' (the backend reported a suspicion or an "
            "intelligence match), or 'weak_observation' (metadata or contextual "
            "attribute only, such as a file extension or a hosting attribute). "
            "Categorical, not a score. Defaults to the weakest value so an "
            "omitted strength can never silently promote an observation into a "
            "detection"
        ),
    )

    @field_validator("finding_type", "explanation")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        """Reject blank findings. The value itself is preserved unchanged."""
        if not v.strip():
            raise ValueError("Value must not be empty")
        return v

    @field_validator("evidence_path")
    @classmethod
    def validate_provenance_path(cls, v: str) -> str:
        """
        Require a resolvable provenance path.

        Two rules only: the path must not be blank, and it must not be one of
        the bare generic labels that identify a subsystem instead of a field.
        A label is rejected only when it is the *entire* value, so
        ``forensic_evidence.attachments[0]`` is accepted while a bare
        ``forensic_evidence`` is not.

        The value is returned exactly as supplied. Nothing is stripped,
        lowercased, re-quoted or rewritten: the stored path must remain
        byte-identical to the path that was asserted, or provenance is lost.
        """
        candidate = v.strip()
        if not candidate:
            raise ValueError("evidence_path must not be empty")
        if candidate.lower() in _COLLAPSED_PROVENANCE_LABELS:
            raise ValueError(
                f"evidence_path {v!r} is a generic label, not a provenance path. "
                "Provide the full path to the evidence field, e.g. "
                "'forensic_evidence.attachments[0].analysis.malware_detected'"
            )
        return v

    @field_validator("evidence_strength")
    @classmethod
    def validate_evidence_strength(cls, v: str) -> str:
        """Restrict evidence strength to the fixed categorical vocabulary."""
        if v not in FORENSIC_EVIDENCE_STRENGTHS:
            raise ValueError(
                f"evidence_strength must be one of {list(FORENSIC_EVIDENCE_STRENGTHS)}, got {v!r}"
            )
        return v


class AIAssessment(BaseModel):
    """
    The AI analysis component's output.

    This is an analysis product, not a decision. It carries probabilities for
    the email-borne attack classes, the attachment/forensic conclusions the
    model drew, and a grounded explanation. It deliberately carries no
    ``risk_score`` and no final ``verdict``: those are owned by the downstream
    Green Logic Engine.

    The attachment/forensic fields are additive and all three default to an
    empty/false value, so any assessment that predates them - including LLM
    output that never mentions them - validates unchanged. They are defined
    after ``model_info`` so the pre-existing ten keys keep their original order
    in ``model_dump()``.
    """

    model_config = ConfigDict(extra="forbid")

    phishing_probability: float = Field(
        ..., ge=0.0, le=1.0, description="Probability of phishing (0.0 to 1.0)"
    )
    bec_probability: float = Field(
        ..., ge=0.0, le=1.0, description="Probability of business email compromise (0.0 to 1.0)"
    )
    social_engineering_probability: float = Field(
        ..., ge=0.0, le=1.0, description="Probability of social engineering (0.0 to 1.0)"
    )
    urgency_detected: bool = Field(..., description="Whether urgency language was detected")
    credential_request_detected: bool = Field(..., description="Whether credential request was detected")
    financial_request_detected: bool = Field(..., description="Whether financial request was detected")
    suspicious_language: list[str] = Field(
        default_factory=list, description="List of suspicious language indicators"
    )
    detected_patterns: list[str] = Field(
        default_factory=list, description="List of detected attack patterns"
    )
    explanation: str = Field(..., description="Human-readable explanation of the assessment")
    model_info: ModelInfo = Field(default_factory=ModelInfo, description="Model metadata")

    # --- Attachment / forensic analysis (additive, optional) ---

    attachment_risk_detected: bool = Field(
        default=False,
        description=(
            "Whether any attachment/forensic risk observation was made. Broad: "
            "true for anything from a weak file-type observation upward. Not a "
            "score and not a verdict"
        ),
    )
    malicious_attachment_detected: bool = Field(
        default=False,
        description=(
            "Whether an attachment or embedded file was assessed as malicious, "
            "based on evidence that explicitly states so. A hash value alone, a "
            "file extension alone, or a country/ISP/hosting/abuse attribute "
            "alone does not support this"
        ),
    )
    attachment_findings: list[ForensicFinding] = Field(
        default_factory=list,
        description=(
            "Attachment/forensic conclusions, each traceable to the forensic "
            "evidence path that justified it. Interpretation only - the raw "
            "forensic evidence is not duplicated here"
        ),
    )

    @field_validator("phishing_probability", "bec_probability", "social_engineering_probability", mode="before")
    @classmethod
    def validate_probability_range(cls, v: float) -> float:
        if not isinstance(v, (int, float)):
            raise ValueError("Probability must be a number")
        if v < 0.0 or v > 1.0:
            raise ValueError("Probability must be between 0.0 and 1.0")
        return float(v)
