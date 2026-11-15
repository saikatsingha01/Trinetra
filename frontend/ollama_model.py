from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogicModelInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_name: str
    model_version: str
    provider: str
    parameters: dict[str, Any] = Field(
        default_factory=dict
    )


class LogicAttachmentFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_type: str
    evidence_path: str
    explanation: str
    evidence_strength: str


class LogicAIAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phishing_probability: float = Field(
        ge=0.0,
        le=1.0,
    )

    bec_probability: float = Field(
        ge=0.0,
        le=1.0,
    )

    social_engineering_probability: float = Field(
        ge=0.0,
        le=1.0,
    )

    urgency_detected: bool

    credential_request_detected: bool

    financial_request_detected: bool

    suspicious_language: list[str] = Field(
        default_factory=list
    )

    detected_patterns: list[str] = Field(
        default_factory=list
    )

    explanation: str

    model_info: LogicModelInfo

    attachment_risk_detected: bool

    malicious_attachment_detected: bool

    attachment_findings: list[LogicAttachmentFinding] = Field(
        default_factory=list
    )


class LogicGrounding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grounded: bool

    unsupported_claims: list[str] = Field(
        default_factory=list
    )

    evidence_references: list[str] = Field(
        default_factory=list
    )


class LogicProcessingModelInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str
    provider: str
    version: str


class LogicAnalysisReport(BaseModel):
    """
    Exact external transport contract for Ollama -> Logic.

    case_id is the original system-wide case identifier and must be
    preserved unchanged by the receiver.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str

    ai_assessment: LogicAIAssessment

    grounding: LogicGrounding

    processing_time_seconds: float = Field(
        ge=0.0
    )

    model_info: LogicProcessingModelInfo

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("case_id must be a non-empty string")

        # Deliberately return the original value unchanged.
        return value