from __future__ import annotations

from typing import Any, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

#Such a Goood Project#
# =============================================================================
# THREAT INTELLIGENCE TRANSPORT MODELS
# =============================================================================


class IPAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iocs_ip_abuseIPDB: list[dict[str, Any]]
    iocs_ip_alienvaultOTX: list[dict[str, Any]]

    originating_ip: str | None = None
    originating_ip_abuseIPDB: list[dict[str, Any]] = Field(
        default_factory=list
    )
    originating_ip_alienvaultOTX: list[dict[str, Any]] = Field(
        default_factory=list
    )


class URLAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    virusTotal_report: list[dict[str, Any]]


class DomainAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    virusTotal_report: list[dict[str, Any]]


class AttachmentAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    virusTotal_report: list[dict[str, Any]]


class ThreatAnalysisModel(BaseModel):
    """
    Authoritative transport model for Workflow 3 / backend threat analysis.
    """

    model_config = ConfigDict(extra="forbid")

    ip_analysis: IPAnalysisModel
    url_analysis: URLAnalysisModel
    domain_analysis: DomainAnalysisModel
    attachment_analysis: AttachmentAnalysisModel


# =============================================================================
# SECURITY ANALYSIS TRANSPORT MODELS
# =============================================================================


class DNSDomainReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    records: dict[str, list[str]]


class ReverseDNSReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    hosts: list[str]


class DNSAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dns_report: list[DNSDomainReport]
    reverse_dns_report: list[ReverseDNSReport]


class AuthenticationAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dns: DNSAnalysisModel
    spf: list[tuple[str, str]]
    dkim: bool
    dmarc: Any


class SenderDataModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = ""
    email_address: Optional[str] = ""


class SenderAnalysisModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    from_: SenderDataModel = Field(alias="from")
    reply_to: SenderDataModel
    return_path: SenderDataModel
    findings: list[str]


class HeaderAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    received: list[str]
    authentication_results: list[str]
    dkim_signature: Optional[str] = None
    findings: list[str]


class SecurityAnalysisModel(BaseModel):
    """
    Authoritative transport model for Workflow 2 / backend security analysis.
    """

    model_config = ConfigDict(extra="forbid")

    authentication_analysis: AuthenticationAnalysisModel
    sender_analysis: SenderAnalysisModel
    header_analysis: HeaderAnalysisModel
    phishing_analysis: list[str]


# =============================================================================
# AUTHORITATIVE BACKEND -> LOGIC RECEIVER PAYLOAD
# =============================================================================


class EvidencePackage(BaseModel):
    """
    Single source of truth for the payload accepted by the Logic Gateway.

    Current backend payload:

        {
            "email_id": "...",
            "security_analysis": {...},
            "threat_analysis": {...}
        }

    Aliases are deliberately handled here so the receiver does not have
    to create duplicate Pydantic models or perform schema reconstruction.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(
        ...,
        validation_alias=AliasChoices(
            "case_id",
            "email_id",
        ),
        description="Backend email/case identifier",
    )

    security_analysis: SecurityAnalysisModel

    threat_intelligence: ThreatAnalysisModel = Field(
        validation_alias=AliasChoices(
            "threat_intelligence",
            "threat_analysis",
        )
    )

    # Optional future-compatible field. The current backend does not send it.
    forensic_evidence: dict[str, Any] = Field(
        default_factory=dict
    )