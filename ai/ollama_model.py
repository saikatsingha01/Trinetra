from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class EmailIocs(BaseModel):
    ip_address: list[str] = Field(default_factory=list)
    url: list[str] = Field(default_factory=list)
    domain: list[str] = Field(default_factory=list)


class EmailAttachment(BaseModel):
    filename: list[str] = Field(default_factory=list)
    content_type: list[str] = Field(default_factory=list)
    size: list[int] = Field(default_factory=list)
    sha256: list[Optional[str]] = Field(default_factory=list)

class EmailModel(BaseModel):
    from_: Optional[str] = Field(default=None, alias="from")
    to: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    received: list[str] = Field(default_factory=list)
    originating_ip: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    content: str
    content_type: list[str] = Field(default_factory=list)
    file_name: list[str] = Field(default_factory=list)
    attachments: EmailAttachment
    iocs: EmailIocs
    dkim_signature: Optional[str] = None
    authentication_results: list[str] = Field(default_factory=list)


class EvidencePackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., description="Unique case identifier")
    email: EmailModel
    security_analysis: SecurityAnalysisModel
    threat_intelligence: ThreatAnalysisModel
    forensic_evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Flexible nested JSON forensic evidence (attachments, malware analysis, file metadata, IP intelligence, hash reputation, sandbox results, extracted IOCs, etc.)"
    )

class IPAnalysisModel(BaseModel):
    iocs_ip_abuseIPDB: list[dict[str, Any]]
    iocs_ip_alienvaultOTX: list[dict[str, Any]]
    originating_ip: str | None = None
    originating_ip_abuseIPDB: list[dict[str, Any]] = Field(default_factory=list)
    originating_ip_alienvaultOTX: list[dict[str, Any]] = Field(default_factory=list)

class URLAnalysisModel(BaseModel):
    virusTotal_report: list[dict[str, Any]]

class DomainAnalysisModel(BaseModel):
    virusTotal_report: list[dict[str, Any]]

class AttachmentAnalysisModel(BaseModel):
    virusTotal_report: list[dict[str, Any]]

class ThreatAnalysisModel(BaseModel):
    ip_analysis: IPAnalysisModel
    url_analysis: URLAnalysisModel
    domain_analysis: DomainAnalysisModel
    attachment_analysis: AttachmentAnalysisModel

class DNSDomainReport(BaseModel):
    domain: str
    records: dict[str, list[str]]

class ReverseDNSReport(BaseModel):
    ip: str
    hosts: list[str]

class DNSAnalysisModel(BaseModel):
    dns_report: list[DNSDomainReport]
    reverse_dns_report: list[ReverseDNSReport]

class AuthenticationAnalysisModel(BaseModel):
    dns: DNSAnalysisModel
    spf: list[tuple[str, str]]
    dkim: bool
    dmarc: Any

class SenderDataModel(BaseModel):
    name: Optional[str] = ""
    email_address: Optional[str] = ""

class SenderAnalysisModel(BaseModel):
    from_: SenderDataModel = Field(alias="from")
    reply_to: SenderDataModel
    return_path: SenderDataModel
    findings: list[str]

class HeaderAnalysisModel(BaseModel):
    received: list[str]
    authentication_results: list[str]
    dkim_signature: Optional[str] = None
    findings: list[str]

class SecurityAnalysisModel(BaseModel):
    authentication_analysis: AuthenticationAnalysisModel
    sender_analysis: SenderAnalysisModel
    header_analysis: HeaderAnalysisModel
    phishing_analysis: list[str]

EvidencePackage.model_rebuild()