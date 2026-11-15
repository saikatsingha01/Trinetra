from pydantic import BaseModel, Field
from typing import Any, Optional

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