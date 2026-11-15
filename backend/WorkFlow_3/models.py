from pydantic import BaseModel, Field
from typing import Any

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