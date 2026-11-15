from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Literal
from datetime import datetime, timezone


Verdict = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "MALICIOUS"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SPFResult(BaseModel):
    result: Literal["pass", "fail", "softfail", "neutral", "none", "unknown"] = "unknown"
    domain: Optional[str] = None
    record: Optional[str] = None


class DKIMResult(BaseModel):
    result: Literal["pass", "fail", "none", "unknown"] = "unknown"
    domain: Optional[str] = None
    selector: Optional[str] = None


class DMARCResult(BaseModel):
    result: Literal["pass", "fail", "none", "unknown"] = "unknown"
    domain: Optional[str] = None
    policy: Optional[str] = None
    alignment: Optional[str] = None


class SenderIdentity(BaseModel):
    from_address: str = Field(validation_alias="from")
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    domain_consistent: bool = True


class HeaderAnalysis(BaseModel):
    relay_anomaly: bool = False
    ip_hops: int = 0
    suspicious_headers: List[str] = Field(default_factory=list)


class SecurityAnalysis(BaseModel):
    spf: SPFResult = Field(default_factory=SPFResult)
    dkim: DKIMResult = Field(default_factory=DKIMResult)
    dmarc: DMARCResult = Field(default_factory=DMARCResult)
    sender_identity: Optional[SenderIdentity] = None
    header_analysis: HeaderAnalysis = Field(default_factory=HeaderAnalysis)
    suspicious_indicators: List[str] = Field(default_factory=list)


class IPThreatIntel(BaseModel):
    ip: str
    reputation_score: int = Field(ge=0, le=100, default=0)
    country: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    threat_history: bool = False
    categories: List[str] = Field(default_factory=list)


class DomainThreatIntel(BaseModel):
    domain: str
    reputation_score: int = Field(ge=0, le=100, default=0)
    country: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    threat_history: bool = False
    categories: List[str] = Field(default_factory=list)


class URLThreatIntel(BaseModel):
    url: str
    reputation_score: int = Field(ge=0, le=100, default=0)
    domain: Optional[str] = None
    threat_history: bool = False
    categories: List[str] = Field(default_factory=list)


class HashThreatIntel(BaseModel):
    hash: str
    hash_type: Literal["md5", "sha1", "sha256", "sha512"]
    reputation_score: int = Field(ge=0, le=100, default=0)
    threat_history: bool = False
    categories: List[str] = Field(default_factory=list)


class ThreatIntelligence(BaseModel):
    ips: List[IPThreatIntel] = Field(default_factory=list)
    domains: List[DomainThreatIntel] = Field(default_factory=list)
    urls: List[URLThreatIntel] = Field(default_factory=list)
    hashes: List[HashThreatIntel] = Field(default_factory=list)


class AIAssessment(BaseModel):
    phishing_probability: float = Field(ge=0.0, le=1.0, default=0.0)
    bec_probability: float = Field(ge=0.0, le=1.0, default=0.0)
    social_engineering_probability: float = Field(ge=0.0, le=1.0, default=0.0)
    urgency_detected: bool = False
    credential_request_detected: bool = False
    financial_request_detected: bool = False
    suspicious_language: List[str] = Field(default_factory=list)
    detected_patterns: List[str] = Field(default_factory=list)
    explanation: str = ""
    model_info: Optional[dict] = None


class IOCData(BaseModel):
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)


class EmailMetadata(BaseModel):
    sender: str
    recipient: str
    subject: str
    date: Optional[datetime] = None
    message_id: Optional[str] = None


class AnalysisInput(BaseModel):
    case_id: str
    email: Optional[EmailMetadata] = None
    iocs: IOCData = Field(default_factory=IOCData)
    security_analysis: SecurityAnalysis = Field(default_factory=SecurityAnalysis)
    threat_intelligence: ThreatIntelligence = Field(default_factory=ThreatIntelligence)
    ai_assessment: AIAssessment = Field(default_factory=AIAssessment)


class CorrelationReason(BaseModel):
    description: str
    evidence_sources: List[str]
    severity: Literal["low", "medium", "high", "critical"]


class LogicOutput(BaseModel):
    case_id: str
    risk_score: int = Field(ge=0, le=100)
    verdict: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "MALICIOUS"]
    reasons: List[CorrelationReason] = Field(default_factory=list)
    correlations: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=_utcnow)
    processing_time_ms: int = 0