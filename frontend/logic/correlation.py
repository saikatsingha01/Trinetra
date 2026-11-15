from logic.models import AnalysisInput, SecurityAnalysis, ThreatIntelligence, AIAssessment
from typing import List, Literal
from dataclasses import dataclass
from logic.config import get_config


@dataclass
class CorrelationFinding:
    description: str
    evidence_sources: List[str]
    severity: Literal["low", "medium", "high", "critical"]
    rule_ids: List[str]


class CorrelationEngine:
    @classmethod
    def _get_config(cls):
        return get_config()

    @classmethod
    def _get_thresholds(cls):
        return cls._get_config().thresholds

    @classmethod
    def get_reputation_high(cls) -> int:
        return cls._get_thresholds().reputation_high

    @classmethod
    def get_reputation_medium(cls) -> int:
        return cls._get_thresholds().reputation_medium

    @classmethod
    def get_phishing_high(cls) -> float:
        return cls._get_thresholds().phishing_high

    @classmethod
    def get_phishing_medium(cls) -> float:
        return cls._get_thresholds().phishing_medium

    @classmethod
    def get_bec_high(cls) -> float:
        return cls._get_thresholds().bec_high

    @classmethod
    def get_social_eng_high(cls) -> float:
        return cls._get_thresholds().social_eng_high

    @classmethod
    def get_auth_fail_count_threshold(cls) -> int:
        return cls._get_thresholds().auth_fail_count

    @classmethod
    def correlate(cls, analysis: AnalysisInput) -> List[CorrelationFinding]:
        findings = []
        sec = analysis.security_analysis
        intel = analysis.threat_intelligence
        ai = analysis.ai_assessment

        # Authentication failures correlation
        auth_failures = cls._count_auth_failures(sec)
        if auth_failures >= cls.get_auth_fail_count_threshold():
            failed_auth_rules = []
            if sec.spf.result == "fail":
                failed_auth_rules.append("spf_fail")
            if sec.dkim.result == "fail":
                failed_auth_rules.append("dkim_fail")
            if sec.dmarc.result == "fail":
                failed_auth_rules.append("dmarc_fail")
            findings.append(CorrelationFinding(
                description="Multiple email authentication failures indicate spoofing attempt",
                evidence_sources=["security_analysis"],
                severity="high",
                rule_ids=failed_auth_rules
            ))

        # DMARC fail + sender mismatch
        if sec.dmarc.result == "fail" and sec.sender_identity and not sec.sender_identity.domain_consistent:
            findings.append(CorrelationFinding(
                description="DMARC failure correlated with sender identity mismatch (From vs Return-Path)",
                evidence_sources=["security_analysis"],
                severity="high",
                rule_ids=["dmarc_fail", "sender_domain_mismatch"]
            ))

        # SPF fail + DKIM pass + DMARC fail (classic spoofing pattern)
        if sec.spf.result == "fail" and sec.dkim.result == "pass" and sec.dmarc.result == "fail":
            findings.append(CorrelationFinding(
                description="SPF fail with DKIM pass but DMARC fail suggests domain spoofing with valid DKIM",
                evidence_sources=["security_analysis"],
                severity="critical",
                rule_ids=["spf_fail", "dkim_fail", "dmarc_fail"]
            ))

        # Header anomaly + spoofing indicator
        if sec.header_analysis.relay_anomaly and "spoofing" in sec.suspicious_indicators:
            findings.append(CorrelationFinding(
                description="Header relay anomaly correlated with spoofing indicator",
                evidence_sources=["security_analysis"],
                severity="high",
                rule_ids=["header_anomaly", "spoofing_indicator"]
            ))

        # High-risk IP + phishing probability
        high_risk_ips = [ip for ip in intel.ips if ip.reputation_score >= cls.get_reputation_high()]
        if high_risk_ips and ai.phishing_probability >= cls.get_phishing_high():
            findings.append(CorrelationFinding(
                description=f"High-risk IP infrastructure ({len(high_risk_ips)} IPs) correlated with strong phishing language",
                evidence_sources=["threat_intelligence", "ai_assessment"],
                severity="critical",
                rule_ids=["bad_ip_reputation", "high_phishing_probability"]
            ))

        # High-risk domain + phishing probability
        high_risk_domains = [d for d in intel.domains if d.reputation_score >= cls.get_reputation_high()]
        if high_risk_domains and ai.phishing_probability >= cls.get_phishing_high():
            findings.append(CorrelationFinding(
                description=f"High-risk domain ({len(high_risk_domains)} domains) correlated with strong phishing indicators",
                evidence_sources=["threat_intelligence", "ai_assessment"],
                severity="critical",
                rule_ids=["bad_domain_reputation", "high_phishing_probability"]
            ))

        # High-risk URL + credential request
        high_risk_urls = [u for u in intel.urls if u.reputation_score >= cls.get_reputation_high()]
        if high_risk_urls and ai.credential_request_detected:
            findings.append(CorrelationFinding(
                description=f"Malicious URLs ({len(high_risk_urls)}) correlated with credential harvesting request",
                evidence_sources=["threat_intelligence", "ai_assessment"],
                severity="critical",
                rule_ids=["bad_url_reputation", "credential_request_detected"]
            ))

        # Sender mismatch + threat intel on reply-to domain
        if sec.sender_identity and sec.sender_identity.reply_to:
            reply_domain = sec.sender_identity.reply_to.split('@')[-1]
            bad_reply_domain = next(
                (d for d in intel.domains if d.domain == reply_domain and d.reputation_score >= cls.get_reputation_medium()),
                None
            )
            if bad_reply_domain:
                findings.append(CorrelationFinding(
                    description=f"Reply-To domain ({reply_domain}) has malicious reputation",
                    evidence_sources=["security_analysis", "threat_intelligence"],
                    severity="high",
                    rule_ids=["reply_to_mismatch", "bad_domain_reputation"]
                ))

        # Header anomaly + social engineering
        if sec.header_analysis.relay_anomaly and ai.social_engineering_probability >= cls.get_social_eng_high():
            findings.append(CorrelationFinding(
                description="Header relay anomaly correlated with strong social engineering language",
                evidence_sources=["security_analysis", "ai_assessment"],
                severity="high",
                rule_ids=["header_anomaly", "high_social_engineering_probability"]
            ))

        # BEC probability + financial request + sender mismatch
        if ai.bec_probability >= cls.get_bec_high() and ai.financial_request_detected and sec.sender_identity and not sec.sender_identity.domain_consistent:
            findings.append(CorrelationFinding(
                description="High BEC probability with financial request and sender identity mismatch",
                evidence_sources=["security_analysis", "ai_assessment"],
                severity="critical",
                rule_ids=["sender_domain_mismatch", "high_bec_probability", "financial_request_detected"]
            ))

        # Urgency + credential request + phishing probability
        if ai.urgency_detected and ai.credential_request_detected and ai.phishing_probability >= cls.get_phishing_medium():
            findings.append(CorrelationFinding(
                description="Urgency tactics combined with credential requests and phishing language",
                evidence_sources=["ai_assessment"],
                severity="high",
                rule_ids=["urgency_detected", "credential_request_detected", "high_phishing_probability"]
            ))

        # Multiple threat intel categories overlapping
        all_categories = set()
        for ip in intel.ips:
            all_categories.update(ip.categories)
        for d in intel.domains:
            all_categories.update(d.categories)
        for u in intel.urls:
            all_categories.update(u.categories)

        if "phishing" in all_categories and "credential_harvesting" in all_categories:
            findings.append(CorrelationFinding(
                description="Threat intelligence shows both phishing and credential harvesting campaigns",
                evidence_sources=["threat_intelligence"],
                severity="high",
                rule_ids=["bad_ip_reputation", "bad_domain_reputation", "bad_url_reputation"]
            ))

        # Geo-location anomaly (high-risk country)
        high_risk_countries = {"RU", "CN", "KP", "IR", "BY"}
        suspicious_countries = set()
        for ip in intel.ips:
            if ip.country in high_risk_countries:
                suspicious_countries.add(ip.country)
        for d in intel.domains:
            if d.country in high_risk_countries:
                suspicious_countries.add(d.country)

        if suspicious_countries:
            findings.append(CorrelationFinding(
                description=f"Infrastructure hosted in high-risk countries: {', '.join(sorted(suspicious_countries))}",
                evidence_sources=["threat_intelligence"],
                severity="medium",
                rule_ids=["bad_ip_reputation", "bad_domain_reputation"]
            ))

        # Recent domain registration + phishing
        from datetime import datetime, timedelta, timezone
        recent_domains = []
        now = datetime.now(timezone.utc)
        for d in intel.domains:
            if d.creation_date:
                try:
                    created = datetime.fromisoformat(d.creation_date.replace('Z', '+00:00'))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if now - created < timedelta(days=30):
                        recent_domains.append(d.domain)
                except Exception:
                    pass

        if recent_domains and ai.phishing_probability >= cls.get_phishing_medium():
            findings.append(CorrelationFinding(
                description=f"Recently registered domains ({', '.join(recent_domains)}) correlated with phishing language",
                evidence_sources=["threat_intelligence", "ai_assessment"],
                severity="high",
                rule_ids=["bad_domain_reputation", "high_phishing_probability"]
            ))

        return findings

    @classmethod
    def _count_auth_failures(cls, sec: SecurityAnalysis) -> int:
        count = 0
        if sec.spf.result == "fail":
            count += 1
        if sec.dkim.result == "fail":
            count += 1
        if sec.dmarc.result == "fail":
            count += 1
        return count

    @classmethod
    def get_correlation_descriptions(cls, analysis: AnalysisInput) -> List[str]:
        findings = cls.correlate(analysis)
        return [f.description for f in findings]

    @classmethod
    def get_correlations_by_severity(cls, analysis: AnalysisInput) -> dict[str, list[str]]:
        findings = cls.correlate(analysis)
        result: dict[str, list[str]] = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            result[f.severity].append(f.description)
        return result