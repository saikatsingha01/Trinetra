from logic.models import AnalysisInput, SecurityAnalysis, ThreatIntelligence, AIAssessment, IOCData
from typing import List, Tuple
from dataclasses import dataclass


@dataclass
class RuleResult:
    rule_id: str
    description: str
    weight: int
    triggered: bool
    evidence: str = ""


class SecurityRules:
    @classmethod
    def _get_config(cls):
        from logic.config import get_config
        return get_config()

    @classmethod
    def _get_rule_weights(cls) -> dict:
        cfg = cls._get_config()
        rw = cfg.rule_weights
        return {
            "spf_fail": rw.spf_fail,
            "dkim_fail": rw.dkim_fail,
            "dmarc_fail": rw.dmarc_fail,
            "sender_domain_mismatch": rw.sender_domain_mismatch,
            "reply_to_mismatch": rw.reply_to_mismatch,
            "header_anomaly": rw.header_anomaly,
            "spoofing_indicator": rw.spoofing_indicator,
            "bad_ip_reputation": rw.bad_ip_reputation,
            "bad_domain_reputation": rw.bad_domain_reputation,
            "bad_url_reputation": rw.bad_url_reputation,
            "malicious_hash_reputation": rw.malicious_hash_reputation,
            "high_phishing_probability": rw.high_phishing_probability,
            "high_bec_probability": rw.high_bec_probability,
            "high_social_engineering_probability": rw.high_social_engineering_probability,
            "urgency_detected": rw.urgency_detected,
            "credential_request_detected": rw.credential_request_detected,
            "financial_request_detected": rw.financial_request_detected,
        }

    @classmethod
    def _get_thresholds(cls) -> tuple:
        cfg = cls._get_config()
        th = cfg.thresholds
        return (
            th.reputation,
            th.phishing,
            th.bec,
            th.social_eng,
        )

    @classmethod
    def get_rule_weights(cls) -> dict:
        return cls._get_rule_weights()

    @classmethod
    def get_reputation_threshold(cls) -> int:
        return cls._get_thresholds()[0]

    @classmethod
    def get_phishing_threshold(cls) -> float:
        return cls._get_thresholds()[1]

    @classmethod
    def get_bec_threshold(cls) -> float:
        return cls._get_thresholds()[2]

    @classmethod
    def get_social_eng_threshold(cls) -> float:
        return cls._get_thresholds()[3]

    # Backward compatibility - use class methods instead of properties
    @property
    def RULE_WEIGHTS(self):
        return self.get_rule_weights()

    @property
    def REPUTATION_THRESHOLD(self):
        return self.get_reputation_threshold()

    @property
    def PHISHING_THRESHOLD(self):
        return self.get_phishing_threshold()

    @property
    def BEC_THRESHOLD(self):
        return self.get_bec_threshold()

    @property
    def SOCIAL_ENG_THRESHOLD(self):
        return self.get_social_eng_threshold()

    @classmethod
    def evaluate(cls, analysis: AnalysisInput) -> List[RuleResult]:
        results = []

        results.extend(cls._evaluate_security_analysis(analysis.security_analysis))
        results.extend(cls._evaluate_threat_intelligence(analysis.threat_intelligence))
        results.extend(cls._evaluate_ai_assessment(analysis.ai_assessment))

        return results

    @classmethod
    def _evaluate_security_analysis(cls, sec: SecurityAnalysis) -> List[RuleResult]:
        results = []

        # SPF
        spf_fail = sec.spf.result == "fail"
        weights = cls.get_rule_weights()
        results.append(RuleResult(
            rule_id="spf_fail",
            description="SPF authentication failed",
            weight=weights["spf_fail"],
            triggered=spf_fail,
            evidence=f"SPF result: {sec.spf.result}" if spf_fail else ""
        ))

        # DKIM
        dkim_fail = sec.dkim.result == "fail"
        results.append(RuleResult(
            rule_id="dkim_fail",
            description="DKIM authentication failed",
            weight=weights["dkim_fail"],
            triggered=dkim_fail,
            evidence=f"DKIM result: {sec.dkim.result}" if dkim_fail else ""
        ))

        # DMARC
        dmarc_fail = sec.dmarc.result == "fail"
        results.append(RuleResult(
            rule_id="dmarc_fail",
            description="DMARC authentication failed",
            weight=weights["dmarc_fail"],
            triggered=dmarc_fail,
            evidence=f"DMARC result: {sec.dmarc.result}, alignment: {sec.dmarc.alignment}" if dmarc_fail else ""
        ))

        # Sender domain consistency
        sender_mismatch = False
        reply_to_mismatch = False
        sender_evidence = ""
        reply_to_evidence = ""
        if sec.sender_identity:
            sender_mismatch = not sec.sender_identity.domain_consistent
            reply_to_mismatch = bool(
                sec.sender_identity.reply_to and
                sec.sender_identity.from_address and
                sec.sender_identity.reply_to.split('@')[-1] != sec.sender_identity.from_address.split('@')[-1]
            )
            if sender_mismatch:
                sender_evidence = f"From: {sec.sender_identity.from_address}, Return-Path: {sec.sender_identity.return_path}"
            if reply_to_mismatch:
                reply_to_evidence = f"Reply-To: {sec.sender_identity.reply_to}, From: {sec.sender_identity.from_address}"

        results.append(RuleResult(
            rule_id="sender_domain_mismatch",
            description="Sender domain inconsistent (From vs Return-Path)",
            weight=weights["sender_domain_mismatch"],
            triggered=sender_mismatch,
            evidence=sender_evidence
        ))

        results.append(RuleResult(
            rule_id="reply_to_mismatch",
            description="Reply-To domain differs from From domain",
            weight=weights["reply_to_mismatch"],
            triggered=reply_to_mismatch,
            evidence=reply_to_evidence
        ))

        # Header anomaly
        header_anomaly = sec.header_analysis.relay_anomaly
        results.append(RuleResult(
            rule_id="header_anomaly",
            description="Suspicious header anomalies detected",
            weight=weights["header_anomaly"],
            triggered=header_anomaly,
            evidence=f"IP hops: {sec.header_analysis.ip_hops}, suspicious headers: {len(sec.header_analysis.suspicious_headers)}" if header_anomaly else ""
        ))

        # Spoofing indicator
        spoofing = "spoofing" in sec.suspicious_indicators
        results.append(RuleResult(
            rule_id="spoofing_indicator",
            description="Spoofing indicator detected",
            weight=weights["spoofing_indicator"],
            triggered=spoofing,
            evidence="spoofing in suspicious_indicators" if spoofing else ""
        ))

        return results

    @classmethod
    def _evaluate_threat_intelligence(cls, ti: ThreatIntelligence) -> List[RuleResult]:
        results = []
        weights = cls.get_rule_weights()
        rep_threshold = cls.get_reputation_threshold()

        # IP reputation
        bad_ips = [ip for ip in ti.ips if ip.reputation_score >= rep_threshold]
        results.append(RuleResult(
            rule_id="bad_ip_reputation",
            description=f"Malicious IP reputation ({len(bad_ips)} IPs)",
            weight=weights["bad_ip_reputation"],
            triggered=len(bad_ips) > 0,
            evidence=", ".join([f"{ip.ip} (score: {ip.reputation_score})" for ip in bad_ips]) if bad_ips else ""
        ))

        # Domain reputation
        bad_domains = [d for d in ti.domains if d.reputation_score >= rep_threshold]
        results.append(RuleResult(
            rule_id="bad_domain_reputation",
            description=f"Malicious domain reputation ({len(bad_domains)} domains)",
            weight=weights["bad_domain_reputation"],
            triggered=len(bad_domains) > 0,
            evidence=", ".join([f"{d.domain} (score: {d.reputation_score})" for d in bad_domains]) if bad_domains else ""
        ))

        # URL reputation
        bad_urls = [u for u in ti.urls if u.reputation_score >= rep_threshold]
        results.append(RuleResult(
            rule_id="bad_url_reputation",
            description=f"Malicious URL reputation ({len(bad_urls)} URLs)",
            weight=weights["bad_url_reputation"],
            triggered=len(bad_urls) > 0,
            evidence=", ".join([f"{u.url} (score: {u.reputation_score})" for u in bad_urls]) if bad_urls else ""
        ))

        # Hash reputation
        bad_hashes = [h for h in ti.hashes if h.reputation_score >= rep_threshold]
        results.append(RuleResult(
            rule_id="malicious_hash_reputation",
            description=f"Malicious file hash reputation ({len(bad_hashes)} hashes)",
            weight=weights["malicious_hash_reputation"],
            triggered=len(bad_hashes) > 0,
            evidence=", ".join([f"{h.hash} ({h.hash_type}, score: {h.reputation_score})" for h in bad_hashes]) if bad_hashes else ""
        ))

        return results

    @classmethod
    def _evaluate_ai_assessment(cls, ai: AIAssessment) -> List[RuleResult]:
        results = []
        weights = cls.get_rule_weights()
        phishing_threshold = cls.get_phishing_threshold()
        bec_threshold = cls.get_bec_threshold()
        social_eng_threshold = cls.get_social_eng_threshold()

        # High phishing probability
        high_phishing = ai.phishing_probability >= phishing_threshold
        results.append(RuleResult(
            rule_id="high_phishing_probability",
            description=f"High phishing probability ({ai.phishing_probability:.0%})",
            weight=weights["high_phishing_probability"],
            triggered=high_phishing,
            evidence=f"phishing_probability={ai.phishing_probability:.2f}" if high_phishing else ""
        ))

        # High BEC probability
        high_bec = ai.bec_probability >= bec_threshold
        results.append(RuleResult(
            rule_id="high_bec_probability",
            description=f"High BEC probability ({ai.bec_probability:.0%})",
            weight=weights["high_bec_probability"],
            triggered=high_bec,
            evidence=f"bec_probability={ai.bec_probability:.2f}" if high_bec else ""
        ))

        # High social engineering probability
        high_soceng = ai.social_engineering_probability >= social_eng_threshold
        results.append(RuleResult(
            rule_id="high_social_engineering_probability",
            description=f"High social engineering probability ({ai.social_engineering_probability:.0%})",
            weight=weights["high_social_engineering_probability"],
            triggered=high_soceng,
            evidence=f"social_engineering_probability={ai.social_engineering_probability:.2f}" if high_soceng else ""
        ))

        # Urgency detected
        results.append(RuleResult(
            rule_id="urgency_detected",
            description="Urgency language detected",
            weight=weights["urgency_detected"],
            triggered=ai.urgency_detected,
            evidence="urgency_detected=true" if ai.urgency_detected else ""
        ))

        # Credential request detected
        results.append(RuleResult(
            rule_id="credential_request_detected",
            description="Credential harvesting request detected",
            weight=weights["credential_request_detected"],
            triggered=ai.credential_request_detected,
            evidence="credential_request_detected=true" if ai.credential_request_detected else ""
        ))

        # Financial request detected
        results.append(RuleResult(
            rule_id="financial_request_detected",
            description="Financial request detected",
            weight=weights["financial_request_detected"],
            triggered=ai.financial_request_detected,
            evidence="financial_request_detected=true" if ai.financial_request_detected else ""
        ))

        return results

    @classmethod
    def get_triggered_rules(cls, analysis: AnalysisInput) -> List[RuleResult]:
        all_results = cls.evaluate(analysis)
        return [r for r in all_results if r.triggered]

    @classmethod
    def calculate_raw_score(cls, analysis: AnalysisInput) -> int:
        triggered = cls.get_triggered_rules(analysis)
        return sum(r.weight for r in triggered)