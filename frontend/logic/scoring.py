from logic.rules import SecurityRules
from logic.models import AnalysisInput
from logic.config import get_config
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ScoreBreakdown:
    raw_score: int
    max_possible_score: int
    normalized_score: int
    capped_score: int
    triggered_rules_count: int
    total_rules_count: int
    category_scores: dict


class RiskScorer:
    @classmethod
    def _get_config(cls):
        return get_config()

    @classmethod
    def _get_max_possible_score(cls) -> int:
        cfg = cls._get_config()
        if cfg.scoring.max_possible_override is not None:
            return cfg.scoring.max_possible_override
        return sum(SecurityRules.get_rule_weights().values())

    @classmethod
    def _get_default_method(cls) -> str:
        return cls._get_config().scoring.method

    @classmethod
    def calculate(cls, analysis: AnalysisInput, method: Optional[str] = None) -> ScoreBreakdown:
        method = method or cls._get_default_method()

        triggered_rules = SecurityRules.get_triggered_rules(analysis)
        raw_score = sum(r.weight for r in triggered_rules)
        all_rules = SecurityRules.evaluate(analysis)

        max_possible = cls._get_max_possible_score()
        category_scores = cls._calculate_category_scores(triggered_rules)

        if method == "capped":
            normalized_score = min(raw_score, 100)
        elif method == "linear":
            normalized_score = int((raw_score / max_possible) * 100)
            normalized_score = min(normalized_score, 100)
        elif method == "sqrt":
            import math
            normalized_score = int(math.sqrt(raw_score / max_possible) * 100)
            normalized_score = min(normalized_score, 100)
        else:
            normalized_score = min(raw_score, 100)

        return ScoreBreakdown(
            raw_score=raw_score,
            max_possible_score=max_possible,
            normalized_score=normalized_score,
            capped_score=min(raw_score, 100),
            triggered_rules_count=len(triggered_rules),
            total_rules_count=len(all_rules),
            category_scores=category_scores
        )

    @classmethod
    def _calculate_category_scores(cls, triggered_rules: List) -> dict:
        categories = {
            "authentication": ["spf_fail", "dkim_fail", "dmarc_fail"],
            "sender_identity": ["sender_domain_mismatch", "reply_to_mismatch", "spoofing_indicator"],
            "headers": ["header_anomaly"],
            "threat_intel_ip": ["bad_ip_reputation"],
            "threat_intel_domain": ["bad_domain_reputation"],
            "threat_intel_url": ["bad_url_reputation"],
            "threat_intel_hash": ["malicious_hash_reputation"],
            "ai_phishing": ["high_phishing_probability"],
            "ai_bec": ["high_bec_probability"],
            "ai_social_eng": ["high_social_engineering_probability"],
            "ai_behavioral": ["urgency_detected", "credential_request_detected", "financial_request_detected"],
        }

        result = {}
        for category, rule_ids in categories.items():
            category_rules = [r for r in triggered_rules if r.rule_id in rule_ids]
            result[category] = {
                "score": sum(r.weight for r in category_rules),
                "triggered": len(category_rules),
                "total": len(rule_ids),
                "rules": [r.rule_id for r in category_rules]
            }

        return result

    @classmethod
    def get_risk_score(cls, analysis: AnalysisInput, method: Optional[str] = None) -> int:
        breakdown = cls.calculate(analysis, method)
        return breakdown.normalized_score

    @classmethod
    def get_breakdown(cls, analysis: AnalysisInput, method: Optional[str] = None) -> ScoreBreakdown:
        return cls.calculate(analysis, method)