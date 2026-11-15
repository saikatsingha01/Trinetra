from dataclasses import dataclass
from typing import List, Optional
from logic.models import LogicOutput, CorrelationReason, Verdict
from logic.config import get_config


@dataclass
class VerdictThresholds:
    low_max: int = 25
    medium_max: int = 49
    high_max: int = 79
    critical_max: int = 100


def _default_thresholds() -> VerdictThresholds:
    cfg = get_config()
    vt = cfg.verdict_thresholds
    return VerdictThresholds(
        low_max=vt.low_max,
        medium_max=vt.medium_max,
        high_max=vt.high_max,
        critical_max=vt.critical_max,
    )


class VerdictEngine:
    def __init__(self, thresholds: Optional[VerdictThresholds] = None):
        self.thresholds = thresholds or _default_thresholds()

    def get_verdict(self, score: int) -> Verdict:
        if score <= self.thresholds.low_max:
            return "LOW"
        if score <= self.thresholds.medium_max:
            return "MEDIUM"
        if score <= self.thresholds.high_max:
            return "HIGH"
        if score <= self.thresholds.critical_max:
            return "CRITICAL"
        return "CRITICAL"

    def get_verdict_info(self, score: int) -> dict:
        verdict = self.get_verdict(score)
        return {
            "score": score,
            "verdict": verdict,
            "thresholds": {
                "LOW": f"1-{self.thresholds.low_max}",
                "MEDIUM": f"{self.thresholds.low_max + 1}-{self.thresholds.medium_max}",
                "HIGH": f"{self.thresholds.medium_max + 1}-{self.thresholds.high_max}",
                "CRITICAL": f"{self.thresholds.high_max + 1}-{self.thresholds.critical_max}",
                "MALICIOUS": "N/A"
            }
        }

    def create_output(
        self,
        case_id: str,
        score: int,
        reasons: List[str],
        correlations: List[str],
        processing_time_ms: int = 0
    ) -> LogicOutput:
        verdict = self.get_verdict(score)
        return LogicOutput(
            case_id=case_id,
            risk_score=score,
            verdict=verdict,
            reasons=[
                CorrelationReason(description=r, evidence_sources=[], severity="medium")
                for r in reasons
            ],
            correlations=correlations,
            processing_time_ms=processing_time_ms
        )

    @classmethod
    def get_all_verdicts(cls) -> List[str]:
        return ["LOW", "MEDIUM", "HIGH", "CRITICAL", "MALICIOUS"]