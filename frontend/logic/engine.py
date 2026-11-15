import time
import logging
import asyncio
from typing import Optional, Literal
from logic.models import AnalysisInput, LogicOutput, CorrelationReason, Verdict
from logic.rules import SecurityRules, RuleResult
from logic.correlation import CorrelationEngine, CorrelationFinding
from logic.scoring import RiskScorer, ScoreBreakdown
from logic.verdict import VerdictEngine, VerdictThresholds
from logic.logging import get_logger, log_structured


logger = get_logger("logic.engine")


class LogicEngine:
    def __init__(
        self,
        verdict_thresholds: Optional[VerdictThresholds] = None,
        scoring_method: str = "capped"
    ):
        self.verdict_engine = VerdictEngine(verdict_thresholds)
        self.scoring_method = scoring_method
        self.correlation_engine = CorrelationEngine()
        self.rules_engine = SecurityRules()
        self.scorer = RiskScorer()

    def analyze(self, analysis: AnalysisInput) -> LogicOutput:
        start_time = time.perf_counter()
        case_id = analysis.case_id
        
        log_structured(logger, logging.INFO, "Starting analysis", case_id=case_id)

        # Step 1: Evaluate security rules
        triggered_rules = self.rules_engine.get_triggered_rules(analysis)
        log_structured(logger, logging.DEBUG, "Security rules evaluated", 
            case_id=case_id, triggered_count=len(triggered_rules),
            rule_ids=[r.rule_id for r in triggered_rules])

        # Step 2: Find correlations
        correlation_findings = self.correlation_engine.correlate(analysis)
        log_structured(logger, logging.DEBUG, "Correlations found",
            case_id=case_id, correlation_count=len(correlation_findings),
            correlation_ids=[f.rule_ids for f in correlation_findings])

        # Step 3: Calculate risk score
        score_breakdown = self.scorer.get_breakdown(analysis, self.scoring_method)
        risk_score = score_breakdown.normalized_score
        log_structured(logger, logging.INFO, "Risk score calculated",
            case_id=case_id, risk_score=risk_score, raw_score=score_breakdown.raw_score,
            method=self.scoring_method)

        # Step 4: Determine verdict
        verdict: Verdict = self.verdict_engine.get_verdict(risk_score)  # type: ignore[assignment]
        log_structured(logger, logging.INFO, "Verdict determined",
            case_id=case_id, verdict=verdict, risk_score=risk_score)

        # Step 5: Build reasons from triggered rules + correlations
        reasons = self._build_reasons(triggered_rules, correlation_findings)

        # Step 6: Build correlation descriptions
        correlations = [f.description for f in correlation_findings]

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)
        
        log_structured(logger, logging.INFO, "Analysis complete",
            case_id=case_id, processing_time_ms=processing_time_ms,
            risk_score=risk_score, verdict=verdict,
            reason_count=len(reasons), correlation_count=len(correlations))

        return LogicOutput(
            case_id=analysis.case_id,
            risk_score=risk_score,
            verdict=verdict,
            reasons=reasons,
            correlations=correlations,
            processing_time_ms=processing_time_ms
        )

    async def analyze_async(self, analysis: AnalysisInput) -> LogicOutput:
        """Async version of analyze() for high-throughput scenarios."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.analyze, analysis)

    def _build_reasons(
        self,
        triggered_rules: list[RuleResult],
        correlation_findings: list[CorrelationFinding]
    ) -> list[CorrelationReason]:
        reasons = []

        # Add triggered rules as reasons
        for rule in triggered_rules:
            if any(x in rule.rule_id for x in ["spf", "dkim", "dmarc", "sender", "reply_to", "header", "spoofing"]):
                sources = ["security_analysis"]
            elif any(x in rule.rule_id for x in ["ip_reputation", "domain_reputation", "url_reputation", "hash_reputation"]):
                sources = ["threat_intelligence"]
            else:
                sources = ["ai_assessment"]
            reasons.append(CorrelationReason(
                description=rule.description,
                evidence_sources=sources,
                severity=self._infer_severity(rule.weight)
            ))

        # Add correlation findings as reasons (higher-level explanations)
        for finding in correlation_findings:
            reasons.append(CorrelationReason(
                description=finding.description,
                evidence_sources=finding.evidence_sources,
                severity=finding.severity  # type: ignore[arg-type]
            ))

        return reasons

    def _infer_severity(self, weight: int) -> Literal["low", "medium", "high", "critical"]:
        if weight >= 20:
            return "critical"
        if weight >= 15:
            return "high"
        if weight >= 10:
            return "medium"
        return "low"

    def get_detailed_report(self, analysis: AnalysisInput) -> dict:
        output = self.analyze(analysis)
        score_breakdown = self.scorer.get_breakdown(analysis, self.scoring_method)
        verdict_info = self.verdict_engine.get_verdict_info(output.risk_score)
        correlations_by_severity = self.correlation_engine.get_correlations_by_severity(analysis)

        return {
            "case_id": output.case_id,
            "risk_score": output.risk_score,
            "verdict": output.verdict,
            "verdict_info": verdict_info,
            "reasons": [
                {
                    "description": r.description,
                    "evidence_sources": r.evidence_sources,
                    "severity": r.severity
                }
                for r in output.reasons
            ],
            "correlations": output.correlations,
            "correlations_by_severity": correlations_by_severity,
            "score_breakdown": {
                "raw_score": score_breakdown.raw_score,
                "max_possible": score_breakdown.max_possible_score,
                "normalized_score": score_breakdown.normalized_score,
                "method": self.scoring_method,
                "triggered_rules": score_breakdown.triggered_rules_count,
                "total_rules": score_breakdown.total_rules_count,
                "category_scores": score_breakdown.category_scores
            },
            "triggered_rules": [
                {
                    "rule_id": r.rule_id,
                    "description": r.description,
                    "weight": r.weight,
                    "evidence": r.evidence
                }
                for r in self.rules_engine.get_triggered_rules(analysis)
            ],
            "processing_time_ms": output.processing_time_ms
        }


def analyze_email(
    case_id: str,
    security_analysis: dict,
    threat_intelligence: dict,
    ai_assessment: dict,
    iocs: Optional[dict] = None,
    email_metadata: Optional[dict] = None,
    verdict_thresholds: Optional[VerdictThresholds] = None,
    scoring_method: str = "capped"
) -> LogicOutput:
    """
    Main entry point for the Logic Engine.
    
    Args:
        case_id: Unique case identifier
        security_analysis: Workflow 2 output (Subhom)
        threat_intelligence: Workflow 3 output (Subhom)
        ai_assessment: Ollama AI output (Saikat)
        iocs: Normalized IOCs from Workflow 1
        email_metadata: Basic email info
        verdict_thresholds: Custom verdict thresholds
        scoring_method: "capped", "linear", or "sqrt"
    
    Returns:
        LogicOutput with risk_score, verdict, reasons, correlations
    """
    from logic.models import (
        AnalysisInput, SecurityAnalysis, ThreatIntelligence,
        AIAssessment, IOCData, EmailMetadata
    )
    
    analysis = AnalysisInput(
        case_id=case_id,
        email=EmailMetadata(**email_metadata) if email_metadata else None,
        iocs=IOCData(**(iocs or {})),
        security_analysis=SecurityAnalysis(**security_analysis),
        threat_intelligence=ThreatIntelligence(**threat_intelligence),
        ai_assessment=AIAssessment(**ai_assessment)
    )
    
    engine = LogicEngine(verdict_thresholds, scoring_method)
    return engine.analyze(analysis)