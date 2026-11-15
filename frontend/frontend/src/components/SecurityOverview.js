import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { verdictTone } from '../lib/severity';
import { ThreatSummary } from './ThreatSummary';
import { formatDateTime, formatDuration } from '../lib/format';
import { IconClock } from './icons';
import { VerdictDisplay } from './VerdictBadge';
function Stat({ label, value, detail }) {
    return (_jsxs("div", { className: "result-stat", children: [_jsx("span", { children: label }), _jsx("strong", { children: value }), _jsx("small", { children: detail })] }));
}
export function SecurityOverview({ report }) {
    const tone = verdictTone(report.verdict);
    const score = Math.max(0, Math.min(100, Number(report.risk_score) || 0));
    const radius = 58;
    const circumference = 2 * Math.PI * radius;
    const dash = (score / 100) * circumference;
    const ipCount = report.threat_intelligence?.ips?.length ?? 0;
    const urlCount = report.threat_intelligence?.urls?.length ?? 0;
    const domainCount = report.threat_intelligence?.domains?.length ?? 0;
    const hashCount = report.threat_intelligence?.hashes?.length ?? 0;
    const confidence = report.analysis_confidence;
    const confidenceDefinitions = {
        evidence_coverage: 'How much of the expected email and security evidence was available.',
        signal_agreement: 'Whether independent signals support the same conclusion rather than contradicting each other.',
        provider_coverage: 'How much useful external reputation or enrichment evidence was available for indicators.',
        authentication_consistency: 'How consistently SPF, DKIM, DMARC and related authentication evidence agree.',
        grounding_quality: 'How well the AI assessment, when available, is tied back to collected evidence.',
        verdict_stability: 'How far the risk score is from a verdict boundary; near-boundary scores are less stable.',
        ai_availability: 'Whether the independent Ollama assessment was successfully incorporated.',
    };
    return (_jsxs("section", { className: "result-overview", children: [
        _jsxs("div", { className: "result-overview__topline", children: [
            _jsxs("div", { children: [_jsx("div", { className: "eyebrow", children: "THREAT ASSESSMENT / COMPLETED" }), _jsx("h1", { children: "Security assessment" }), _jsx("p", { children: report.email?.subject || report.source_file?.filename || 'Analyzed email message' })] }),
            _jsxs("div", { className: "result-overview__meta", children: [report.analyzed_at && _jsx("span", { children: formatDateTime(report.analyzed_at) }), _jsxs("span", { children: [_jsx(IconClock, { size: 13 }), " ", formatDuration(report.processing_time_ms)] })] })
        ] }),
        _jsxs("div", { className: "result-overview__grid", children: [
            _jsxs("div", { className: `result-verdict-card ${tone.border}`, children: [_jsx("div", { className: "result-verdict-card__label", children: "FINAL VERDICT" }), _jsx("div", { className: "result-verdict-card__value", children: _jsx(VerdictDisplay, { verdict: report.verdict }) }), _jsx("p", { children: "The verdict and score below are the values returned by the connected analysis engine." }), _jsxs("div", { className: "result-verdict-card__case", children: [_jsx("span", { children: "CASE" }), _jsx("strong", { children: report.case_id })] }), _jsx("div", { className: "result-verdict-card__summary", children: _jsx(ThreatSummary, { report: report }) })] }),
            _jsxs("div", { className: "result-score-card result-score-card--split", children: [
                _jsxs("div", { className: "result-metric-box result-metric-box--risk", children: [_jsx("div", { className: "result-score-card__label", children: "RISK SCORE" }), _jsxs("div", { className: "result-score-card__copy", children: [_jsx("span", { children: score }), _jsx("small", { children: "/ 100" })] }), _jsxs("div", { className: "result-score-ring", "aria-label": `Risk score ${score} out of 100`, children: [_jsxs("svg", { viewBox: "0 0 140 140", "aria-hidden": "true", children: [_jsx("circle", { className: "result-score-ring__track", cx: "70", cy: "70", r: radius }), _jsx("circle", { className: "result-score-ring__value", cx: "70", cy: "70", r: radius, strokeDasharray: `${dash} ${circumference - dash}` })] }), _jsxs("div", { className: "result-score-ring__center", children: [_jsx("strong", { children: score }), _jsx("span", { children: "RISK" })] })] }), _jsx("p", { className: "result-risk-description", children: "The risk score measures the severity of security and threat signals detected in this email. Higher values indicate stronger evidence of risk." })] }),
                _jsxs("div", { className: "result-metric-box result-metric-box--confidence", children: [_jsxs("div", { className: "result-confidence__head", children: [_jsxs("div", { children: [_jsx("div", { className: "result-score-card__label", children: "ANALYSIS CONFIDENCE" }), _jsx("strong", { children: confidence ? `${confidence.score}%` : '—' })] }), _jsx("span", { className: "result-confidence__label", children: confidence?.label ?? 'Not available' })] }), _jsx("div", { className: "result-confidence__bar", children: _jsx("span", { style: { width: `${Math.max(0, Math.min(100, confidence?.score ?? 0))}%` } }) }), _jsxs("div", { className: "result-confidence__reason-box", children: [_jsx("div", { className: "result-confidence__reason-title", children: "WHY THIS CONFIDENCE SCORE?" }), _jsxs("p", { className: "result-confidence__explanation", children: ["Confidence tells you how strongly the available evidence supports the risk decision. It is ", _jsx("strong", { children: "not" }), " the probability that the email is safe or malicious. It reflects evidence coverage, agreement between independent signals, provider coverage, authentication consistency, grounding quality, verdict stability, and AI availability.", report.analysis_mode === 'subhom_only' ? ' Ollama AI assessment failed, so the independent AI signal is missing; confidence is intentionally lower. Re-upload the email for a more precise result.' : ''] })] }), confidence && (_jsx("div", { className: "result-confidence__factors", children: Object.entries(confidence.factors).map(([key, value]) => (_jsxs("div", { children: [_jsx("span", { children: key.replace(/_/g, ' ') }), _jsxs("strong", { children: [value, "%"] }), _jsx("small", { children: confidenceDefinitions[key] ?? 'Evidence quality factor used by the confidence model.' })] }, key))) })), confidence?.rationale?.length ? (_jsx("ul", { className: "result-confidence__rationale", children: confidence.rationale.map((reason) => _jsx("li", { children: reason }, reason)) })) : null] })
            ] }),
            _jsxs("div", { className: "result-stat-grid", children: [_jsx(Stat, { label: "INDICATORS", value: String(ipCount + domainCount + urlCount + hashCount), detail: "IPs / domains / URLs / hashes" }), _jsx(Stat, { label: "RULES", value: String(report.triggered_rules?.length ?? 0), detail: "Triggered by engine" }), _jsx(Stat, { label: "CORRELATIONS", value: String(report.correlations?.length ?? 0), detail: "Cross-signal findings" }), _jsx(Stat, { label: "PROCESSING", value: formatDuration(report.processing_time_ms), detail: "Engine processing time" })] })
        ] })
    ] }));
}
