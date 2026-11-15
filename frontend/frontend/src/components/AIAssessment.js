import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { flagTone, severityTone } from '../lib/severity';
import { formatProbability, humanizeToken } from '../lib/format';
import { Badge, Chip, EmptyNote, Meter, Section } from './primitives';
/* Mirrors logic/rules.py thresholds. Display banding only. */
const THRESHOLDS = {
    phishing: 0.7,
    bec: 0.6,
    social_engineering: 0.7,
};
function probabilityTone(value, threshold) {
    if (value >= threshold)
        return severityTone(value >= 0.85 ? 'critical' : 'high');
    if (value >= threshold * 0.7)
        return severityTone('medium');
    return severityTone('low');
}
function ProbabilityRow({ label, value, threshold, }) {
    const tone = probabilityTone(value, threshold);
    const over = value >= threshold;
    return (_jsxs("div", { children: [_jsxs("div", { className: "flex items-baseline justify-between gap-3", children: [_jsx("span", { className: "font-display text-[12.5px] font-medium text-ink", children: label }), _jsx("span", { className: `datum text-[13px] tabular ${tone.text}`, children: formatProbability(value) })] }), _jsx(Meter, { value: value, max: 1, tone: tone, className: "mt-1.5" }), _jsxs("div", { className: "mt-1.5 text-[11px] text-ink-4", children: ["Backend threshold ", formatProbability(threshold), over ? ' — exceeded' : ' — not exceeded'] })] }));
}
export function AIAssessmentPanel({ data }) {
    if (!data) {
        return (_jsx(Section, { title: "AI assessment", children: _jsx(EmptyNote, { children: "The response did not include an AI assessment." }) }));
    }
    const flags = [
        { label: 'Urgency', value: data.urgency_detected },
        { label: 'Credential request', value: data.credential_request_detected },
        { label: 'Financial request', value: data.financial_request_detected },
    ];
    const modelInfo = data.model_info
        ? Object.entries(data.model_info).filter(([, v]) => v !== null && v !== undefined)
        : [];
    return (_jsxs(Section, { title: "AI assessment", children: [_jsxs("div", { className: "grid gap-6 px-5 py-5 sm:grid-cols-3", children: [_jsx(ProbabilityRow, { label: "Phishing", value: data.phishing_probability, threshold: THRESHOLDS.phishing }), _jsx(ProbabilityRow, { label: "BEC", value: data.bec_probability, threshold: THRESHOLDS.bec }), _jsx(ProbabilityRow, { label: "Social engineering", value: data.social_engineering_probability, threshold: THRESHOLDS.social_engineering })] }), _jsxs("div", { className: "border-t border-line px-5 py-5", children: [_jsx("span", { className: "eyebrow", children: "Detected behaviour" }), _jsx("div", { className: "mt-2.5 flex flex-wrap gap-2", children: flags.map((flag) => {
                            const tone = flagTone(flag.value);
                            return (_jsxs(Badge, { tone: tone, children: [flag.label, _jsx("span", { className: flag.value ? '' : 'text-ink-4', children: flag.value ? 'yes' : 'no' })] }, flag.label));
                        }) })] }), (data.detected_patterns.length > 0 || data.suspicious_language.length > 0) && (_jsxs("div", { className: "grid gap-5 border-t border-line px-5 py-5 sm:grid-cols-2", children: [data.detected_patterns.length > 0 && (_jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "Patterns" }), _jsx("div", { className: "mt-2.5 flex flex-wrap gap-1.5", children: data.detected_patterns.map((pattern) => (_jsx(Chip, { children: humanizeToken(pattern) }, pattern))) })] })), data.suspicious_language.length > 0 && (_jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "Suspicious language" }), _jsx("ul", { className: "mt-2.5 space-y-1.5", children: data.suspicious_language.map((phrase) => (_jsxs("li", { className: "border-l-2 border-line-strong pl-2.5 text-[12.5px] italic text-ink-2", children: ["\u201C", phrase, "\u201D"] }, phrase))) })] }))] })), data.explanation && (_jsxs("div", { className: "border-t border-line px-5 py-5", children: [_jsx("span", { className: "eyebrow", children: "Model explanation" }), _jsx("p", { className: "mt-2 max-w-[68ch] text-[13px] leading-relaxed text-ink-2", children: data.explanation })] })), modelInfo.length > 0 && (_jsx("div", { className: "flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-line px-5 py-3", children: modelInfo.map(([key, value]) => (_jsxs("span", { className: "datum text-[11px] text-ink-4", children: [_jsxs("span", { className: "text-ink-3", children: [humanizeToken(key), ":"] }), " ", String(value)] }, key))) })), modelInfo.length === 0 && (_jsx("div", { className: "border-t border-line px-5 py-3", children: _jsx("span", { className: "datum text-[11px] text-ink-4", children: "The model that produced this assessment was not identified in the response." }) }))] }));
}
