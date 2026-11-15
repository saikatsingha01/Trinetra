import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { SEVERITY_ORDER, severityTone } from '../lib/severity';
import { pluralize } from '../lib/format';
export function ThreatSummary({ report }) {
    const counts = new Map();
    for (const reason of report.reasons ?? []) {
        const key = (reason.severity ?? '').toLowerCase();
        if (!SEVERITY_ORDER.includes(key))
            continue;
        counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const indicators = report.security_analysis?.suspicious_indicators?.length ?? 0;
    const present = SEVERITY_ORDER.filter((s) => (counts.get(s) ?? 0) > 0);
    if (present.length === 0 && indicators === 0) {
        return (_jsx("p", { className: "text-[12.5px] text-ink-3", children: "The engine returned no findings for this email." }));
    }
    return (_jsxs("div", { children: [_jsx("div", { className: "eyebrow", children: "Threat summary" }), _jsxs("ul", { className: "mt-2.5 flex flex-wrap items-center gap-x-5 gap-y-2", children: [present.map((severity) => {
                        const count = counts.get(severity) ?? 0;
                        const tone = severityTone(severity);
                        return (_jsxs("li", { className: "flex items-baseline gap-2", children: [_jsx("span", { className: `font-display text-[19px] font-semibold tabular ${tone.text}`, children: count }), _jsxs("span", { className: "text-[12.5px] text-ink-2", children: [tone.label, " ", pluralize(count, 'finding')] })] }, severity));
                    }), indicators > 0 && (_jsxs("li", { className: "flex items-baseline gap-2", children: [_jsx("span", { className: "font-display text-[19px] font-semibold tabular text-ink-2", children: indicators }), _jsxs("span", { className: "text-[12.5px] text-ink-2", children: ["suspicious ", pluralize(indicators, 'indicator')] })] }))] })] }));
}
