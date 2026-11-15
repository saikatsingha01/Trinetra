import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { SEVERITY_ORDER, severityTone } from '../lib/severity';
import { Badge, EmptyNote, Section } from './primitives';
function CorrelationItem({ text, tone }) {
    return (_jsxs("li", { className: "flex gap-3 border-b border-line px-5 py-3 last:border-b-0", children: [_jsx("span", { className: `mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full ${tone.solid}`, "aria-hidden": "true" }), _jsx("p", { className: "text-[13px] leading-snug text-ink", children: text })] }));
}
export function Correlations({ correlations, bySeverity, }) {
    const total = correlations?.length ?? 0;
    if (total === 0) {
        return (_jsx(Section, { title: "Correlations", children: _jsx(EmptyNote, { children: "The engine did not find any cross-signal correlations for this email." }) }));
    }
    const groups = bySeverity
        ? SEVERITY_ORDER.map((severity) => ({
            severity,
            items: bySeverity[severity] ?? [],
        })).filter((g) => g.items.length > 0)
        : [];
    return (_jsx(Section, { title: "Correlations", count: total, caption: "Findings that reinforce each other across separate analysis blocks.", children: groups.length > 0 ? (groups.map(({ severity, items }) => {
            const tone = severityTone(severity);
            return (_jsxs("div", { className: "border-b border-line last:border-b-0", children: [_jsxs("div", { className: "flex items-center gap-2.5 bg-inset px-5 py-2", children: [_jsx(Badge, { tone: tone, children: tone.label }), _jsx("span", { className: "datum text-[11px] tabular text-ink-4", children: items.length })] }), _jsx("ul", { children: items.map((text, i) => (_jsx(CorrelationItem, { text: text, tone: tone }, `${severity}-${i}`))) })] }, severity));
        })) : (_jsx("ul", { children: correlations.map((text, i) => (_jsx(CorrelationItem, { text: text, tone: severityTone(null) }, i))) })) }));
}
