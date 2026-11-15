import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { SEVERITY_ORDER, severityTone } from '../lib/severity';
import { humanizeToken } from '../lib/format';
import { Badge, Chip, EmptyNote, Section } from './primitives';
export function DetectionReasons({ reasons }) {
    if (!reasons || reasons.length === 0) {
        return (_jsx(Section, { title: "Detection reasons", children: _jsx(EmptyNote, { children: "No detection reasons were returned." }) }));
    }
    // Group without reordering within a group, so the engine's own order survives.
    const groups = SEVERITY_ORDER.map((severity) => ({
        severity,
        items: reasons.filter((r) => (r.severity ?? '').toLowerCase() === severity),
    })).filter((g) => g.items.length > 0);
    const ungrouped = reasons.filter((r) => !SEVERITY_ORDER.includes((r.severity ?? '').toLowerCase()));
    return (_jsxs(Section, { title: "Detection reasons", count: reasons.length, caption: "Each reason names the analysis block that supplied its evidence.", children: [groups.map(({ severity, items }) => {
                const tone = severityTone(severity);
                return (_jsxs("div", { className: "border-b border-line last:border-b-0", children: [_jsxs("div", { className: "flex items-center gap-2.5 bg-inset px-5 py-2", children: [_jsx(Badge, { tone: tone, children: tone.label }), _jsx("span", { className: "datum text-[11px] tabular text-ink-4", children: items.length })] }), _jsx("ul", { children: items.map((reason, i) => (_jsxs("li", { className: "flex gap-3 border-b border-line px-5 py-3 last:border-b-0", children: [_jsx("span", { className: `mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full ${tone.solid}`, "aria-hidden": "true" }), _jsxs("div", { className: "min-w-0", children: [_jsx("p", { className: "text-[13px] leading-snug text-ink", children: reason.description }), reason.evidence_sources?.length > 0 && (_jsx("div", { className: "mt-1.5 flex flex-wrap gap-1.5", children: reason.evidence_sources.map((source) => (_jsx(Chip, { children: humanizeToken(source) }, source))) }))] })] }, `${severity}-${i}`))) })] }, severity));
            }), ungrouped.length > 0 && (_jsx("ul", { className: "border-t border-line", children: ungrouped.map((reason, i) => (_jsxs("li", { className: "border-b border-line px-5 py-3 last:border-b-0", children: [_jsx("p", { className: "text-[13px] leading-snug text-ink", children: reason.description }), _jsxs("span", { className: "datum mt-1 block text-[11px] text-ink-4", children: ["Unrecognised severity: ", reason.severity ?? '—'] })] }, `other-${i}`))) }))] }));
}
