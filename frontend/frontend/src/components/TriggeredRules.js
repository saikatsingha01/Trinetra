import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Disclosure, EmptyNote } from './primitives';
export function TriggeredRulesTable({ rules }) {
    if (!rules || rules.length === 0) {
        return (_jsx(Disclosure, { title: "Triggered rules", count: 0, children: _jsx(EmptyNote, { children: "No rules fired for this email." }) }));
    }
    const ordered = [...rules].sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0));
    return (_jsx(Disclosure, { title: "Triggered rules", count: rules.length, children: _jsx("div", { className: "overflow-x-auto", children: _jsxs("table", { className: "w-full border-collapse text-left", children: [_jsx("thead", { children: _jsxs("tr", { className: "border-b border-line", children: [_jsx("th", { scope: "col", className: "eyebrow px-5 py-2.5 font-semibold", children: "Rule" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 text-right font-semibold", children: "Weight" }), _jsx("th", { scope: "col", className: "eyebrow px-5 py-2.5 font-semibold", children: "Evidence" })] }) }), _jsx("tbody", { children: ordered.map((rule) => (_jsxs("tr", { className: "border-b border-line last:border-b-0", children: [_jsxs("td", { className: "px-5 py-3 align-top", children: [_jsx("div", { className: "datum text-[12px] text-ink", children: rule.rule_id }), _jsx("div", { className: "mt-0.5 text-[12.5px] leading-snug text-ink-2", children: rule.description })] }), _jsx("td", { className: "px-3 py-3 align-top text-right", children: _jsx("span", { className: "datum text-[13px] tabular text-ink", children: rule.weight }) }), _jsx("td", { className: "datum px-5 py-3 align-top text-[11.5px] leading-relaxed text-ink-3", children: rule.evidence || '—' })] }, rule.rule_id))) })] }) }) }));
}
