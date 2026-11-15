import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { severityTone } from '../lib/severity';
import { humanizeToken } from '../lib/format';
import { Chip, Disclosure, Field, Meter } from './primitives';
export function ScoreBreakdownPanel({ breakdown }) {
    if (!breakdown)
        return null;
    const categories = Object.entries(breakdown.category_scores ?? {});
    // Bars are drawn relative to the biggest category in THIS response, so the
    // comparison is between categories rather than against an invented ceiling.
    const peak = categories.reduce((max, [, c]) => Math.max(max, c.score ?? 0), 0);
    const contributing = categories
        .filter(([, c]) => (c.score ?? 0) > 0)
        .sort((a, b) => (b[1].score ?? 0) - (a[1].score ?? 0));
    const quiet = categories.filter(([, c]) => (c.score ?? 0) === 0);
    return (_jsxs(Disclosure, { title: "Score breakdown", summary: `raw ${breakdown.raw_score} → ${breakdown.normalized_score}`, children: [_jsxs("div", { className: "grid gap-5 border-b border-line px-5 py-5 sm:grid-cols-4", children: [_jsx(Field, { label: "Raw score", value: String(breakdown.raw_score) }), _jsx(Field, { label: "Max possible", value: String(breakdown.max_possible) }), _jsx(Field, { label: "Normalized", value: String(breakdown.normalized_score) }), _jsx(Field, { label: "Method", value: breakdown.method })] }), _jsx("div", { className: "border-b border-line px-5 py-3", children: _jsxs("span", { className: "text-[12px] text-ink-3", children: [_jsx("span", { className: "datum tabular text-ink", children: breakdown.triggered_rules }), " of", ' ', _jsx("span", { className: "datum tabular text-ink", children: breakdown.total_rules }), " rules fired. Normalisation to a 0\u2013100 score was performed by the backend using the", ' ', _jsx("span", { className: "datum", children: breakdown.method }), " method."] }) }), contributing.length > 0 && (_jsxs("div", { className: "px-5 py-5", children: [_jsx("span", { className: "eyebrow", children: "Contributing categories" }), _jsx("ul", { className: "mt-3 space-y-4", children: contributing.map(([name, category]) => {
                            // Tone tracks how much of this response's weight sits here.
                            const share = peak > 0 ? category.score / peak : 0;
                            const tone = severityTone(share >= 0.75 ? 'critical' : share >= 0.5 ? 'high' : share >= 0.25 ? 'medium' : 'low');
                            return (_jsxs("li", { children: [_jsxs("div", { className: "flex items-baseline justify-between gap-3", children: [_jsx("span", { className: "font-display text-[12.5px] font-medium text-ink", children: humanizeToken(name) }), _jsxs("span", { className: "datum shrink-0 text-[12px] tabular text-ink-2", children: [category.score, _jsxs("span", { className: "text-ink-4", children: [' ', "\u00B7 ", category.triggered, "/", category.total, " rules"] })] })] }), _jsx(Meter, { value: category.score, max: peak, tone: tone, className: "mt-1.5" }), category.rules?.length > 0 && (_jsx("div", { className: "mt-2 flex flex-wrap gap-1.5", children: category.rules.map((rule) => (_jsx(Chip, { children: rule }, rule))) }))] }, name));
                        }) })] })), quiet.length > 0 && (_jsxs("div", { className: "border-t border-line px-5 py-4", children: [_jsx("span", { className: "eyebrow", children: "Scored zero" }), _jsx("div", { className: "mt-2 flex flex-wrap gap-1.5", children: quiet.map(([name]) => (_jsx(Chip, { children: humanizeToken(name) }, name))) })] })), categories.length === 0 && (_jsx("p", { className: "px-5 py-5 text-[12.5px] text-ink-3", children: "The response did not include category scores." }))] }));
}
