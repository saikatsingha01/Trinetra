import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/* ==========================================================================
   CasesTable — the analyst's list.
   --------------------------------------------------------------------------
   Columns follow the brief: Case ID, Sender, Subject, Risk Score, Verdict,
   Processing Time, Date, Action. Rows are shown in the order the backend
   returned them; sorting is a display choice offered on the Cases page.
   ========================================================================== */
import { Link } from 'react-router-dom';
import { verdictTone } from '../lib/severity';
import { formatDateTime, formatDuration, truncateEnd } from '../lib/format';
import { VerdictBadge } from './VerdictBadge';
import { IconArrowRight } from './icons';
export function CasesTable({ rows }) {
    return (_jsx("div", { className: "overflow-x-auto", children: _jsxs("table", { className: "w-full min-w-[860px] border-collapse text-left", children: [_jsx("thead", { children: _jsxs("tr", { className: "border-b border-line", children: [_jsx("th", { scope: "col", className: "eyebrow px-5 py-2.5 font-semibold", children: "Case ID" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 font-semibold", children: "Sender" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 font-semibold", children: "Subject" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 text-right font-semibold", children: "Risk" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 font-semibold", children: "Verdict" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 text-right font-semibold", children: "Time" }), _jsx("th", { scope: "col", className: "eyebrow px-3 py-2.5 font-semibold", children: "Date" }), _jsx("th", { scope: "col", className: "eyebrow px-5 py-2.5 text-right font-semibold", children: "Action" })] }) }), _jsx("tbody", { children: rows.map((row) => {
                        const tone = verdictTone(row.verdict);
                        return (_jsxs("tr", { className: "border-b border-line transition-colors last:border-b-0 hover:bg-raised/50", children: [_jsx("td", { className: "px-5 py-3", children: _jsx(Link, { to: `/cases/${encodeURIComponent(row.case_id)}`, className: "datum text-[12px] text-ink transition-colors hover:text-steel-hi", children: row.case_id }) }), _jsx("td", { className: "datum max-w-[190px] truncate px-3 py-3 text-[12px] text-ink-2", children: row.sender ?? '—' }), _jsx("td", { className: "max-w-[260px] px-3 py-3 text-[12.5px] text-ink-2", children: row.subject ? truncateEnd(row.subject, 64) : '—' }), _jsx("td", { className: "px-3 py-3 text-right", children: _jsx("span", { className: `datum text-[13px] font-semibold tabular ${tone.text}`, children: row.risk_score }) }), _jsx("td", { className: "px-3 py-3", children: _jsx(VerdictBadge, { verdict: row.verdict }) }), _jsx("td", { className: "datum px-3 py-3 text-right text-[11.5px] tabular text-ink-3", children: formatDuration(row.processing_time_ms) }), _jsx("td", { className: "datum px-3 py-3 text-[11.5px] text-ink-3", children: row.analyzed_at ? formatDateTime(row.analyzed_at) : '—' }), _jsx("td", { className: "px-5 py-3 text-right", children: _jsxs(Link, { to: `/cases/${encodeURIComponent(row.case_id)}`, className: "inline-flex items-center gap-1.5 font-display text-[11.5px] font-medium text-steel-hi transition-colors hover:text-ink", children: ["View report", _jsx(IconArrowRight, { size: 13 })] }) })] }, row.case_id));
                    }) })] }) }));
}
