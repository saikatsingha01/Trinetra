import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
/* ==========================================================================
   Cases — analyses completed during this browser session.
   ========================================================================== */
import { useMemo, useState } from 'react';
import { VERDICTS } from '../types/analysis';
import { Header } from '../components/Header';
import { CasesTable } from '../components/CasesTable';
import { Badge, Panel, Section } from '../components/primitives';
import { IconSearch } from '../components/icons';
import { verdictTone } from '../lib/severity';
import { useSession } from '../store/session';
const SORTS = [
    { key: 'date', label: 'Newest' },
    { key: 'risk', label: 'Highest risk' },
    { key: 'time', label: 'Slowest' },
];
export function Cases() {
    const { cases } = useSession();
    const [query, setQuery] = useState('');
    const [verdicts, setVerdicts] = useState(new Set());
    const [sort, setSort] = useState('date');
    const rows = useMemo(() => {
        const needle = query.trim().toLowerCase();
        const filtered = cases.filter((row) => {
            if (verdicts.size > 0 && !verdicts.has(row.verdict))
                return false;
            if (!needle)
                return true;
            return (row.case_id.toLowerCase().includes(needle) ||
                (row.sender ?? '').toLowerCase().includes(needle) ||
                (row.subject ?? '').toLowerCase().includes(needle));
        });
        return [...filtered].sort((a, b) => {
            if (sort === 'risk')
                return b.risk_score - a.risk_score;
            if (sort === 'time')
                return b.processing_time_ms - a.processing_time_ms;
            const at = a.analyzed_at ? Date.parse(a.analyzed_at) : 0;
            const bt = b.analyzed_at ? Date.parse(b.analyzed_at) : 0;
            return bt - at;
        });
    }, [cases, query, verdicts, sort]);
    function toggleVerdict(verdict) {
        setVerdicts((prev) => {
            const next = new Set(prev);
            if (next.has(verdict))
                next.delete(verdict);
            else
                next.add(verdict);
            return next;
        });
    }
    const filtering = query.trim().length > 0 || verdicts.size > 0;
    return (_jsxs(_Fragment, { children: [_jsx(Header, { title: "Cases", description: "Analyses completed during this browser session." }), _jsxs("div", { className: "space-y-4 px-7 py-6", children: [_jsx(Panel, { className: "px-4 py-3", children: _jsxs("div", { className: "flex flex-wrap items-center gap-x-5 gap-y-3", children: [_jsxs("label", { className: "flex min-w-[220px] flex-1 items-center gap-2 rounded-[5px] border border-line-strong bg-inset px-2.5 py-1.5 focus-within:border-steel-dim", children: [_jsx(IconSearch, { size: 14, className: "shrink-0 text-ink-4" }), _jsx("input", { type: "search", value: query, onChange: (e) => setQuery(e.target.value), placeholder: "Search case ID, sender or subject", className: "w-full bg-transparent text-[12.5px] text-ink outline-none placeholder:text-ink-4" })] }), _jsx("div", { className: "flex flex-wrap items-center gap-1.5", children: VERDICTS.map((verdict) => {
                                        const on = verdicts.has(verdict);
                                        const tone = verdictTone(verdict);
                                        return (_jsx("button", { type: "button", onClick: () => toggleVerdict(verdict), "aria-pressed": on, className: `rounded-sm border px-1.5 py-[3px] text-[10.5px] font-semibold uppercase tracking-[0.08em] transition-colors ${on
                                                ? `${tone.text} ${tone.bg} ${tone.border}`
                                                : 'border-line text-ink-4 hover:text-ink-2'}`, children: verdict }, verdict));
                                    }) }), _jsx("div", { className: "flex items-center gap-1", children: SORTS.map((option) => (_jsx("button", { type: "button", onClick: () => setSort(option.key), "aria-pressed": sort === option.key, className: `rounded-[4px] px-2 py-1 text-[11.5px] transition-colors ${sort === option.key
                                            ? 'bg-raised font-medium text-ink'
                                            : 'text-ink-3 hover:text-ink'}`, children: option.label }, option.key))) })] }) }), _jsx(Section, { title: "All Cases", count: rows.length, action: filtering ? (_jsxs(Badge, { tone: verdictTone(null), children: ["Filtered from ", cases.length] })) : undefined, children: rows.length === 0 ? (_jsx("p", { className: "px-5 py-10 text-center text-[12.5px] text-ink-3", children: cases.length === 0
                                ? 'No completed cases in this session. Upload an .EML file to create the first one.'
                                : 'No cases match this filter.' })) : (_jsx(CasesTable, { rows: rows })) })] })] }));
}
