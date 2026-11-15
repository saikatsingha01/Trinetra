import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { VERDICTS } from '../types/analysis';
import { verdictTone } from '../lib/severity';
/**
 * Reads the backend's band strings ("21-40") into numbers. Returns null if the
 * table is missing or unparseable, so the caller can fall back rather than
 * invent boundaries.
 */
function parseBands(info) {
    if (!info?.thresholds)
        return null;
    const bands = [];
    for (const verdict of VERDICTS) {
        const raw = info.thresholds[verdict];
        if (typeof raw !== 'string')
            continue;
        const match = raw.match(/^\s*(\d+)\s*-\s*(\d+)\s*$/);
        if (!match)
            continue;
        const min = Number(match[1]);
        const max = Number(match[2]);
        if (Number.isNaN(min) || Number.isNaN(max) || max < min)
            continue;
        bands.push({ verdict, min, max });
    }
    return bands.length === VERDICTS.length ? bands : null;
}
export function RiskScore({ score, verdict, verdictInfo, }) {
    const tone = verdictTone(verdict);
    const bands = parseBands(verdictInfo);
    const active = String(verdict).toUpperCase();
    const clamped = Math.min(100, Math.max(0, score));
    return (_jsxs("div", { children: [_jsx("div", { className: "eyebrow", children: "Risk score" }), _jsxs("div", { className: "mt-2 flex items-baseline gap-1.5", children: [_jsx("span", { className: `font-display text-[46px] font-bold leading-none tracking-[-0.03em] tabular ${tone.text}`, children: score }), _jsx("span", { className: "font-display text-[18px] font-medium leading-none text-ink-4 tabular", children: "/ 100" })] }), bands ? (_jsxs("div", { className: "mt-5", children: [_jsxs("div", { className: "relative flex h-2 gap-[2px]", role: "img", "aria-label": `Risk score ${score} of 100, in the ${active} band`, children: [bands.map((band) => {
                                const bandTone = verdictTone(band.verdict);
                                const isActive = band.verdict === active;
                                return (_jsx("div", { style: { flexGrow: band.max - band.min + 1 }, className: `overflow-hidden rounded-[2px] ${isActive ? bandTone.solid : `${bandTone.bg} opacity-60`}` }, band.verdict));
                            }), _jsx("div", { className: "pointer-events-none absolute -top-1 bottom-[-4px] w-[2px] bg-ink", style: { left: `calc(${clamped}% - 1px)` } })] }), _jsx("div", { className: "mt-2 flex gap-[2px]", children: bands.map((band) => {
                            const bandTone = verdictTone(band.verdict);
                            const isActive = band.verdict === active;
                            return (_jsxs("div", { style: { flexGrow: band.max - band.min + 1 }, className: "min-w-0", children: [_jsx("div", { className: `truncate text-[9.5px] font-semibold uppercase tracking-[0.07em] ${isActive ? bandTone.text : 'text-ink-4'}`, children: band.verdict }), _jsxs("div", { className: "datum text-[9.5px] tabular text-ink-4", children: [band.min, "\u2013", band.max] })] }, band.verdict));
                        }) })] })) : (
            // No band table from the backend — show the score alone.
            _jsxs("div", { className: "mt-5", children: [_jsx("div", { className: "h-2 overflow-hidden rounded-full bg-inset", children: _jsx("div", { className: `h-full rounded-full ${tone.solid}`, style: { width: `${clamped}%` } }) }), _jsx("p", { className: "mt-2 text-[11px] text-ink-4", children: "Verdict bands were not included in the response." })] }))] }));
}
