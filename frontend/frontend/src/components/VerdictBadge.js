import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { verdictTone } from '../lib/severity';
import { Badge } from './primitives';
export function VerdictBadge({ verdict }) {
    return _jsx(Badge, { tone: verdictTone(verdict), children: verdict });
}
/** The dominant display treatment used at the top of a report. */
export function VerdictDisplay({ verdict }) {
    const tone = verdictTone(verdict);
    const isMalicious = String(verdict).toUpperCase() === 'MALICIOUS';
    return (_jsxs("div", { children: [_jsx("div", { className: "eyebrow", children: "Verdict" }), _jsx("div", { className: `mt-2 inline-flex items-center rounded-md border px-4 py-2.5 ${tone.border} ${isMalicious ? tone.solid : tone.bg}`, children: _jsx("span", { className: `font-display text-[26px] font-bold leading-none tracking-[0.01em] ${isMalicious ? 'text-white' : tone.text}`, children: verdict }) })] }));
}
