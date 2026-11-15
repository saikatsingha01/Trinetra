import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/* ==========================================================================
   ThreatIntelligencePanel — renders backend.threat_intelligence.
   --------------------------------------------------------------------------
   Four indicator classes, one tab each, counts on the tabs so an empty class
   is visible without clicking. Every number here is the backend's
   reputation_score; the frontend only labels which band it falls in
   (see lib/severity.ts, which mirrors the thresholds in logic/rules.py).

   reputation_score runs 0-100 and HIGHER IS WORSE, so the meter fills toward
   danger. That is easy to misread, hence the caption.
   ========================================================================== */
import { useState } from 'react';
import { reputationTone, severityTone } from '../lib/severity';
import { formatDate, humanizeToken, truncateEnd } from '../lib/format';
import { Badge, Chip, EmptyNote, Field, Meter, Section } from './primitives';
import { IconGlobe, IconHash, IconLink, IconServer } from './icons';
const TABS = [
    { key: 'ips', label: 'IPs', Icon: IconServer },
    { key: 'domains', label: 'Domains', Icon: IconGlobe },
    { key: 'urls', label: 'URLs', Icon: IconLink },
    { key: 'hashes', label: 'Hashes', Icon: IconHash },
];
/* -------------------------------------------------------------------------
   One indicator card. The identifier is the headline; reputation is the
   status; everything else is context the backend chose to send.
   ------------------------------------------------------------------------- */
function IndicatorCard({ identifier, reputation, threatHistory, categories, children, }) {
    const reputationUnknown = categories.includes('reputation_unknown');
    const visibleCategories = categories.filter((category) => category !== 'reputation_unknown');
    const tone = reputationUnknown
        ? { ...reputationTone(0), label: 'Unknown' }
        : reputation === 0
            ? { ...reputationTone(0), label: 'No malicious reputation' }
            : reputationTone(reputation);
    return (_jsxs("li", { className: "border-b border-line px-5 py-4 last:border-b-0", children: [_jsxs("div", { className: "flex flex-wrap items-start justify-between gap-x-4 gap-y-2", children: [_jsx("div", { className: "datum min-w-0 break-all text-[13px] text-ink", children: identifier }), _jsx(Badge, { tone: tone, children: tone.label })] }), _jsxs("div", { className: "mt-3", children: [_jsxs("div", { className: "flex items-baseline justify-between gap-3", children: [_jsx("span", { className: "eyebrow", children: "Reputation" }), _jsxs("span", { className: `datum text-[12px] tabular ${tone.text}`, children: reputationUnknown ? 'No result' : `${reputation} / 100` })] }), _jsx(Meter, { value: reputationUnknown ? 0 : reputation, max: 100, tone: tone, className: "mt-1.5" })] }), children, _jsxs("div", { className: "mt-3 flex flex-wrap items-center gap-1.5", children: [threatHistory && _jsx(Badge, { tone: severityTone('high'), children: "Threat history" }), reputationUnknown && _jsx(Badge, { tone: tone, children: "No reputation result" }), visibleCategories.map((category) => (_jsx(Chip, { children: humanizeToken(category) }, category))), !threatHistory && visibleCategories.length === 0 && !reputationUnknown && (_jsx("span", { className: "text-[11.5px] text-ink-4", children: "No categories reported." }))] })] }));
}
/* -------------------------------------------------------------------------
   Per-class lists
   ------------------------------------------------------------------------- */
function IPList({ items }) {
    return (_jsx("ul", { children: items.map((item) => (_jsx(IndicatorCard, { identifier: item.ip, reputation: item.reputation_score, threatHistory: item.threat_history, categories: item.categories, children: _jsxs("div", { className: "mt-3 grid gap-4 sm:grid-cols-3", children: [_jsx(Field, { label: "Country", value: item.country }), _jsx(Field, { label: "ASN", value: item.asn }), _jsx(Field, { label: "ISP", value: item.isp, mono: false })] }) }, item.ip))) }));
}
function DomainList({ items }) {
    return (_jsx("ul", { children: items.map((item) => (_jsx(IndicatorCard, { identifier: item.domain, reputation: item.reputation_score, threatHistory: item.threat_history, categories: item.categories, children: _jsxs("div", { className: "mt-3 grid gap-4 sm:grid-cols-3", children: [_jsx(Field, { label: "Country", value: item.country }), _jsx(Field, { label: "Registrar", value: item.registrar, mono: false }), _jsx(Field, { label: "Created", value: formatDate(item.creation_date) })] }) }, item.domain))) }));
}
function URLList({ items }) {
    return (_jsx("ul", { children: items.map((item) => (_jsx(IndicatorCard, { 
            // URLs are shown in full but never rendered as a clickable link.
            identifier: item.url, reputation: item.reputation_score, threatHistory: item.threat_history, categories: item.categories, children: _jsx("div", { className: "mt-3", children: _jsx(Field, { label: "Domain", value: item.domain }) }) }, item.url))) }));
}
function HashList({ items }) {
    return (_jsx("ul", { children: items.map((item) => (_jsx(IndicatorCard, { identifier: truncateEnd(item.hash, 64), reputation: item.reputation_score, threatHistory: item.threat_history, categories: item.categories, children: _jsx("div", { className: "mt-3", children: _jsx(Field, { label: "Type", value: item.hash_type.toUpperCase() }) }) }, item.hash))) }));
}
/* -------------------------------------------------------------------------
   Panel
   ------------------------------------------------------------------------- */
export function ThreatIntelligencePanel({ data }) {
    const [active, setActive] = useState('ips');
    if (!data) {
        return (_jsx(Section, { title: "Threat intelligence", children: _jsx(EmptyNote, { children: "The response did not include threat intelligence." }) }));
    }
    const counts = {
        ips: data.ips?.length ?? 0,
        domains: data.domains?.length ?? 0,
        urls: data.urls?.length ?? 0,
        hashes: data.hashes?.length ?? 0,
    };
    const total = counts.ips + counts.domains + counts.urls + counts.hashes;
    return (_jsxs(Section, { title: "Threat intelligence", count: total, caption: "Reputation scores are 0\u2013100 as reported by the backend, where a higher score is worse.", children: [_jsx("div", { role: "tablist", "aria-label": "Indicator type", className: "flex border-b border-line", children: TABS.map(({ key, label, Icon }) => {
                    const isActive = key === active;
                    const count = counts[key];
                    return (_jsxs("button", { role: "tab", type: "button", "aria-selected": isActive, onClick: () => setActive(key), className: `-mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 font-display text-[12px] font-medium transition-colors ${isActive
                            ? 'border-steel-hi text-ink'
                            : 'border-transparent text-ink-3 hover:text-ink-2'}`, children: [_jsx(Icon, { size: 14, className: isActive ? 'text-steel-hi' : 'text-ink-4' }), label, _jsx("span", { className: `datum rounded-sm px-1.5 py-0.5 text-[10.5px] tabular ${count > 0 ? 'bg-inset text-ink-2' : 'text-ink-4'}`, children: count })] }, key));
                }) }), _jsxs("div", { role: "tabpanel", children: [active === 'ips' &&
                        (counts.ips > 0 ? (_jsx(IPList, { items: data.ips })) : (_jsx(EmptyNote, { children: "No IP addresses were submitted for this email." }))), active === 'domains' &&
                        (counts.domains > 0 ? (_jsx(DomainList, { items: data.domains })) : (_jsx(EmptyNote, { children: "No domains were submitted for this email." }))), active === 'urls' &&
                        (counts.urls > 0 ? (_jsx(URLList, { items: data.urls })) : (_jsx(EmptyNote, { children: "No URLs were submitted for this email." }))), active === 'hashes' &&
                        (counts.hashes > 0 ? (_jsx(HashList, { items: data.hashes })) : (_jsx(EmptyNote, { children: "No file hashes were submitted for this email." })))] }), total === 0 && (_jsx("p", { className: "border-t border-line px-5 py-3 text-[11.5px] text-ink-4", children: "An empty result means no indicators were looked up \u2014 not that the email is clean." }))] }));
}
