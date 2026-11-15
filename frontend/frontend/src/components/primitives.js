import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useId, useState } from 'react';
import { IconChevronDown } from './icons';
/* -------------------------------------------------------------------------
   Panel — the single container primitive.
   ------------------------------------------------------------------------- */
export function Panel({ children, className = '', as: Tag = 'section', }) {
    return (_jsx(Tag, { className: `rounded-md border border-line bg-panel ${className}`, children: children }));
}
/* -------------------------------------------------------------------------
   Section — a titled report block. `count` is shown only when meaningful.
   ------------------------------------------------------------------------- */
export function Section({ title, caption, count, action, children, className = '', }) {
    return (_jsxs(Panel, { className: className, children: [_jsxs("header", { className: "flex items-start justify-between gap-4 border-b border-line px-5 py-3.5", children: [_jsxs("div", { className: "min-w-0", children: [_jsxs("div", { className: "flex items-center gap-2.5", children: [_jsx("h2", { className: "font-display text-[13.5px] font-semibold tracking-[-0.01em] text-ink", children: title }), count !== undefined && (_jsx("span", { className: "datum rounded-sm bg-inset px-1.5 py-0.5 text-[10.5px] text-ink-3 tabular", children: count }))] }), caption && _jsx("p", { className: "mt-1 text-[12px] leading-snug text-ink-3", children: caption })] }), action] }), children] }));
}
/* -------------------------------------------------------------------------
   Badge — small status chip. Tone comes from lib/severity.
   ------------------------------------------------------------------------- */
export function Badge({ tone, children, mono = false, className = '', }) {
    return (_jsx("span", { className: `inline-flex shrink-0 items-center gap-1.5 rounded-sm border px-1.5 py-[3px] text-[10.5px] font-semibold uppercase tracking-[0.08em] ${mono ? 'font-mono' : ''} ${tone.text} ${tone.bg} ${tone.border} ${className}`, children: children }));
}
/** Neutral chip for categories, patterns and other non-risk labels. */
export function Chip({ children, className = '' }) {
    return (_jsx("span", { className: `inline-flex items-center rounded-sm border border-line-strong bg-inset px-1.5 py-[3px] font-mono text-[10.5px] text-ink-2 ${className}`, children: children }));
}
/* -------------------------------------------------------------------------
   Field — a labelled value. `mono` marks machine-produced text.
   ------------------------------------------------------------------------- */
export function Field({ label, value, mono = true, children, className = '', }) {
    const empty = value === null || value === undefined || value === '';
    return (_jsxs("div", { className: className, children: [_jsx("div", { className: "eyebrow", children: label }), _jsx("div", { className: `mt-1 ${mono ? 'datum' : 'text-[13px] text-ink'} ${empty && !children ? 'text-ink-4' : ''}`, children: children ?? (empty ? '—' : value) })] }));
}
/* -------------------------------------------------------------------------
   A single row of a status list: label on the left, badge on the right.
   ------------------------------------------------------------------------- */
export function StatusRow({ label, tone, status, detail, }) {
    return (_jsxs("div", { className: "flex items-center justify-between gap-4 border-b border-line px-5 py-3 last:border-b-0", children: [_jsxs("div", { className: "min-w-0", children: [_jsx("div", { className: "font-display text-[12.5px] font-medium text-ink", children: label }), detail && _jsx("div", { className: "datum mt-0.5 text-[11.5px] text-ink-3", children: detail })] }), _jsx(Badge, { tone: tone, children: status })] }));
}
/* -------------------------------------------------------------------------
   Disclosure — expandable block. Used for Score Breakdown and Triggered
   Rules, which the brief asks to keep collapsed by default.
   ------------------------------------------------------------------------- */
export function Disclosure({ title, summary, count, defaultOpen = false, children, }) {
    const [open, setOpen] = useState(defaultOpen);
    const panelId = useId();
    return (_jsxs(Panel, { children: [_jsx("h2", { children: _jsxs("button", { type: "button", onClick: () => setOpen((v) => !v), "aria-expanded": open, "aria-controls": panelId, className: "flex w-full items-center justify-between gap-4 px-5 py-3.5 text-left transition-colors hover:bg-raised", children: [_jsxs("span", { className: "flex min-w-0 items-center gap-2.5", children: [_jsx("span", { className: "font-display text-[13.5px] font-semibold tracking-[-0.01em] text-ink", children: title }), count !== undefined && (_jsx("span", { className: "datum rounded-sm bg-inset px-1.5 py-0.5 text-[10.5px] text-ink-3 tabular", children: count }))] }), _jsxs("span", { className: "flex shrink-0 items-center gap-3", children: [summary && _jsx("span", { className: "datum text-[11.5px] text-ink-3", children: summary }), _jsx(IconChevronDown, { size: 15, className: `text-ink-3 transition-transform duration-200 ${open ? 'rotate-180' : ''}` })] })] }) }), open && (_jsx("div", { id: panelId, className: "border-t border-line", children: children }))] }));
}
/* -------------------------------------------------------------------------
   Empty note — states what is absent, without implying it is reassuring.
   ------------------------------------------------------------------------- */
export function EmptyNote({ children }) {
    return _jsx("p", { className: "px-5 py-6 text-[12.5px] text-ink-3", children: children });
}
/* -------------------------------------------------------------------------
   Meter — a plain horizontal bar. Width is a ratio of values the backend
   supplied; nothing is derived.
   ------------------------------------------------------------------------- */
export function Meter({ value, max, tone, className = '', }) {
    const pct = max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0;
    return (_jsx("div", { className: `h-1 overflow-hidden rounded-full bg-inset ${className}`, role: "presentation", children: _jsx("div", { className: `h-full rounded-full ${tone.solid} transition-[width] duration-500 ease-out`, style: { width: `${pct}%` } }) }));
}
/* -------------------------------------------------------------------------
   Spinner + button
   ------------------------------------------------------------------------- */
export function Spinner({ size = 14, className = '' }) {
    return (_jsx("span", { className: `spin inline-block shrink-0 rounded-full border-2 border-current border-t-transparent ${className}`, style: { width: size, height: size }, "aria-hidden": "true" }));
}
const BUTTON_STYLES = {
    primary: 'bg-steel text-white hover:bg-steel-hi disabled:bg-line-strong disabled:text-ink-4 border border-transparent',
    secondary: 'bg-raised text-ink border border-line-strong hover:border-ink-4 hover:bg-panel disabled:text-ink-4',
    ghost: 'bg-transparent text-ink-2 border border-transparent hover:text-ink hover:bg-raised disabled:text-ink-4',
    danger: 'bg-transparent text-critical border border-critical/40 hover:bg-critical/10 disabled:text-ink-4',
};
export function Button({ variant = 'secondary', size = 'md', busy = false, children, className = '', ...rest }) {
    const sizing = size === 'lg'
        ? 'h-11 px-6 text-[12px] tracking-[0.09em]'
        : size === 'sm'
            ? 'h-7 px-2.5 text-[11px] tracking-[0.05em]'
            : 'h-9 px-3.5 text-[11.5px] tracking-[0.06em]';
    return (_jsxs("button", { ...rest, disabled: rest.disabled || busy, className: `inline-flex items-center justify-center gap-2 rounded-[5px] font-display font-semibold uppercase transition-colors duration-150 disabled:cursor-not-allowed ${sizing} ${BUTTON_STYLES[variant]} ${className}`, children: [busy && _jsx(Spinner, { size: 13 }), children] }));
}
