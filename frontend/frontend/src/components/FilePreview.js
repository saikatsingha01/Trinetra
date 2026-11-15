import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/* ==========================================================================
   FilePreview — the selected-file state of the upload card.
   Confirms what will be sent, and offers the way back out.
   ========================================================================== */
import { formatBytes } from '../lib/format';
import { IconCheck, IconFile, IconTrash } from './icons';
import { Button } from './primitives';
export function FilePreview({ file, onRemove, busy = false, }) {
    return (_jsx("div", { className: "settle rounded-lg border border-line bg-panel", children: _jsxs("div", { className: "flex items-start gap-4 px-6 py-6", children: [_jsx("span", { className: "flex h-11 w-11 shrink-0 items-center justify-center rounded-md border border-line-strong bg-inset text-ink-2", children: _jsx(IconFile, { size: 19 }) }), _jsxs("div", { className: "min-w-0 flex-1", children: [_jsx("p", { className: "datum text-[13.5px] leading-snug text-ink", children: file.name }), _jsx("p", { className: "mt-1 flex items-center gap-2 text-[12px] text-ink-3", children: _jsx("span", { className: "tabular", children: formatBytes(file.size) }) }), _jsxs("p", { className: "mt-3 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-low", children: [_jsx(IconCheck, { size: 14 }), "Ready for analysis"] })] }), _jsxs(Button, { variant: "ghost", size: "sm", onClick: onRemove, disabled: busy, "aria-label": `Remove ${file.name}`, children: [_jsx(IconTrash, { size: 13 }), "Remove"] })] }) }));
}
