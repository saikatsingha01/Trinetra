import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
/* Primary .EML ingestion control. Validation and file handoff remain exactly
   on the existing API path; this component only controls the browser UI. */
import { useRef, useState } from 'react';
import { ACCEPT_ATTRIBUTE, validateEmlFile } from '../services/api';
import { IconUpload } from './icons';
export function UploadZone({ onSelect, onReject, disabled = false, }) {
    const inputRef = useRef(null);
    const [dragging, setDragging] = useState(false);
    const dragDepth = useRef(0);
    function accept(files) {
        const selected = Array.from(files ?? []);
        if (selected.length === 0)
            return;
        if (selected.length > 5) {
            onReject('You can upload up to 5 Gmail/EML messages at once.');
            return;
        }
        const invalid = selected.map(validateEmlFile).find(Boolean);
        if (invalid) {
            onReject(invalid.message);
            return;
        }
        onSelect(selected);
    }
    function reset() {
        dragDepth.current = 0;
        setDragging(false);
    }
    return (_jsxs("div", { onDragEnter: (e) => {
            e.preventDefault();
            if (disabled)
                return;
            dragDepth.current += 1;
            setDragging(true);
        }, onDragOver: (e) => {
            e.preventDefault();
            if (!disabled)
                e.dataTransfer.dropEffect = 'copy';
        }, onDragLeave: (e) => {
            e.preventDefault();
            dragDepth.current -= 1;
            if (dragDepth.current <= 0)
                reset();
        }, onDrop: (e) => {
            e.preventDefault();
            reset();
            if (disabled)
                return;
            accept(e.dataTransfer.files);
        }, className: `trinetra-dropzone ${dragging ? 'is-dragging' : ''} ${disabled ? 'is-disabled' : ''}`, children: [_jsx("input", { ref: inputRef, type: "file", multiple: true, accept: ACCEPT_ATTRIBUTE, className: "sr-only", disabled: disabled, onChange: (e) => {
                    accept(e.target.files);
                    e.target.value = '';
                } }), _jsxs("button", { type: "button", disabled: disabled, onClick: () => inputRef.current?.click(), className: "trinetra-dropzone__button", "aria-label": "Choose up to five EML files at once", children: [_jsx("span", { className: `trinetra-dropzone__orb ${dragging ? 'is-active' : ''}`, children: _jsx(IconUpload, { size: 24 }) }), _jsxs("span", { className: "trinetra-dropzone__copy", children: [_jsx("strong", { children: "Drop up to 5 .EML / Gmail files here" }), _jsx("small", { children: "or click to select multiple messages at once" })] })] })] }));
}
