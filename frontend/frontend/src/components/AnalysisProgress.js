import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useRef, useState } from 'react';
import { Button } from './primitives';
const STAGES = [
    { id: 'upload', label: 'Email uploaded' },
    { id: 'parsing', label: 'Email parsing' },
    { id: 'subhom', label: 'Security & threat analysis' },
    { id: 'ollama', label: 'Ollama AI assessment' },
    { id: 'finalizing', label: 'Finalizing analysis' },
];
function Spinner() {
    return (_jsx("div", { className: "trinetra-spinner", "aria-hidden": "true", children: Array.from({ length: 8 }, (_, index) => _jsx("span", {}, index)) }));
}
function stageForProgress(progress) {
    if (progress >= 100)
        return 'complete';
    if (progress >= 90)
        return 'finalizing';
    if (progress >= 60)
        return 'ollama';
    if (progress >= 40)
        return 'subhom';
    if (progress >= 18)
        return 'parsing';
    return 'upload';
}
function stageCopy(stage) {
    switch (stage) {
        case 'upload': return ['Uploading email', 'Sending the message into the connected pipeline.'];
        case 'parsing': return ['Parsing email', 'Reading the message structure, headers and content.'];
        case 'subhom': return ['Security analysis', 'TRINETRA is processing security and threat signal.'];
        case 'ollama': return ['AI assessment', 'Ollama is evaluating the correlated analysis.'];
        case 'finalizing': return ['Finalizing analysis', 'Preparing the complete TRINETRA report.'];
        case 'complete': return ['Analysis complete', 'Opening the final security report.'];
    }
}
export function AnalysisProgress({ filename, onCancel, onSubhomReceived, onAnalysisComplete, externalTarget, }) {
    const [target, setTarget] = useState(externalTarget ?? 12);
    useEffect(() => {
        if (typeof externalTarget === 'number')
            setTarget((value) => Math.max(value, externalTarget));
    }, [externalTarget]);
    const [progress, setProgress] = useState(0);
    const [elapsedMs, setElapsedMs] = useState(0);
    const completionTriggered = useRef(false);
    // Smoothly chase the target instead of jumping between backend events.
    useEffect(() => {
        const id = window.setInterval(() => {
            setProgress((current) => {
                const delta = target - current;
                if (Math.abs(delta) < 0.35)
                    return target;
                return current + delta * (target >= 90 ? 0.22 : 0.09);
            });
            setElapsedMs((value) => value + 100);
        }, 100);
        return () => window.clearInterval(id);
    }, [target]);
    const stage = stageForProgress(progress);
    const [title, subtitle] = stageCopy(stage);
    useEffect(() => {
        if (target >= 60 && target < 90)
            onSubhomReceived?.();
    }, [target, onSubhomReceived]);
    useEffect(() => {
        if (target === 100 && progress > 99.5 && !completionTriggered.current) {
            completionTriggered.current = true;
            onAnalysisComplete?.();
        }
    }, [target, progress, onAnalysisComplete]);
    const stageIndex = stage === 'complete' ? STAGES.length : STAGES.findIndex((item) => item.id === stage);
    return (_jsxs("div", { className: "trinetra-loader-page", role: "status", "aria-live": "polite", "aria-label": "TRINETRA analysis in progress", children: [_jsx("div", { className: "trinetra-loader-glow" }), _jsxs("div", { className: "trinetra-loader-card", children: [_jsx("div", { className: "trinetra-loader-kicker", children: "TRINETRA // ANALYSIS PIPELINE" }), _jsx(Spinner, {}), _jsxs("div", { className: "trinetra-loader-percent", children: [Math.min(100, Math.round(progress)), "%"] }), _jsx("h1", { children: title }), _jsx("p", { className: "trinetra-loader-subtitle", children: subtitle }), _jsx("p", { className: "trinetra-loader-file", children: filename }), _jsx("div", { className: "trinetra-progress", "aria-label": `Analysis ${Math.round(progress)} percent complete`, children: _jsx("div", { className: "trinetra-progress-value", style: { width: `${Math.min(100, progress)}%` } }) }), _jsx("div", { className: "trinetra-stage-list", children: STAGES.map((item, index) => {
                            const done = index < stageIndex;
                            const active = index === stageIndex && stage !== 'complete';
                            return (_jsxs("div", { className: `trinetra-stage ${done ? 'is-done' : ''} ${active ? 'is-active' : ''}`, children: [_jsx("span", { className: "trinetra-stage-mark", children: done ? '✓' : active ? '◉' : '○' }), _jsx("span", { children: item.label })] }, item.id));
                        }) }), _jsxs("div", { className: "trinetra-loader-footer", children: [_jsxs("span", { children: [(elapsedMs / 1000).toFixed(1), "s elapsed"] }), onCancel && _jsx(Button, { variant: "ghost", size: "sm", onClick: onCancel, children: "Cancel" })] })] })] }));
}
