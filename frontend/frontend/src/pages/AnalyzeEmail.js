import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/Header';
import { UploadZone } from '../components/UploadZone';
import { FilePreview } from '../components/FilePreview';
import { AnalysisProgress } from '../components/AnalysisProgress';
import { Alert } from '../components/Alert';
import { Button } from '../components/primitives';
import { IconArrowRight, IconTrash } from '../components/icons';
import { analyzeEmail, toUserMessage } from '../services/api';
import { useSession } from '../store/session';
import { takePendingFile } from '../store/pendingUpload';
export function AnalyzeEmail() {
    const navigate = useNavigate();
    const { recordReport } = useSession();
    const [files, setFiles] = useState([]);
    const [phase, setPhase] = useState('choose');
    const [failure, setFailure] = useState(null);
    const abortRef = useRef(null);
    const [loaderTarget, setLoaderTarget] = useState(12);
    const [currentIndex, setCurrentIndex] = useState(0);
    useEffect(() => {
        const staged = takePendingFile();
        if (staged) {
            setFiles([staged]);
            setPhase('ready');
        }
    }, []);
    useEffect(() => () => abortRef.current?.abort(), []);
    async function run() {
        if (!files.length || phase === 'running' || abortRef.current)
            return;
        const controller = new AbortController();
        const analysisStartedAt = performance.now();
        abortRef.current = controller;
        setFailure(null);
        setLoaderTarget(12);
        setPhase('running');
        const successful = [];
        try {
            for (let index = 0; index < files.length; index += 1) {
                const file = files[index];
                setCurrentIndex(index);
                setLoaderTarget(Math.max(12, Math.round((index / files.length) * 88)));
                const report = await analyzeEmail(file, {
                    signal: controller.signal,
                    onProgress: (event) => {
                        const base = (index / files.length) * 88;
                        const span = 88 / files.length;
                        if (event.type === 'upload-start')
                            setLoaderTarget((current) => Math.max(current, base + span * 0.18));
                        if (event.type === 'case-received')
                            setLoaderTarget((current) => Math.max(current, base + span * 0.39));
                        if (event.type === 'security-analysis-received')
                            setLoaderTarget((current) => Math.max(current, base + span * 0.60));
                        if (event.type === 'analysis-complete')
                            setLoaderTarget((current) => Math.max(current, base + span));
                    },
                });
                const providedEmail = await file.text();
                recordReport({
                    ...report,
                    provided_email: providedEmail,
                    processing_time_ms: Math.round(performance.now() - analysisStartedAt),
                });
                successful.push(report.case_id);
            }
            setLoaderTarget(100);
            await new Promise((resolve) => window.setTimeout(resolve, 550));
            if (successful.length === 1)
                navigate(`/cases/${encodeURIComponent(successful[0])}`, { replace: true });
            else
                navigate(`/cases/batch?ids=${encodeURIComponent(successful.join(','))}`, { replace: true });
        }
        catch (error) {
            if (controller.signal.aborted) {
                setPhase('ready');
                return;
            }
            setFailure(toUserMessage(error));
            setPhase('ready');
        }
        finally {
            abortRef.current = null;
        }
    }
    if (phase === 'running') {
        const label = files.length > 1 ? `Email ${currentIndex + 1} of ${files.length} — ${files[currentIndex]?.name ?? ''}` : files[0]?.name ?? '';
        return _jsx(AnalysisProgress, { filename: label, externalTarget: loaderTarget, onCancel: () => { abortRef.current?.abort(); setPhase('ready'); } });
    }
    return (_jsxs(_Fragment, { children: [_jsx(Header, { title: "Analyze email", description: "Upload up to five .EML messages and review each assessment with result tabs." }), _jsx("div", { className: "internal-pad", children: _jsxs("div", { className: "analysis-layout", children: [_jsxs("div", { className: "analysis-intro", children: [_jsx("div", { className: "micro-label", children: "INGESTION WORKSPACE" }), _jsx("h2", { children: "Submit one or more messages." }), _jsx("p", { children: "TRINETRA sends each message through the same connected pipeline. Multiple uploads are processed safely one by one, then shown together as switchable result tabs." }), _jsxs("div", { className: "analysis-note", children: [_jsx("span", { children: "01" }), _jsxs("div", { children: [_jsx("strong", { children: "Upload" }), _jsx("small", { children: "Choose 1\u20135 valid .EML messages." })] })] }), _jsxs("div", { className: "analysis-note", children: [_jsx("span", { children: "02" }), _jsxs("div", { children: [_jsx("strong", { children: "Analyze" }), _jsx("small", { children: "TRINETRA processes each message through the connected pipeline." })] })] }), _jsxs("div", { className: "analysis-note", children: [_jsx("span", { children: "03" }), _jsxs("div", { children: [_jsx("strong", { children: "Review" }), _jsx("small", { children: "See the provided Gmail and the full assessment for every message." })] })] })] }), _jsxs("div", { className: "analysis-card", children: [failure && _jsx(Alert, { tone: "error", message: failure.message, detail: failure.detail, action: files.length ? _jsx(Button, { variant: "secondary", size: "sm", onClick: run, children: "Retry" }) : undefined }), files.length ? (_jsx(_Fragment, { children: _jsxs("div", { className: "batch-upload-summary", children: [_jsxs("div", { className: "batch-upload-add", children: [_jsx(UploadZone, { disabled: files.length >= 5, onSelect: (selected) => {
                                                            setFailure(null);
                                                            setFiles((current) => {
                                                                const seen = new Set(current.map((file) => `${file.name}:${file.size}:${file.lastModified}`));
                                                                const merged = [...current];
                                                                for (const file of selected) {
                                                                    const key = `${file.name}:${file.size}:${file.lastModified}`;
                                                                    if (!seen.has(key) && merged.length < 5) {
                                                                        seen.add(key);
                                                                        merged.push(file);
                                                                    }
                                                                }
                                                                return merged;
                                                            });
                                                            setPhase('ready');
                                                        }, onReject: (m) => setFailure({ message: m }) }), _jsx("div", { className: "batch-upload-add__hint", children: files.length >= 5 ? 'Maximum of 5 messages reached.' : `Add more Gmail messages (${5 - files.length} slot${5 - files.length === 1 ? '' : 's'} remaining).` })] }), _jsxs("div", { className: "batch-upload-summary__head", children: [_jsxs("strong", { children: [files.length, " ", files.length === 1 ? 'Gmail' : 'Gmails', " selected"] }), _jsx("span", { children: "MAX 5" })] }), _jsx("div", { className: "batch-upload-list", children: files.map((file, index) => _jsx(FilePreview, { file: file, onRemove: () => setFiles((current) => current.filter((_, i) => i !== index)) }, `${file.name}-${file.lastModified}-${index}`)) }), _jsxs("div", { className: "batch-upload-actions", children: [_jsxs(Button, { variant: "ghost", size: "sm", onClick: () => { setFiles([]); setFailure(null); }, children: [_jsx(IconTrash, { size: 13 }), " Clear"] }), _jsxs(Button, { variant: "primary", size: "lg", onClick: run, autoFocus: true, children: ["Analyze ", files.length > 1 ? 'emails' : 'email', " ", _jsx(IconArrowRight, { size: 15 })] })] })] }) })) : (_jsx(UploadZone, { onSelect: (selected) => { setFailure(null); setFiles(selected); setPhase('ready'); }, onReject: (m) => setFailure({ message: m }) }))] })] }) })] }));
}
