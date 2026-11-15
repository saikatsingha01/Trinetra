import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { formatDateTime } from '../lib/format';
import { AIAssessmentPanel } from './AIAssessment';
import { Correlations } from './Correlations';
import { DetectionReasons } from './DetectionReasons';
import { EmailSummary } from './EmailSummary';
import { ScoreBreakdownPanel } from './ScoreBreakdown';
import { SecurityAnalysisPanel } from './SecurityAnalysis';
import { ThreatIntelligencePanel } from './ThreatIntelligence';
import { TriggeredRulesTable } from './TriggeredRules';
import { Panel } from './primitives';
import { IconAlert } from './icons';
import { SecurityOverview } from './SecurityOverview';
import { SenderLocationMap } from './SenderLocationMap';
import { AnalysisEvidenceExtras } from './AnalysisEvidenceExtras';
import { parseEmlForGmailView } from '../lib/emailViewer';
import { useEffect, useState, useRef } from 'react';
import { downloadReportPdf } from '../lib/pdf';
function ProvidedGmail({ content, filename }) {
    const [open, setOpen] = useState(false);
    const [emailData, setEmailData] = useState(null);
    const [viewerKey, setViewerKey] = useState(null);
    const iframeRef = useRef(null);
    useEffect(() => {
        if (!open)
            return;
        const onKey = (event) => {
            if (event.key === 'Escape') setOpen(false);
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [open]);
    useEffect(() => {
        if (!content) {
            setEmailData(null);
            return;
        }
        try { setEmailData(parseEmlForGmailView(content)); }
        catch { setEmailData({ from: 'Unknown sender', to: '', cc: '', bcc: '', replyTo: '', subject: filename || '(no subject)', date: '', body: String(content), attachments: [] }); }
    }, [content, filename]);
    useEffect(() => {
        if (!open || !emailData) return;
        const key = `trinetra-gmail-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        try {
            sessionStorage.setItem(key, JSON.stringify(emailData));
            setViewerKey(key);
        } catch {
            setViewerKey(null);
        }
        return () => {
            try { sessionStorage.removeItem(key); } catch { /* ignore */ }
        };
    }, [open, emailData]);
    const safeFilename = filename || 'Uploaded Gmail / EML message';
    const senderName = String(emailData?.from || 'Unknown sender').replace(/<[^>]*>/g, '').trim() || 'Unknown sender';
    const viewerSrc = viewerKey ? `/threeui/ThreeDPaper-email.html?emailKey=${encodeURIComponent(viewerKey)}` : '/threeui/ThreeDPaper-email.html';
    return (_jsxs("section", { className: "provided-gmail-shell", children: [_jsxs("div", { className: "provided-gmail-head", children: [_jsxs("div", { children: [_jsx("div", { className: "eyebrow", children: "ORIGINAL MESSAGE" }), _jsx("h2", { children: "Provided Gmail" }), _jsxs("p", { children: [safeFilename, " — structured to mirror the message view a user would open in Gmail."] })] }), _jsx("button", { type: "button", className: "result-expand-button", disabled: !content, onClick: () => setOpen(true), children: "SEE PROVIDED GMAIL" })] }), !content && (_jsxs("div", { className: "provided-gmail-missing", children: [_jsx(IconAlert, { size: 14 }), _jsx("span", { children: "The original Gmail content is unavailable in this report." })] })), open && (_jsxs("div", { className: "provided-gmail-modal", role: "dialog", "aria-modal": "true", "aria-label": "Provided Gmail", children: [_jsx("div", { className: "provided-gmail-modal__backdrop", onClick: () => setOpen(false) }), _jsxs("div", { className: "provided-gmail-modal__stage", children: [_jsx("iframe", { ref: iframeRef, className: "provided-gmail-modal__scene", src: viewerSrc, title: "ThreeDPaper Gmail view", scrolling: "no" }), _jsx("button", { type: "button", className: "provided-gmail-modal__close", onClick: () => setOpen(false), "aria-label": "Close provided Gmail scene", children: "CLOSE" })] })] }))] }));
}


function ExportPdfButton({ report }) {
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');
    async function handleExport() {
        setBusy(true);
        setError('');
        try {
            await downloadReportPdf(report);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Unable to export the report.');
        } finally {
            setBusy(false);
        }
    }
    return _jsxs("div", { className: "result-export-wrap result-export-wrap--prominent", children: [
        _jsx("button", { type: "button", className: "result-export-button", onClick: handleExport, disabled: busy, children: busy ? "GENERATING PDF..." : "Export Report as PDF" }),
        error && _jsx("span", { className: "result-export-error", children: error })
    ] });
}

function ProvenanceNotice({ report }) {
    if (!report.is_temporary_backend)
        return null;
    return (_jsxs("div", { className: "result-provenance", children: [_jsx(IconAlert, { size: 15 }), _jsxs("p", { children: [_jsx("strong", { children: "Temporary backend." }), " The API that answered declared itself a stand-in. The scoring is real, but some analysis inputs are placeholders."] })] }));
}
function ReportMeta({ report }) {
    return (_jsx(Panel, { className: "result-source-panel", children: _jsxs("div", { className: "result-source-grid", children: [_jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "SOURCE FILE" }), _jsx("strong", { children: report.source_file?.filename || 'EML message' })] }), _jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "ANALYZED" }), _jsx("strong", { children: formatDateTime(report.analyzed_at) })] }), _jsxs("div", { children: [_jsx("span", { className: "eyebrow", children: "CASE ID" }), _jsx("strong", { className: "result-mono", children: report.case_id })] })] }) }));
}
export function SecurityReport({ report }) {
    return (_jsxs("div", { className: "result-page", children: [_jsx(SecurityOverview, { report: report }), _jsx(ExportPdfButton, { report: report }), report.analysis_mode === 'subhom_only' && (_jsxs("div", { className: "result-degraded-notice", children: [_jsx(IconAlert, { size: 15 }), _jsxs("div", { children: [_jsx("strong", { children: "AI assessment unavailable." }), " TRINETRA calculated this risk score from Subhom's security and threat signals only. The confidence score is intentionally lower because Saikat's Ollama signal could not be incorporated. Resend the email for a more precise report."] })] })), _jsx(ProvidedGmail, { content: report.provided_email, filename: report.source_file?.filename }), _jsx(ProvenanceNotice, { report: report }), _jsxs("div", { className: "result-feature-grid", children: [_jsx(EmailSummary, { email: report.email }), _jsx(SenderLocationMap, { data: report.threat_intelligence })] }), _jsxs("section", { className: "result-section-label", children: [_jsx("div", { className: "eyebrow", children: "EVIDENCE LAYER" }), _jsx("h2", { children: "What the engine saw" }), _jsx("p", { children: "Authentication, infrastructure reputation and model signals are presented exactly as returned by the analysis pipeline." })] }), _jsxs("div", { className: "result-evidence-grid", children: [_jsx(SecurityAnalysisPanel, { data: report.security_analysis }), _jsx(AIAssessmentPanel, { data: report.ai_assessment, unavailable: report.analysis_mode === 'subhom_only' })] }), _jsx(ThreatIntelligencePanel, { data: report.threat_intelligence }), _jsx(AnalysisEvidenceExtras, { report: report }), _jsxs("section", { className: "result-section-label result-section-label--compact", children: [_jsx("div", { className: "eyebrow", children: "DECISION TRAIL" }), _jsx("h2", { children: "Why this verdict was returned" })] }), _jsxs("div", { className: "result-evidence-grid", children: [_jsx(DetectionReasons, { reasons: report.reasons ?? [] }), _jsx(Correlations, { correlations: report.correlations ?? [], bySeverity: report.correlations_by_severity })] }), _jsx(ScoreBreakdownPanel, { breakdown: report.score_breakdown }), _jsx(TriggeredRulesTable, { rules: report.triggered_rules ?? [] }), _jsx(ReportMeta, { report: report }), _jsx("p", { className: "result-footnote", children: "Every value shown in this report came from the connected analysis engine. TRINETRA presents the response but does not perform its own parsing, scoring or classification." })] }));
}
