import type { AnalysisReport } from '../types/analysis';
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
import { useEffect, useRef, useState } from 'react';
import { downloadReportPdf } from '../lib/pdf';

function ProvidedGmail({ content, filename }: { content?: string | null; filename?: string | null }) {
  const [open, setOpen] = useState(false);
  const [emailData, setEmailData] = useState<ReturnType<typeof parseEmlForGmailView> | null>(null);
  const [viewerKey, setViewerKey] = useState<string | null>(null);

  useEffect(() => {
    if (!content) {
      setEmailData(null);
      return;
    }
    try {
      setEmailData(parseEmlForGmailView(content));
    } catch {
      setEmailData({
        from: 'Unknown sender', to: '', cc: '', bcc: '', replyTo: '',
        subject: filename || '(no subject)', date: '', body: String(content), attachments: [],
      });
    }
  }, [content, filename]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

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
  const viewerSrc = viewerKey
    ? `/threeui/ThreeDPaper-email.html?emailKey=${encodeURIComponent(viewerKey)}`
    : '/threeui/ThreeDPaper-email.html';

  return (
    <section className="provided-gmail-shell">
      <div className="provided-gmail-head">
        <div>
          <div className="eyebrow">ORIGINAL MESSAGE</div>
          <h2>Provided Gmail</h2>
          <p>{safeFilename} — structured to mirror the message view a user would open in Gmail.</p>
        </div>
        <button type="button" className="result-expand-button" disabled={!content} onClick={() => setOpen(true)}>
          SEE PROVIDED GMAIL
        </button>
      </div>
      {!content && (
        <div className="provided-gmail-missing">
          <IconAlert size={14} />
          <span>The original Gmail content is unavailable in this report.</span>
        </div>
      )}
      {open && (
        <div className="provided-gmail-modal" role="dialog" aria-modal="true" aria-label="Provided Gmail">
          <div className="provided-gmail-modal__backdrop" onClick={() => setOpen(false)} />
          <div className="provided-gmail-modal__stage">
            <iframe
              className="provided-gmail-modal__scene"
              src={viewerSrc}
              title="ThreeDPaper Gmail view"
              scrolling="no"
            />
            <button
              type="button"
              className="provided-gmail-modal__close"
              onClick={() => setOpen(false)}
              aria-label="Close provided Gmail scene"
            >
              CLOSE
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

function ExportPdfButton({ report }: { report: AnalysisReport }) {
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

  return (
    <div className="result-export-wrap result-export-wrap--prominent">
      <button type="button" className="result-export-button" onClick={handleExport} disabled={busy}>
        {busy ? 'GENERATING PDF...' : 'Export Report as PDF'}
      </button>
      {error && <span className="result-export-error">{error}</span>}
    </div>
  );
}

function ProvenanceNotice({ report }: { report: AnalysisReport }) {
  if (!report.is_temporary_backend) return null;
  return (
    <div className="result-provenance">
      <IconAlert size={15} />
      <p><strong>Temporary backend.</strong> The API that answered declared itself a stand-in. The scoring is real, but some analysis inputs are placeholders.</p>
    </div>
  );
}

function ReportMeta({ report }: { report: AnalysisReport }) {
  return (
    <Panel className="result-source-panel">
      <div className="result-source-grid">
        <div><span className="eyebrow">SOURCE FILE</span><strong>{report.source_file?.filename || 'EML message'}</strong></div>
        <div><span className="eyebrow">ANALYZED</span><strong>{formatDateTime(report.analyzed_at)}</strong></div>
        <div><span className="eyebrow">CASE ID</span><strong className="result-mono">{report.case_id}</strong></div>
      </div>
    </Panel>
  );
}

export function SecurityReport({ report }: { report: AnalysisReport }) {
  return (
    <div className="result-page">
      <SecurityOverview report={report} />
      <ExportPdfButton report={report} />
      {report.analysis_mode === 'subhom_only' && (
        <div className="result-degraded-notice">
          <IconAlert size={15} />
          <div><strong>AI assessment unavailable.</strong> TRINETRA calculated this risk score from Subhom's security and threat signals only. The confidence score is intentionally lower because Saikat's Ollama signal could not be incorporated. Resend the email for a more precise report.</div>
        </div>
      )}
      <ProvidedGmail content={report.provided_email} filename={report.source_file?.filename} />
      <ProvenanceNotice report={report} />

      <div className="result-feature-grid">
        <EmailSummary email={report.email} />
        <SenderLocationMap data={report.threat_intelligence} />
      </div>

      <section className="result-section-label">
        <div className="eyebrow">EVIDENCE LAYER</div>
        <h2>What the engine saw</h2>
        <p>Authentication, infrastructure reputation and model signals are presented exactly as returned by the analysis pipeline.</p>
      </section>

      <div className="result-evidence-grid">
        <SecurityAnalysisPanel data={report.security_analysis} />
        <AIAssessmentPanel data={report.ai_assessment} unavailable={report.analysis_mode === 'subhom_only'} />
      </div>

      <ThreatIntelligencePanel data={report.threat_intelligence} />
      <AnalysisEvidenceExtras report={report} />

      <section className="result-section-label result-section-label--compact">
        <div className="eyebrow">DECISION TRAIL</div>
        <h2>Why this verdict was returned</h2>
      </section>

      <div className="result-evidence-grid">
        <DetectionReasons reasons={report.reasons ?? []} />
        <Correlations correlations={report.correlations ?? []} bySeverity={report.correlations_by_severity} />
      </div>

      <ScoreBreakdownPanel breakdown={report.score_breakdown} />
      <TriggeredRulesTable rules={report.triggered_rules ?? []} />
      <ReportMeta report={report} />
      <p className="result-footnote">Every value shown in this report came from the connected analysis engine. TRINETRA presents the response but does not perform its own parsing, scoring or classification.</p>
    </div>
  );
}
