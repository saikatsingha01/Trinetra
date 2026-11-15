import { useState } from 'react';
import type { AnalysisReport } from '../types/analysis';
import { Badge, Chip } from './primitives';
import { severityTone } from '../lib/severity';

function prettyKey(value: string) {
  return value.replace(/[_-]+/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}

function truthLabel(value: boolean | undefined) {
  return value == null ? 'NOT REPORTED' : value ? 'DETECTED' : 'NONE';
}

export function AnalysisEvidenceExtras({ report }: { report: AnalysisReport }) {
  const [showTechnical, setShowTechnical] = useState(false);
  const ai = report.ai_assessment;
  const attachments = report.attachment_analysis;
  const grounding = report.grounding;
  const model = report.model_info ?? ai?.model_info ?? null;
  const evidence = grounding?.evidence_references ?? [];
  const unsupported = grounding?.unsupported_claims ?? [];
  const ioc = report.iocs;
  const ti = report.threat_intelligence;
  const counts = {
    ips: ti?.ips?.length ?? ioc?.ips?.length ?? 0,
    domains: ti?.domains?.length ?? ioc?.domains?.length ?? 0,
    urls: ti?.urls?.length ?? ioc?.urls?.length ?? 0,
    hashes: ti?.hashes?.length ?? ioc?.hashes?.length ?? 0,
  };
  const total = counts.ips + counts.domains + counts.urls + counts.hashes;

  return (
    <>
      <section className="result-signal-grid">
        <div className="result-signal-panel">
          <div className="result-panel__head">
            <div><div className="eyebrow">BEHAVIOURAL SIGNALS</div><h2>What stood out</h2></div>
            <span className="result-panel__tag">MODEL + RULES</span>
          </div>
          <div className="result-signal-rows">
            <div><span>Urgency</span><Badge tone={severityTone(ai?.urgency_detected ? 'medium' : 'low')}>{truthLabel(ai?.urgency_detected)}</Badge></div>
            <div><span>Credential request</span><Badge tone={severityTone(ai?.credential_request_detected ? 'high' : 'low')}>{truthLabel(ai?.credential_request_detected)}</Badge></div>
            <div><span>Financial request</span><Badge tone={severityTone(ai?.financial_request_detected ? 'high' : 'low')}>{truthLabel(ai?.financial_request_detected)}</Badge></div>
            <div><span>Suspicious language</span><strong>{ai?.suspicious_language?.length ?? 0} signal{(ai?.suspicious_language?.length ?? 0) === 1 ? '' : 's'}</strong></div>
            <div><span>Detected patterns</span><strong>{ai?.detected_patterns?.length ?? 0} pattern{(ai?.detected_patterns?.length ?? 0) === 1 ? '' : 's'}</strong></div>
            <div><span>Attachments</span><Badge tone={severityTone(attachments?.malicious_attachment_detected ? 'high' : attachments?.attachment_risk_detected ? 'medium' : 'low')}>{attachments ? (attachments.malicious_attachment_detected ? 'MALICIOUS' : attachments.attachment_risk_detected ? 'RISK DETECTED' : 'NONE') : 'NOT REPORTED'}</Badge></div>
          </div>
        </div>

        <div className="result-signal-panel">
          <div className="result-panel__head">
            <div><div className="eyebrow">IOC INVENTORY</div><h2>Investigation surface</h2></div>
            <span className="result-panel__tag">{total} TOTAL</span>
          </div>
          <div className="result-ioc-grid">
            {Object.entries(counts).map(([key, count]) => (
              <div key={key} className="result-ioc-cell">
                <span>{key.toUpperCase()}</span><strong>{count}</strong>
              </div>
            ))}
          </div>
          <div className="result-signal-note">Counts reflect indicators returned or submitted to the connected intelligence pipeline. Zero does not mean safe; it means no indicator was available in that class.</div>
        </div>
      </section>

      {(evidence.length > 0 || unsupported.length > 0 || model || attachments) && (
        <section className="result-evidence-extra">
          <div className="result-evidence-extra__head">
            <div>
              <div className="eyebrow">PROVENANCE & GROUNDING</div>
              <h2>Evidence behind the assessment</h2>
              <p>Signals supplied by the connected analysis engines, kept separate from the final risk score.</p>
            </div>
            <button type="button" className="result-expand-button" onClick={() => setShowTechnical((value) => !value)}>
              {showTechnical ? 'Hide details' : 'View details'}
            </button>
          </div>

          <div className="result-grounding-summary">
            <div><span>Grounded</span><strong>{grounding?.grounded === false ? 'NO' : grounding ? 'YES' : '—'}</strong></div>
            <div><span>Evidence references</span><strong>{evidence.length || '—'}</strong></div>
            <div><span>Unsupported claims</span><strong>{unsupported.length || '0'}</strong></div>
            <div><span>Processing</span><strong>{report.processing_time_ms > 0 ? `${(report.processing_time_ms / 1000).toFixed(2)} s` : '—'}</strong></div>
          </div>

          {showTechnical && (
            <div className="result-technical-grid">
              <div>
                <span className="eyebrow">EVIDENCE REFERENCES</span>
                <div className="result-chip-list">
                  {evidence.length ? evidence.map((item) => <Chip key={item}>{item}</Chip>) : <span className="result-empty-inline">No grounding references returned.</span>}
                </div>
              </div>
              <div>
                <span className="eyebrow">MODEL</span>
                {model && Object.keys(model).length > 0 ? (
                  <div className="result-kv-list">
                    {Object.entries(model).map(([key, value]) => <div key={key}><span>{prettyKey(key)}</span><strong>{typeof value === 'object' ? JSON.stringify(value) : String(value || '—')}</strong></div>)}
                  </div>
                ) : <span className="result-empty-inline">Model metadata was not supplied.</span>}
              </div>
              <div>
                <span className="eyebrow">ATTACHMENT ANALYSIS</span>
                <div className="result-kv-list">
                  <div><span>Risk detected</span><strong>{attachments?.attachment_risk_detected ? 'YES' : 'NO'}</strong></div>
                  <div><span>Malicious attachment</span><strong>{attachments?.malicious_attachment_detected ? 'YES' : 'NO'}</strong></div>
                  <div><span>Findings</span><strong>{attachments?.attachment_findings?.length ?? 0}</strong></div>
                </div>
              </div>
              {unsupported.length > 0 && (
                <div className="result-unsupported">
                  <span className="eyebrow">UNSUPPORTED CLAIMS</span>
                  <ul>{unsupported.map((item) => <li key={item}>{item}</li>)}</ul>
                </div>
              )}
            </div>
          )}
        </section>
      )}
    </>
  );
}
