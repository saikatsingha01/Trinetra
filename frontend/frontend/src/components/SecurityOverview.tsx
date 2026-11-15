import type { AnalysisReport } from '../types/analysis';
import { verdictTone } from '../lib/severity';
import { ThreatSummary } from './ThreatSummary';
import { formatDateTime, formatDuration } from '../lib/format';
import { IconClock } from './icons';
import { VerdictDisplay } from './VerdictBadge';

function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="result-stat"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

export function SecurityOverview({ report }: { report: AnalysisReport }) {
  const tone = verdictTone(report.verdict);
  const score = Math.max(0, Math.min(100, Number(report.risk_score) || 0));
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const dash = (score / 100) * circumference;
  const ipCount = report.threat_intelligence?.ips?.length ?? 0;
  const urlCount = report.threat_intelligence?.urls?.length ?? 0;
  const domainCount = report.threat_intelligence?.domains?.length ?? 0;
  const hashCount = report.threat_intelligence?.hashes?.length ?? 0;
  const confidence = report.analysis_confidence;
  const confidenceDefinitions: Record<string, string> = {
    evidence_coverage: 'How much of the expected email and security evidence was available.',
    signal_agreement: 'Whether independent signals support the same conclusion rather than contradicting each other.',
    provider_coverage: 'How much useful external reputation or enrichment evidence was available for indicators.',
    authentication_consistency: 'How consistently SPF, DKIM, DMARC and related authentication evidence agree.',
    grounding_quality: 'How well the AI assessment, when available, is tied back to collected evidence.',
    verdict_stability: 'How far the risk score is from a verdict boundary; near-boundary scores are less stable.',
    ai_availability: 'Whether the independent Ollama assessment was successfully incorporated.',
  };

  return (
    <section className="result-overview">
      <div className="result-overview__topline">
        <div>
          <div className="eyebrow">THREAT ASSESSMENT / COMPLETED</div>
          <h1>Security assessment</h1>
          <p>{report.email?.subject || report.source_file?.filename || 'Analyzed email message'}</p>
        </div>
        <div className="result-overview__meta">
          {report.analyzed_at && <span>{formatDateTime(report.analyzed_at)}</span>}
          <span><IconClock size={13} /> {formatDuration(report.processing_time_ms)}</span>
        </div>
      </div>

      <div className="result-overview__grid">
        <div className={`result-verdict-card ${tone.border}`}>
          <div className="result-verdict-card__label">FINAL VERDICT</div>
          <div className="result-verdict-card__value"><VerdictDisplay verdict={report.verdict} /></div>
          <p>The verdict and score below are the values returned by the connected analysis engine.</p>
          <div className="result-verdict-card__case"><span>CASE</span><strong>{report.case_id}</strong></div>
          <div className="result-verdict-card__summary"><ThreatSummary report={report} /></div>
        </div>

        <div className="result-score-card result-score-card--split">
          <div className="result-metric-box result-metric-box--risk">
            <div className="result-score-card__label">RISK SCORE</div>
            <div className="result-score-card__copy"><span>{score}</span><small>/ 100</small></div>
            <div className="result-score-ring" aria-label={`Risk score ${score} out of 100`}>
              <svg viewBox="0 0 140 140" aria-hidden="true">
                <circle className="result-score-ring__track" cx="70" cy="70" r={radius} />
                <circle className="result-score-ring__value" cx="70" cy="70" r={radius} strokeDasharray={`${dash} ${circumference - dash}`} />
              </svg>
              <div className="result-score-ring__center"><strong>{score}</strong><span>RISK</span></div>
            </div>
            <p className="result-risk-description">The risk score measures the severity of security and threat signals detected in this email. Higher values indicate stronger evidence of risk.</p>
          </div>

          <div className="result-metric-box result-metric-box--confidence">
            <div className="result-confidence__head">
              <div>
                <div className="result-score-card__label">ANALYSIS CONFIDENCE</div>
                <strong>{confidence ? `${confidence.score}%` : '—'}</strong>
              </div>
              <span className="result-confidence__label">{confidence?.label ?? 'Not available'}</span>
            </div>
            <div className="result-confidence__bar"><span style={{ width: `${Math.max(0, Math.min(100, confidence?.score ?? 0))}%` }} /></div>
            <div className="result-confidence__reason-box">
              <div className="result-confidence__reason-title">WHY THIS CONFIDENCE SCORE?</div>
              <p className="result-confidence__explanation">
                Confidence tells you how strongly the available evidence supports the risk decision. It is <strong>not</strong> the probability that the email is safe or malicious. It reflects evidence coverage, agreement between independent signals, provider coverage, authentication consistency, grounding quality, verdict stability, and AI availability.
                {report.analysis_mode === 'subhom_only' ? ' Ollama AI assessment failed, so the independent AI signal is missing; confidence is intentionally lower. Re-upload the email for a more precise result.' : ''}
              </p>
            </div>
            {confidence && <div className="result-confidence__factors">{Object.entries(confidence.factors).map(([key, value]) => <div key={key}><span>{key.replace(/_/g, ' ')}</span><strong>{value}%</strong><small>{confidenceDefinitions[key] ?? 'Evidence quality factor used by the confidence model.'}</small></div>)}</div>}
            {confidence?.rationale?.length ? <ul className="result-confidence__rationale">{confidence.rationale.map((reason) => <li key={reason}>{reason}</li>)}</ul> : null}
          </div>
        </div>

        <div className="result-stat-grid">
          <Stat label="INDICATORS" value={String(ipCount + domainCount + urlCount + hashCount)} detail="IPs / domains / URLs / hashes" />
          <Stat label="RULES" value={String(report.triggered_rules?.length ?? 0)} detail="Triggered by engine" />
          <Stat label="CORRELATIONS" value={String(report.correlations?.length ?? 0)} detail="Cross-signal findings" />
          <Stat label="PROCESSING" value={formatDuration(report.processing_time_ms)} detail="Engine processing time" />
        </div>
      </div>
    </section>
  );
}
