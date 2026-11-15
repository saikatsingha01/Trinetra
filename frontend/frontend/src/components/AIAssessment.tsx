/* ==========================================================================
   AIAssessmentPanel — renders backend.ai_assessment.
   --------------------------------------------------------------------------
   Probabilities arrive as 0.0-1.0 floats and are shown as percentages. The
   band colours mirror the thresholds the backend already uses when deciding
   whether to fire a rule (logic/rules.py) — they are LABELS for the
   backend's number, not a second opinion about it.

   The explanation is set in the body face rather than mono: it is a model's
   commentary, not measured evidence, and the type should say so.
   ========================================================================== */

import type { AIAssessment } from '../types/analysis';
import type { Tone } from '../lib/severity';
import { flagTone, severityTone } from '../lib/severity';
import { formatProbability, humanizeToken } from '../lib/format';
import { Badge, Chip, EmptyNote, Meter, Section } from './primitives';

/* Mirrors logic/rules.py thresholds. Display banding only. */
const THRESHOLDS = {
  phishing: 0.7,
  bec: 0.6,
  social_engineering: 0.7,
} as const;

function probabilityTone(value: number, threshold: number): Tone {
  if (value >= threshold) return severityTone(value >= 0.85 ? 'critical' : 'high');
  if (value >= threshold * 0.7) return severityTone('medium');
  return severityTone('low');
}

function ProbabilityRow({
  label,
  value,
  threshold,
}: {
  label: string;
  value: number;
  threshold: number;
}) {
  const tone = probabilityTone(value, threshold);
  const over = value >= threshold;

  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-display text-[12.5px] font-medium text-ink">{label}</span>
        <span className={`datum text-[13px] tabular ${tone.text}`}>
          {formatProbability(value)}
        </span>
      </div>
      <Meter value={value} max={1} tone={tone} className="mt-1.5" />
      <div className="mt-1.5 text-[11px] text-ink-4">
        Backend threshold {formatProbability(threshold)}
        {over ? ' — exceeded' : ' — not exceeded'}
      </div>
    </div>
  );
}

export function AIAssessmentPanel({ data, unavailable = false }: { data?: AIAssessment | null; unavailable?: boolean }) {
  if (unavailable) {
    return (
      <Section title="AI assessment">
        <div className="ai-unavailable-note">
          <strong>Ollama assessment unavailable.</strong> Saikat returned <span>OLLAMA Failed</span>, so no AI signal was used in this report.
        </div>
      </Section>
    );
  }

  if (!data) {
    return (
      <Section title="AI assessment">
        <EmptyNote>The response did not include an AI assessment.</EmptyNote>
      </Section>
    );
  }

  const flags = [
    { label: 'Urgency', value: data.urgency_detected },
    { label: 'Credential request', value: data.credential_request_detected },
    { label: 'Financial request', value: data.financial_request_detected },
  ];

  const modelInfo = data.model_info
    ? Object.entries(data.model_info).filter(([, v]) => v !== null && v !== undefined)
    : [];

  return (
    <Section title="AI assessment">
      {/* --- probabilities -------------------------------------------------- */}
      <div className="grid gap-6 px-5 py-5 sm:grid-cols-3">
        <ProbabilityRow
          label="Phishing"
          value={data.phishing_probability}
          threshold={THRESHOLDS.phishing}
        />
        <ProbabilityRow
          label="BEC"
          value={data.bec_probability}
          threshold={THRESHOLDS.bec}
        />
        <ProbabilityRow
          label="Social engineering"
          value={data.social_engineering_probability}
          threshold={THRESHOLDS.social_engineering}
        />
      </div>

      {/* --- boolean flags -------------------------------------------------- */}
      <div className="border-t border-line px-5 py-5">
        <span className="eyebrow">Detected behaviour</span>
        <div className="mt-2.5 flex flex-wrap gap-2">
          {flags.map((flag) => {
            const tone = flagTone(flag.value);
            return (
              <Badge key={flag.label} tone={tone}>
                {flag.label}
                <span className={flag.value ? '' : 'text-ink-4'}>
                  {flag.value ? 'yes' : 'no'}
                </span>
              </Badge>
            );
          })}
        </div>
      </div>

      {/* --- patterns and language ----------------------------------------- */}
      {(data.detected_patterns.length > 0 || data.suspicious_language.length > 0) && (
        <div className="grid gap-5 border-t border-line px-5 py-5 sm:grid-cols-2">
          {data.detected_patterns.length > 0 && (
            <div>
              <span className="eyebrow">Patterns</span>
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {data.detected_patterns.map((pattern) => (
                  <Chip key={pattern}>{humanizeToken(pattern)}</Chip>
                ))}
              </div>
            </div>
          )}

          {data.suspicious_language.length > 0 && (
            <div>
              <span className="eyebrow">Suspicious language</span>
              {/* Quoted email text — kept verbatim and clearly marked as a quote. */}
              <ul className="mt-2.5 space-y-1.5">
                {data.suspicious_language.map((phrase) => (
                  <li
                    key={phrase}
                    className="border-l-2 border-line-strong pl-2.5 text-[12.5px] italic text-ink-2"
                  >
                    “{phrase}”
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* --- explanation ---------------------------------------------------- */}
      {data.explanation && (
        <div className="border-t border-line px-5 py-5">
          <span className="eyebrow">Model explanation</span>
          <p className="mt-2 max-w-[68ch] text-[13px] leading-relaxed text-ink-2">
            {data.explanation}
          </p>
        </div>
      )}

      {/* --- provenance ----------------------------------------------------- */}
      {modelInfo.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-line px-5 py-3">
          {modelInfo.map(([key, value]) => (
            <span key={key} className="datum text-[11px] text-ink-4">
              <span className="text-ink-3">{humanizeToken(key)}:</span> {String(value)}
            </span>
          ))}
        </div>
      )}

      {modelInfo.length === 0 && (
        <div className="border-t border-line px-5 py-3">
          <span className="datum text-[11px] text-ink-4">
            The model that produced this assessment was not identified in the response.
          </span>
        </div>
      )}
    </Section>
  );
}
