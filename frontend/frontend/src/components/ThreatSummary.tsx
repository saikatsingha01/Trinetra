/* ==========================================================================
   ThreatSummary — the one-line answer, directly under the verdict.
   --------------------------------------------------------------------------
   This is a tally of findings the backend already classified, grouped by the
   severity IT assigned (CorrelationReason.severity). No finding is reweighted
   or reinterpreted here, and a bucket with nothing in it is not shown.
   ========================================================================== */

import type { AnalysisReport, Severity } from '../types/analysis';
import { SEVERITY_ORDER, severityTone } from '../lib/severity';
import { pluralize } from '../lib/format';

export function ThreatSummary({ report }: { report: AnalysisReport }) {
  const counts = new Map<Severity, number>();
  for (const reason of report.reasons ?? []) {
    const key = (reason.severity ?? '').toLowerCase() as Severity;
    if (!SEVERITY_ORDER.includes(key)) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const indicators = report.security_analysis?.suspicious_indicators?.length ?? 0;
  const present = SEVERITY_ORDER.filter((s) => (counts.get(s) ?? 0) > 0);

  if (present.length === 0 && indicators === 0) {
    return (
      <p className="text-[12.5px] text-ink-3">
        The engine returned no findings for this email.
      </p>
    );
  }

  return (
    <div>
      <div className="eyebrow">Threat summary</div>
      <ul className="mt-2.5 flex flex-wrap items-center gap-x-5 gap-y-2">
        {present.map((severity) => {
          const count = counts.get(severity) ?? 0;
          const tone = severityTone(severity);
          return (
            <li key={severity} className="flex items-baseline gap-2">
              <span className={`font-display text-[19px] font-semibold tabular ${tone.text}`}>
                {count}
              </span>
              <span className="text-[12.5px] text-ink-2">
                {tone.label} {pluralize(count, 'finding')}
              </span>
            </li>
          );
        })}

        {indicators > 0 && (
          <li className="flex items-baseline gap-2">
            <span className="font-display text-[19px] font-semibold tabular text-ink-2">
              {indicators}
            </span>
            <span className="text-[12.5px] text-ink-2">
              suspicious {pluralize(indicators, 'indicator')}
            </span>
          </li>
        )}
      </ul>
    </div>
  );
}
