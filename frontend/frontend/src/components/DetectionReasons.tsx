/* ==========================================================================
   DetectionReasons — renders backend.reasons.
   --------------------------------------------------------------------------
   Grouped by the severity the backend assigned, worst first. `evidence_sources`
   names which analysis block supported the finding, which is how an analyst
   decides whether to trust it — so it is shown, not hidden.
   ========================================================================== */

import type { DetectionReason, Severity } from '../types/analysis';
import { SEVERITY_ORDER, severityTone } from '../lib/severity';
import { humanizeToken } from '../lib/format';
import { Badge, Chip, EmptyNote, Section } from './primitives';

export function DetectionReasons({ reasons }: { reasons: DetectionReason[] }) {
  if (!reasons || reasons.length === 0) {
    return (
      <Section title="Detection reasons">
        <EmptyNote>No detection reasons were returned.</EmptyNote>
      </Section>
    );
  }

  // Group without reordering within a group, so the engine's own order survives.
  const groups = SEVERITY_ORDER.map((severity) => ({
    severity,
    items: reasons.filter((r) => (r.severity ?? '').toLowerCase() === severity),
  })).filter((g) => g.items.length > 0);

  const ungrouped = reasons.filter(
    (r) => !SEVERITY_ORDER.includes((r.severity ?? '').toLowerCase() as Severity),
  );

  return (
    <Section
      title="Detection reasons"
      count={reasons.length}
      caption="Each reason names the analysis block that supplied its evidence."
    >
      {groups.map(({ severity, items }) => {
        const tone = severityTone(severity);
        return (
          <div key={severity} className="border-b border-line last:border-b-0">
            <div className="flex items-center gap-2.5 bg-inset px-5 py-2">
              <Badge tone={tone}>{tone.label}</Badge>
              <span className="datum text-[11px] tabular text-ink-4">{items.length}</span>
            </div>

            <ul>
              {items.map((reason, i) => (
                <li
                  key={`${severity}-${i}`}
                  className="flex gap-3 border-b border-line px-5 py-3 last:border-b-0"
                >
                  <span
                    className={`mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full ${tone.solid}`}
                    aria-hidden="true"
                  />
                  <div className="min-w-0">
                    <p className="text-[13px] leading-snug text-ink">{reason.description}</p>
                    {reason.evidence_sources?.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {reason.evidence_sources.map((source) => (
                          <Chip key={source}>{humanizeToken(source)}</Chip>
                        ))}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        );
      })}

      {/* A severity the frontend does not recognise is still shown, not dropped. */}
      {ungrouped.length > 0 && (
        <ul className="border-t border-line">
          {ungrouped.map((reason, i) => (
            <li key={`other-${i}`} className="border-b border-line px-5 py-3 last:border-b-0">
              <p className="text-[13px] leading-snug text-ink">{reason.description}</p>
              <span className="datum mt-1 block text-[11px] text-ink-4">
                Unrecognised severity: {reason.severity ?? '—'}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
