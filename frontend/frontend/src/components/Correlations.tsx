/* ==========================================================================
   Correlations — renders backend.correlations.
   --------------------------------------------------------------------------
   The brief asks for a simple readable list, explicitly not an animated graph,
   and that is also the honest shape: the engine returns sentences, each one
   describing a link it found between two analysis blocks. It does not return
   node/edge data, so drawing a graph would mean inventing structure.

   When correlations_by_severity is present the list is grouped by it; when it
   is absent the flat list is shown in engine order.
   ========================================================================== */

import type { CorrelationsBySeverity, Severity } from '../types/analysis';
import { SEVERITY_ORDER, severityTone } from '../lib/severity';
import { Badge, EmptyNote, Section } from './primitives';

function CorrelationItem({ text, tone }: { text: string; tone: { solid: string } }) {
  return (
    <li className="flex gap-3 border-b border-line px-5 py-3 last:border-b-0">
      <span
        className={`mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full ${tone.solid}`}
        aria-hidden="true"
      />
      <p className="text-[13px] leading-snug text-ink">{text}</p>
    </li>
  );
}

export function Correlations({
  correlations,
  bySeverity,
}: {
  correlations: string[];
  bySeverity?: CorrelationsBySeverity;
}) {
  const total = correlations?.length ?? 0;

  if (total === 0) {
    return (
      <Section title="Correlations">
        <EmptyNote>
          The engine did not find any cross-signal correlations for this email.
        </EmptyNote>
      </Section>
    );
  }

  const groups = bySeverity
    ? SEVERITY_ORDER.map((severity) => ({
        severity,
        items: bySeverity[severity as Severity] ?? [],
      })).filter((g) => g.items.length > 0)
    : [];

  return (
    <Section
      title="Correlations"
      count={total}
      caption="Findings that reinforce each other across separate analysis blocks."
    >
      {groups.length > 0 ? (
        groups.map(({ severity, items }) => {
          const tone = severityTone(severity);
          return (
            <div key={severity} className="border-b border-line last:border-b-0">
              <div className="flex items-center gap-2.5 bg-inset px-5 py-2">
                <Badge tone={tone}>{tone.label}</Badge>
                <span className="datum text-[11px] tabular text-ink-4">{items.length}</span>
              </div>
              <ul>
                {items.map((text, i) => (
                  <CorrelationItem key={`${severity}-${i}`} text={text} tone={tone} />
                ))}
              </ul>
            </div>
          );
        })
      ) : (
        <ul>
          {correlations.map((text, i) => (
            <CorrelationItem key={i} text={text} tone={severityTone(null)} />
          ))}
        </ul>
      )}
    </Section>
  );
}
