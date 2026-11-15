/* ==========================================================================
   ScoreBreakdownPanel — renders backend.score_breakdown, collapsed by default.
   --------------------------------------------------------------------------
   Two naming traps in the engine's flattened dict, both handled here:
     - the ceiling key is `max_possible`, not `max_possible_score`
     - `score_breakdown.triggered_rules` is a COUNT, while the top-level
       `triggered_rules` is an array of rule objects

   The arithmetic (raw -> normalized, by `method`) is the backend's. This panel
   shows the inputs and the result side by side so the normalisation is legible,
   but it never recomputes either number.
   ========================================================================== */

import type { ScoreBreakdown } from '../types/analysis';
import { severityTone } from '../lib/severity';
import { humanizeToken } from '../lib/format';
import { Chip, Disclosure, Field, Meter } from './primitives';

export function ScoreBreakdownPanel({ breakdown }: { breakdown?: ScoreBreakdown }) {
  if (!breakdown) return null;

  const categories = Object.entries(breakdown.category_scores ?? {});

  // Bars are drawn relative to the biggest category in THIS response, so the
  // comparison is between categories rather than against an invented ceiling.
  const peak = categories.reduce((max, [, c]) => Math.max(max, c.score ?? 0), 0);

  const contributing = categories
    .filter(([, c]) => (c.score ?? 0) > 0)
    .sort((a, b) => (b[1].score ?? 0) - (a[1].score ?? 0));
  const quiet = categories.filter(([, c]) => (c.score ?? 0) === 0);

  return (
    <Disclosure
      title="Score breakdown"
      summary={`raw ${breakdown.raw_score} → ${breakdown.normalized_score}`}
    >
      {/* --- the four numbers ---------------------------------------------- */}
      <div className="grid gap-5 border-b border-line px-5 py-5 sm:grid-cols-4">
        <Field label="Raw score" value={String(breakdown.raw_score)} />
        <Field label="Max possible" value={String(breakdown.max_possible)} />
        <Field label="Normalized" value={String(breakdown.normalized_score)} />
        <Field label="Method" value={breakdown.method} />
      </div>

      <div className="border-b border-line px-5 py-3">
        <span className="text-[12px] text-ink-3">
          <span className="datum tabular text-ink">{breakdown.triggered_rules}</span> of{' '}
          <span className="datum tabular text-ink">{breakdown.total_rules}</span> rules fired.
          Normalisation to a 0–100 score was performed by the backend using the{' '}
          <span className="datum">{breakdown.method}</span> method.
        </span>
      </div>

      {/* --- per-category contribution ------------------------------------- */}
      {contributing.length > 0 && (
        <div className="px-5 py-5">
          <span className="eyebrow">Contributing categories</span>
          <ul className="mt-3 space-y-4">
            {contributing.map(([name, category]) => {
              // Tone tracks how much of this response's weight sits here.
              const share = peak > 0 ? category.score / peak : 0;
              const tone = severityTone(
                share >= 0.75 ? 'critical' : share >= 0.5 ? 'high' : share >= 0.25 ? 'medium' : 'low',
              );

              return (
                <li key={name}>
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="font-display text-[12.5px] font-medium text-ink">
                      {humanizeToken(name)}
                    </span>
                    <span className="datum shrink-0 text-[12px] tabular text-ink-2">
                      {category.score}
                      <span className="text-ink-4">
                        {' '}
                        · {category.triggered}/{category.total} rules
                      </span>
                    </span>
                  </div>
                  <Meter value={category.score} max={peak} tone={tone} className="mt-1.5" />
                  {category.rules?.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {category.rules.map((rule) => (
                        <Chip key={rule}>{rule}</Chip>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* --- categories that scored nothing -------------------------------- */}
      {quiet.length > 0 && (
        <div className="border-t border-line px-5 py-4">
          <span className="eyebrow">Scored zero</span>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {quiet.map(([name]) => (
              <Chip key={name}>{humanizeToken(name)}</Chip>
            ))}
          </div>
        </div>
      )}

      {categories.length === 0 && (
        <p className="px-5 py-5 text-[12.5px] text-ink-3">
          The response did not include category scores.
        </p>
      )}
    </Disclosure>
  );
}
