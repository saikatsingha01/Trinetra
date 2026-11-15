/* ==========================================================================
   RiskScore — the report's signature element.
   --------------------------------------------------------------------------
   WHY A LADDER AND NOT A GAUGE
   The engine returns not just a score but the band table it used
   (verdict_info.thresholds, e.g. { HIGH: "41-60" }). A dial would throw that
   away. The ladder plots the score against the real bands, so an analyst can
   see at a glance not only how bad it is but how close it sits to the next
   verdict up — which is the question they actually ask when triaging.

   The frontend NEVER computes the score or the verdict. It reads
   backend.risk_score, backend.verdict, and the backend's own band strings.
   If verdict_info is absent it degrades to a plain bar rather than guessing
   at thresholds.
   ========================================================================== */

import type { Verdict, VerdictInfo } from '../types/analysis';
import { VERDICTS } from '../types/analysis';
import { verdictTone } from '../lib/severity';

interface Band {
  verdict: Verdict;
  min: number;
  max: number;
}

/**
 * Reads the backend's band strings ("21-40") into numbers. Returns null if the
 * table is missing or unparseable, so the caller can fall back rather than
 * invent boundaries.
 */
function parseBands(info: VerdictInfo | undefined): Band[] | null {
  if (!info?.thresholds) return null;

  const bands: Band[] = [];
  for (const verdict of VERDICTS) {
    const raw = info.thresholds[verdict];
    if (typeof raw !== 'string') continue;
    const match = raw.match(/^\s*(\d+)\s*-\s*(\d+)\s*$/);
    if (!match) continue;
    const min = Number(match[1]);
    const max = Number(match[2]);
    if (Number.isNaN(min) || Number.isNaN(max) || max < min) continue;
    bands.push({ verdict, min, max });
  }

  return bands.length === VERDICTS.length ? bands : null;
}

export function RiskScore({
  score,
  verdict,
  verdictInfo,
}: {
  score: number;
  verdict: Verdict | string;
  verdictInfo?: VerdictInfo;
}) {
  const tone = verdictTone(verdict);
  const bands = parseBands(verdictInfo);
  const active = String(verdict).toUpperCase();
  const clamped = Math.min(100, Math.max(0, score));

  return (
    <div>
      <div className="eyebrow risk-score-label">Risk score</div>

      <div className="mt-2 flex items-baseline gap-1.5">
        <span
          className={`font-display text-[46px] font-bold leading-none tracking-[-0.03em] tabular ${tone.text}`}
        >
          {score}
        </span>
        <span className="font-display text-[18px] font-medium leading-none text-ink-4 tabular">
          / 100
        </span>
      </div>

      {bands ? (
        <div className="mt-5">
          {/* The five bands, widths proportional to their real spans. */}
          <div
            className="relative flex h-2 gap-[2px]"
            role="img"
            aria-label={`Risk score ${score} of 100, in the ${active} band`}
          >
            {bands.map((band) => {
              const bandTone = verdictTone(band.verdict);
              const isActive = band.verdict === active;
              return (
                <div
                  key={band.verdict}
                  style={{ flexGrow: band.max - band.min + 1 }}
                  className={`overflow-hidden rounded-[2px] ${
                    isActive ? bandTone.solid : `${bandTone.bg} opacity-60`
                  }`}
                />
              );
            })}

            {/* Marker at the reported score. */}
            <div
              className="pointer-events-none absolute -top-1 bottom-[-4px] w-[2px] bg-ink"
              style={{ left: `calc(${clamped}% - 1px)` }}
            />
          </div>

          {/* Band labels. The active one is named in full. */}
          <div className="mt-2 flex gap-[2px]">
            {bands.map((band) => {
              const bandTone = verdictTone(band.verdict);
              const isActive = band.verdict === active;
              return (
                <div
                  key={band.verdict}
                  style={{ flexGrow: band.max - band.min + 1 }}
                  className="min-w-0"
                >
                  <div
                    className={`truncate text-[9.5px] font-semibold uppercase tracking-[0.07em] ${
                      isActive ? bandTone.text : 'text-ink-4'
                    }`}
                  >
                    {band.verdict}
                  </div>
                  <div className="datum text-[9.5px] tabular text-ink-4">
                    {band.min}–{band.max}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        // No band table from the backend — show the score alone.
        <div className="mt-5">
          <div className="h-2 overflow-hidden rounded-full bg-inset">
            <div
              className={`h-full rounded-full ${tone.solid}`}
              style={{ width: `${clamped}%` }}
            />
          </div>
          <p className="mt-2 text-[11px] text-ink-4">
            Verdict bands were not included in the response.
          </p>
        </div>
      )}
    </div>
  );
}
