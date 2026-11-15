/* ==========================================================================
   VerdictBadge — renders backend.verdict, unchanged.
   --------------------------------------------------------------------------
   The five values come from logic/verdict.py. This component chooses type and
   colour for them and nothing else. CRITICAL and MALICIOUS are both red; they
   are distinguished by weight, MALICIOUS being the only one filled solid.
   ========================================================================== */

import type { Verdict } from '../types/analysis';
import { verdictTone } from '../lib/severity';
import { Badge } from './primitives';

export function VerdictBadge({ verdict }: { verdict: Verdict | string }) {
  return <Badge tone={verdictTone(verdict)}>{verdict}</Badge>;
}

/** The dominant display treatment used at the top of a report. */
export function VerdictDisplay({ verdict }: { verdict: Verdict | string }) {
  const tone = verdictTone(verdict);
  const isMalicious = String(verdict).toUpperCase() === 'MALICIOUS';

  return (
    <div>
      <div className="eyebrow">Verdict</div>
      <div
        className={`mt-2 inline-flex items-center rounded-md border px-4 py-2.5 ${tone.border} ${
          isMalicious ? tone.solid : tone.bg
        }`}
      >
        <span
          className={`font-display text-[26px] font-bold leading-none tracking-[0.01em] ${
            isMalicious ? 'text-white' : tone.text
          }`}
        >
          {verdict}
        </span>
      </div>
    </div>
  );
}
