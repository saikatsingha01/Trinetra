/* ==========================================================================
   TriggeredRulesTable — renders the top-level backend.triggered_rules array.
   --------------------------------------------------------------------------
   Collapsed by default, per the brief: this is the audit trail an analyst
   opens when they want to argue with the score. Ordered by the weight the
   backend assigned, heaviest first, because that is the order in which the
   score was built. Weights are displayed, never summed here.
   ========================================================================== */

import type { TriggeredRule } from '../types/analysis';
import { Disclosure, EmptyNote } from './primitives';

export function TriggeredRulesTable({ rules }: { rules: TriggeredRule[] }) {
  if (!rules || rules.length === 0) {
    return (
      <Disclosure title="Triggered rules" count={0}>
        <EmptyNote>No rules fired for this email.</EmptyNote>
      </Disclosure>
    );
  }

  const ordered = [...rules].sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0));

  return (
    <Disclosure title="Triggered rules" count={rules.length}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-line">
              <th scope="col" className="eyebrow px-5 py-2.5 font-semibold">
                Rule
              </th>
              <th scope="col" className="eyebrow px-3 py-2.5 text-right font-semibold">
                Weight
              </th>
              <th scope="col" className="eyebrow px-5 py-2.5 font-semibold">
                Evidence
              </th>
            </tr>
          </thead>
          <tbody>
            {ordered.map((rule) => (
              <tr key={rule.rule_id} className="border-b border-line last:border-b-0">
                <td className="px-5 py-3 align-top">
                  <div className="datum text-[12px] text-ink">{rule.rule_id}</div>
                  <div className="mt-0.5 text-[12.5px] leading-snug text-ink-2">
                    {rule.description}
                  </div>
                </td>
                <td className="px-3 py-3 align-top text-right">
                  <span className="datum text-[13px] tabular text-ink">{rule.weight}</span>
                </td>
                <td className="datum px-5 py-3 align-top text-[11.5px] leading-relaxed text-ink-3">
                  {rule.evidence || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Disclosure>
  );
}
