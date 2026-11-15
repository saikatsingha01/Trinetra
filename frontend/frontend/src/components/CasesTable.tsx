/* ==========================================================================
   CasesTable — the analyst's list.
   --------------------------------------------------------------------------
   Columns follow the brief: Case ID, Sender, Subject, Risk Score, Verdict,
   Processing Time, Date, Action. Rows are shown in the order the backend
   returned them; sorting is a display choice offered on the Cases page.
   ========================================================================== */

import { Link } from 'react-router-dom';
import type { CaseSummary } from '../types/analysis';
import { verdictTone } from '../lib/severity';
import { formatDateTime, formatDuration, truncateEnd } from '../lib/format';
import { VerdictBadge } from './VerdictBadge';
import { IconArrowRight } from './icons';

export function CasesTable({ rows }: { rows: CaseSummary[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] border-collapse text-left">
        <thead>
          <tr className="border-b border-line">
            <th scope="col" className="eyebrow px-5 py-2.5 font-semibold">
              Case ID
            </th>
            <th scope="col" className="eyebrow px-3 py-2.5 font-semibold">
              Sender
            </th>
            <th scope="col" className="eyebrow px-3 py-2.5 font-semibold">
              Subject
            </th>
            <th scope="col" className="eyebrow px-3 py-2.5 text-right font-semibold">
              Risk
            </th>
            <th scope="col" className="eyebrow px-3 py-2.5 font-semibold">
              Verdict
            </th>
            <th scope="col" className="eyebrow px-3 py-2.5 text-right font-semibold">
              Time
            </th>
            <th scope="col" className="eyebrow px-3 py-2.5 font-semibold">
              Date
            </th>
            <th scope="col" className="eyebrow px-5 py-2.5 text-right font-semibold">
              Action
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const tone = verdictTone(row.verdict);
            return (
              <tr
                key={row.case_id}
                className="border-b border-line transition-colors last:border-b-0 hover:bg-raised/50"
              >
                <td className="px-5 py-3">
                  <Link
                    to={`/cases/${encodeURIComponent(row.case_id)}`}
                    className="datum text-[12px] text-ink transition-colors hover:text-steel-hi"
                  >
                    {row.case_id}
                  </Link>
                </td>
                <td className="datum max-w-[190px] truncate px-3 py-3 text-[12px] text-ink-2">
                  {row.sender ?? '—'}
                </td>
                <td className="max-w-[260px] px-3 py-3 text-[12.5px] text-ink-2">
                  {row.subject ? truncateEnd(row.subject, 64) : '—'}
                </td>
                <td className="px-3 py-3 text-right">
                  <span className={`datum text-[13px] font-semibold tabular ${tone.text}`}>
                    {row.risk_score}
                  </span>
                </td>
                <td className="px-3 py-3">
                  <VerdictBadge verdict={row.verdict} />
                </td>
                <td className="datum px-3 py-3 text-right text-[11.5px] tabular text-ink-3">
                  {formatDuration(row.processing_time_ms)}
                </td>
                <td className="datum px-3 py-3 text-[11.5px] text-ink-3">
                  {row.analyzed_at ? formatDateTime(row.analyzed_at) : '—'}
                </td>
                <td className="px-5 py-3 text-right">
                  <Link
                    to={`/cases/${encodeURIComponent(row.case_id)}`}
                    className="inline-flex items-center gap-1.5 font-display text-[11.5px] font-medium text-steel-hi transition-colors hover:text-ink"
                  >
                    View report
                    <IconArrowRight size={13} />
                  </Link>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
