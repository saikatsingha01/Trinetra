/* ==========================================================================
   Alert — inline error and notice block.
   --------------------------------------------------------------------------
   Errors state what happened and what to do about it, in the interface's
   voice. The user-facing sentence is fixed (see services/api.ts); the
   technical detail is available but folded away, because it helps whoever is
   running the server and confuses everyone else.
   ========================================================================== */

import { useState } from 'react';
import type { ReactNode } from 'react';
import { IconAlert, IconChevronRight } from './icons';

type AlertTone = 'error' | 'warning' | 'info';

const TONES: Record<AlertTone, { border: string; bg: string; icon: string; title: string }> = {
  error: {
    border: 'border-critical/40',
    bg: 'bg-critical/8',
    icon: 'text-critical',
    title: 'text-critical',
  },
  warning: {
    border: 'border-medium/35',
    bg: 'bg-medium/8',
    icon: 'text-medium',
    title: 'text-medium',
  },
  info: {
    border: 'border-line-strong',
    bg: 'bg-raised',
    icon: 'text-steel-hi',
    title: 'text-ink',
  },
};

export function Alert({
  tone = 'error',
  message,
  detail,
  action,
}: {
  tone?: AlertTone;
  message: string;
  detail?: string;
  action?: ReactNode;
}) {
  const [showDetail, setShowDetail] = useState(false);
  const style = TONES[tone];

  return (
    <div className={`rounded-md border px-4 py-3 ${style.border} ${style.bg}`} role="alert">
      <div className="flex items-start gap-2.5">
        <IconAlert size={15} className={`mt-px shrink-0 ${style.icon}`} />
        <div className="min-w-0 flex-1">
          <p className={`text-[13px] font-medium leading-snug ${style.title}`}>{message}</p>

          {detail && (
            <>
              <button
                type="button"
                onClick={() => setShowDetail((v) => !v)}
                aria-expanded={showDetail}
                className="mt-1.5 inline-flex items-center gap-1 text-[11.5px] text-ink-3 transition-colors hover:text-ink-2"
              >
                <IconChevronRight
                  size={12}
                  className={`transition-transform duration-150 ${showDetail ? 'rotate-90' : ''}`}
                />
                {showDetail ? 'Hide technical detail' : 'Technical detail'}
              </button>
              {showDetail && (
                <pre className="datum mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-line bg-inset px-2.5 py-2 text-[11px] text-ink-3">
                  {detail}
                </pre>
              )}
            </>
          )}
        </div>

        {action && <div className="shrink-0">{action}</div>}
      </div>
    </div>
  );
}
