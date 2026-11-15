/* ==========================================================================
   Shared UI primitives.
   Every report section is assembled from these, so spacing and type stay
   consistent without each section re-inventing them.
   ========================================================================== */

import type { ReactNode } from 'react';
import { useId, useState } from 'react';
import { IconChevronDown } from './icons';
import type { Tone } from '../lib/severity';

/* -------------------------------------------------------------------------
   Panel — the single container primitive.
   ------------------------------------------------------------------------- */

export function Panel({
  children,
  className = '',
  as: Tag = 'section',
}: {
  children: ReactNode;
  className?: string;
  as?: 'section' | 'div' | 'article';
}) {
  return (
    <Tag className={`rounded-md border border-line bg-panel ${className}`}>{children}</Tag>
  );
}

/* -------------------------------------------------------------------------
   Section — a titled report block. `count` is shown only when meaningful.
   ------------------------------------------------------------------------- */

export function Section({
  title,
  caption,
  count,
  action,
  children,
  className = '',
}: {
  title: string;
  caption?: string;
  count?: number;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Panel className={className}>
      <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-3.5">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <h2 className="font-display text-[13.5px] font-semibold tracking-[-0.01em] text-ink">
              {title}
            </h2>
            {count !== undefined && (
              <span className="datum rounded-sm bg-inset px-1.5 py-0.5 text-[10.5px] text-ink-3 tabular">
                {count}
              </span>
            )}
          </div>
          {caption && <p className="mt-1 text-[12px] leading-snug text-ink-3">{caption}</p>}
        </div>
        {action}
      </header>
      {children}
    </Panel>
  );
}

/* -------------------------------------------------------------------------
   Badge — small status chip. Tone comes from lib/severity.
   ------------------------------------------------------------------------- */

export function Badge({
  tone,
  children,
  mono = false,
  className = '',
}: {
  tone: Tone;
  children: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-sm border px-1.5 py-[3px] text-[10.5px] font-semibold uppercase tracking-[0.08em] ${
        mono ? 'font-mono' : ''
      } ${tone.text} ${tone.bg} ${tone.border} ${className}`}
    >
      {children}
    </span>
  );
}

/** Neutral chip for categories, patterns and other non-risk labels. */
export function Chip({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-sm border border-line-strong bg-inset px-1.5 py-[3px] font-mono text-[10.5px] text-ink-2 ${className}`}
    >
      {children}
    </span>
  );
}

/* -------------------------------------------------------------------------
   Field — a labelled value. `mono` marks machine-produced text.
   ------------------------------------------------------------------------- */

export function Field({
  label,
  value,
  mono = true,
  children,
  className = '',
}: {
  label: string;
  value?: ReactNode;
  mono?: boolean;
  children?: ReactNode;
  className?: string;
}) {
  const empty = value === null || value === undefined || value === '';
  return (
    <div className={className}>
      <div className="eyebrow">{label}</div>
      <div
        className={`mt-1 ${mono ? 'datum' : 'text-[13px] text-ink'} ${
          empty && !children ? 'text-ink-4' : ''
        }`}
      >
        {children ?? (empty ? '—' : value)}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------
   A single row of a status list: label on the left, badge on the right.
   ------------------------------------------------------------------------- */

export function StatusRow({
  label,
  tone,
  status,
  detail,
}: {
  label: string;
  tone: Tone;
  status: string;
  detail?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line px-5 py-3 last:border-b-0">
      <div className="min-w-0">
        <div className="font-display text-[12.5px] font-medium text-ink">{label}</div>
        {detail && <div className="datum mt-0.5 text-[11.5px] text-ink-3">{detail}</div>}
      </div>
      <Badge tone={tone}>{status}</Badge>
    </div>
  );
}

/* -------------------------------------------------------------------------
   Disclosure — expandable block. Used for Score Breakdown and Triggered
   Rules, which the brief asks to keep collapsed by default.
   ------------------------------------------------------------------------- */

export function Disclosure({
  title,
  summary,
  count,
  defaultOpen = false,
  children,
}: {
  title: string;
  summary?: string;
  count?: number;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();

  return (
    <Panel>
      <h2>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={panelId}
          className="flex w-full items-center justify-between gap-4 px-5 py-3.5 text-left transition-colors hover:bg-raised"
        >
          <span className="flex min-w-0 items-center gap-2.5">
            <span className="font-display text-[13.5px] font-semibold tracking-[-0.01em] text-ink">
              {title}
            </span>
            {count !== undefined && (
              <span className="datum rounded-sm bg-inset px-1.5 py-0.5 text-[10.5px] text-ink-3 tabular">
                {count}
              </span>
            )}
          </span>
          <span className="flex shrink-0 items-center gap-3">
            {summary && <span className="datum text-[11.5px] text-ink-3">{summary}</span>}
            <IconChevronDown
              size={15}
              className={`text-ink-3 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
            />
          </span>
        </button>
      </h2>
      {open && (
        <div id={panelId} className="border-t border-line">
          {children}
        </div>
      )}
    </Panel>
  );
}

/* -------------------------------------------------------------------------
   Empty note — states what is absent, without implying it is reassuring.
   ------------------------------------------------------------------------- */

export function EmptyNote({ children }: { children: ReactNode }) {
  return <p className="px-5 py-6 text-[12.5px] text-ink-3">{children}</p>;
}

/* -------------------------------------------------------------------------
   Meter — a plain horizontal bar. Width is a ratio of values the backend
   supplied; nothing is derived.
   ------------------------------------------------------------------------- */

export function Meter({
  value,
  max,
  tone,
  className = '',
}: {
  value: number;
  max: number;
  tone: Tone;
  className?: string;
}) {
  const pct = max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0;
  return (
    <div
      className={`h-1 overflow-hidden rounded-full bg-inset ${className}`}
      role="presentation"
    >
      <div
        className={`h-full rounded-full ${tone.solid} transition-[width] duration-500 ease-out`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

/* -------------------------------------------------------------------------
   Spinner + button
   ------------------------------------------------------------------------- */

export function Spinner({ size = 14, className = '' }: { size?: number; className?: string }) {
  return (
    <span
      className={`spin inline-block shrink-0 rounded-full border-2 border-current border-t-transparent ${className}`}
      style={{ width: size, height: size }}
      aria-hidden="true"
    />
  );
}

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

const BUTTON_STYLES: Record<ButtonVariant, string> = {
  primary:
    'bg-steel text-white hover:bg-steel-hi disabled:bg-line-strong disabled:text-ink-4 border border-transparent',
  secondary:
    'bg-raised text-ink border border-line-strong hover:border-ink-4 hover:bg-panel disabled:text-ink-4',
  ghost:
    'bg-transparent text-ink-2 border border-transparent hover:text-ink hover:bg-raised disabled:text-ink-4',
  danger:
    'bg-transparent text-critical border border-critical/40 hover:bg-critical/10 disabled:text-ink-4',
};

export function Button({
  variant = 'secondary',
  size = 'md',
  busy = false,
  children,
  className = '',
  ...rest
}: {
  variant?: ButtonVariant;
  size?: 'sm' | 'md' | 'lg';
  busy?: boolean;
  children: ReactNode;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const sizing =
    size === 'lg'
      ? 'h-11 px-6 text-[12px] tracking-[0.09em]'
      : size === 'sm'
        ? 'h-7 px-2.5 text-[11px] tracking-[0.05em]'
        : 'h-9 px-3.5 text-[11.5px] tracking-[0.06em]';

  return (
    <button
      {...rest}
      disabled={rest.disabled || busy}
      className={`inline-flex items-center justify-center gap-2 rounded-[5px] font-display font-semibold uppercase transition-colors duration-150 disabled:cursor-not-allowed ${sizing} ${BUTTON_STYLES[variant]} ${className}`}
    >
      {busy && <Spinner size={13} />}
      {children}
    </button>
  );
}
