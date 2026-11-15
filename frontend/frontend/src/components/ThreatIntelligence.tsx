/* ==========================================================================
   ThreatIntelligencePanel — renders backend.threat_intelligence.
   --------------------------------------------------------------------------
   Four indicator classes, one tab each, counts on the tabs so an empty class
   is visible without clicking. Every number here is the backend's
   reputation_score; the frontend only labels which band it falls in
   (see lib/severity.ts, which mirrors the thresholds in logic/rules.py).

   reputation_score runs 0-100 and HIGHER IS WORSE, so the meter fills toward
   danger. That is easy to misread, hence the caption.
   ========================================================================== */

import { useState } from 'react';
import type { ReactNode } from 'react';
import type {
  DomainThreatIntel,
  HashThreatIntel,
  IPThreatIntel,
  ThreatIntelligence,
  URLThreatIntel,
} from '../types/analysis';
import { reputationTone, severityTone } from '../lib/severity';
import { formatDate, humanizeToken, truncateEnd } from '../lib/format';
import { Badge, Chip, EmptyNote, Field, Meter, Section } from './primitives';
import { IconGlobe, IconHash, IconLink, IconServer } from './icons';

type TabKey = 'ips' | 'domains' | 'urls' | 'hashes';

const TABS: { key: TabKey; label: string; Icon: typeof IconServer }[] = [
  { key: 'ips', label: 'IPs', Icon: IconServer },
  { key: 'domains', label: 'Domains', Icon: IconGlobe },
  { key: 'urls', label: 'URLs', Icon: IconLink },
  { key: 'hashes', label: 'Hashes', Icon: IconHash },
];

/* -------------------------------------------------------------------------
   One indicator card. The identifier is the headline; reputation is the
   status; everything else is context the backend chose to send.
   ------------------------------------------------------------------------- */

function IndicatorCard({
  identifier,
  reputation,
  threatHistory,
  categories,
  children,
}: {
  identifier: string;
  reputation: number;
  threatHistory: boolean;
  categories: string[];
  children?: ReactNode;
}) {
  const reputationUnknown = categories.includes('reputation_unknown');
  const visibleCategories = categories.filter((category) => category !== 'reputation_unknown');
  const tone = reputationUnknown
    ? { ...reputationTone(0), label: 'Unknown' }
    : reputation === 0
      ? { ...reputationTone(0), label: 'No malicious reputation' }
      : reputationTone(reputation);

  return (
    <li className="border-b border-line px-5 py-4 last:border-b-0">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="datum min-w-0 break-all text-[13px] text-ink">{identifier}</div>
        <Badge tone={tone}>{tone.label}</Badge>
      </div>

      {/* Reputation: the backend's number, its band, and a bar. */}
      <div className="mt-3">
        <div className="flex items-baseline justify-between gap-3">
          <span className="eyebrow">Reputation</span>
          <span className={`datum text-[12px] tabular ${tone.text}`}>{reputationUnknown ? 'No result' : `${reputation} / 100`}</span>
        </div>
        <Meter value={reputationUnknown ? 0 : reputation} max={100} tone={tone} className="mt-1.5" />
      </div>

      {children}

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {threatHistory && <Badge tone={severityTone('high')}>Threat history</Badge>}
        {reputationUnknown && <Badge tone={tone}>No reputation result</Badge>}
        {visibleCategories.map((category) => (
          <Chip key={category}>{humanizeToken(category)}</Chip>
        ))}
        {!threatHistory && visibleCategories.length === 0 && !reputationUnknown && (
          <span className="text-[11.5px] text-ink-4">No categories reported.</span>
        )}
      </div>
    </li>
  );
}

/* -------------------------------------------------------------------------
   Per-class lists
   ------------------------------------------------------------------------- */

function IPList({ items }: { items: IPThreatIntel[] }) {
  return (
    <ul>
      {items.map((item) => (
        <IndicatorCard
          key={item.ip}
          identifier={item.ip}
          reputation={item.reputation_score}
          threatHistory={item.threat_history}
          categories={item.categories}
        >
          <div className="mt-3 grid gap-4 sm:grid-cols-3">
            <Field label="Country" value={item.country} />
            <Field label="ASN" value={item.asn} />
            <Field label="ISP" value={item.isp} mono={false} />
          </div>
        </IndicatorCard>
      ))}
    </ul>
  );
}

function DomainList({ items }: { items: DomainThreatIntel[] }) {
  return (
    <ul>
      {items.map((item) => (
        <IndicatorCard
          key={item.domain}
          identifier={item.domain}
          reputation={item.reputation_score}
          threatHistory={item.threat_history}
          categories={item.categories}
        >
          <div className="mt-3 grid gap-4 sm:grid-cols-3">
            <Field label="Country" value={item.country} />
            <Field label="Registrar" value={item.registrar} mono={false} />
            <Field label="Created" value={formatDate(item.creation_date)} />
          </div>
          {(item.analysis_stats || item.community_votes || item.community_reputation != null) && (
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              {item.community_reputation != null && <Field label="Community reputation" value={String(item.community_reputation)} />}
              {item.analysis_stats && <Field label="VT malicious / suspicious" value={`${item.analysis_stats.malicious ?? 0} / ${item.analysis_stats.suspicious ?? 0}`} />}
              {item.community_votes && <Field label="Community votes" value={`${item.community_votes.malicious ?? 0} malicious · ${item.community_votes.harmless ?? 0} harmless`} mono={false} />}
            </div>
          )}
        </IndicatorCard>
      ))}
    </ul>
  );
}

function URLList({ items }: { items: URLThreatIntel[] }) {
  return (
    <ul>
      {items.map((item) => (
        <IndicatorCard
          key={item.url}
          // URLs are shown in full but never rendered as a clickable link.
          identifier={item.url}
          reputation={item.reputation_score}
          threatHistory={item.threat_history}
          categories={item.categories}
        >
          <div className="mt-3">
            <Field label="Domain" value={item.domain} />
          </div>
        </IndicatorCard>
      ))}
    </ul>
  );
}

function HashList({ items }: { items: HashThreatIntel[] }) {
  return (
    <ul>
      {items.map((item) => (
        <IndicatorCard
          key={item.hash}
          identifier={truncateEnd(item.hash, 64)}
          reputation={item.reputation_score}
          threatHistory={item.threat_history}
          categories={item.categories}
        >
          <div className="mt-3">
            <Field label="Type" value={item.hash_type.toUpperCase()} />
          </div>
        </IndicatorCard>
      ))}
    </ul>
  );
}

/* -------------------------------------------------------------------------
   Panel
   ------------------------------------------------------------------------- */

export function ThreatIntelligencePanel({ data }: { data?: ThreatIntelligence | null }) {
  const [active, setActive] = useState<TabKey>('ips');

  if (!data) {
    return (
      <Section title="Threat intelligence">
        <EmptyNote>The response did not include threat intelligence.</EmptyNote>
      </Section>
    );
  }

  const counts: Record<TabKey, number> = {
    ips: data.ips?.length ?? 0,
    domains: data.domains?.length ?? 0,
    urls: data.urls?.length ?? 0,
    hashes: data.hashes?.length ?? 0,
  };
  const total = counts.ips + counts.domains + counts.urls + counts.hashes;

  return (
    <Section
      title="Threat intelligence"
      count={total}
      caption="Reputation scores are 0–100 as reported by the backend, where a higher score is worse."
    >
      {/* Tabs. A class with nothing in it stays reachable but reads as quiet. */}
      <div role="tablist" aria-label="Indicator type" className="flex border-b border-line">
        {TABS.map(({ key, label, Icon }) => {
          const isActive = key === active;
          const count = counts[key];
          return (
            <button
              key={key}
              role="tab"
              type="button"
              aria-selected={isActive}
              onClick={() => setActive(key)}
              className={`-mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 font-display text-[12px] font-medium transition-colors ${
                isActive
                  ? 'border-steel-hi text-ink'
                  : 'border-transparent text-ink-3 hover:text-ink-2'
              }`}
            >
              <Icon size={14} className={isActive ? 'text-steel-hi' : 'text-ink-4'} />
              {label}
              <span
                className={`datum rounded-sm px-1.5 py-0.5 text-[10.5px] tabular ${
                  count > 0 ? 'bg-inset text-ink-2' : 'text-ink-4'
                }`}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      <div role="tabpanel">
        {active === 'ips' &&
          (counts.ips > 0 ? (
            <IPList items={data.ips} />
          ) : (
            <EmptyNote>No IP addresses were submitted for this email.</EmptyNote>
          ))}
        {active === 'domains' &&
          (counts.domains > 0 ? (
            <DomainList items={data.domains} />
          ) : (
            <EmptyNote>No domains were submitted for this email.</EmptyNote>
          ))}
        {active === 'urls' &&
          (counts.urls > 0 ? (
            <URLList items={data.urls} />
          ) : (
            <EmptyNote>No URLs were submitted for this email.</EmptyNote>
          ))}
        {active === 'hashes' &&
          (counts.hashes > 0 ? (
            <HashList items={data.hashes} />
          ) : (
            <EmptyNote>No file hashes were submitted for this email.</EmptyNote>
          ))}
      </div>

      {total === 0 && (
        <p className="border-t border-line px-5 py-3 text-[11.5px] text-ink-4">
          An empty result means no indicators were looked up — not that the email is clean.
        </p>
      )}
    </Section>
  );
}
