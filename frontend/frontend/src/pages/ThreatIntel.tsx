/* ==========================================================================
   ThreatIntel — indicators collected from reports opened this session.
   --------------------------------------------------------------------------
   HONESTY NOTE
   TRINETRA does not expose a standalone threat-intelligence endpoint: intel
   arrives attached to an analysis. So this page does not query anything. It
   collects the indicators from reports already loaded in this session and
   presents them in one place.

   Where the same indicator appears in several reports, the entry with the
   worst reputation_score the backend reported is kept. Nothing is re-scored.
   ========================================================================== */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import type { ThreatIntelligence } from '../types/analysis';
import { Header } from '../components/Header';
import { ThreatIntelligencePanel } from '../components/ThreatIntelligence';
import { Alert } from '../components/Alert';
import { Button, Panel } from '../components/primitives';
import { IconUpload } from '../components/icons';
import { useSession } from '../store/session';

/** Keeps the worst-scored entry per identifier. */
function mergeBy<T>(groups: T[][], identify: (item: T) => string, score: (item: T) => number): T[] {
  const worst = new Map<string, T>();
  for (const group of groups) {
    for (const item of group) {
      const key = identify(item);
      const existing = worst.get(key);
      if (!existing || score(item) > score(existing)) worst.set(key, item);
    }
  }
  return [...worst.values()].sort((a, b) => score(b) - score(a));
}

export function ThreatIntel() {
  const { seenReports } = useSession();

  const aggregate = useMemo<ThreatIntelligence>(() => {
    const blocks = seenReports
      .map((r) => r.threat_intelligence)
      .filter((t): t is ThreatIntelligence => Boolean(t));

    return {
      ips: mergeBy(
        blocks.map((b) => b.ips ?? []),
        (i) => i.ip,
        (i) => i.reputation_score,
      ),
      domains: mergeBy(
        blocks.map((b) => b.domains ?? []),
        (d) => d.domain,
        (d) => d.reputation_score,
      ),
      urls: mergeBy(
        blocks.map((b) => b.urls ?? []),
        (u) => u.url,
        (u) => u.reputation_score,
      ),
      hashes: mergeBy(
        blocks.map((b) => b.hashes ?? []),
        (h) => h.hash,
        (h) => h.reputation_score,
      ),
    };
  }, [seenReports]);

  const total =
    aggregate.ips.length +
    aggregate.domains.length +
    aggregate.urls.length +
    aggregate.hashes.length;

  return (
    <>
      <Header
        title="Threat Intelligence"
        description="Indicators from the reports you have opened in this session."
      />

      <div className="space-y-4 px-7 py-6">
        <Alert
          tone="info"
          message="This page does not query a threat-intelligence service."
          detail={
            'TRINETRA returns intelligence as part of an analysis, not from a separate endpoint. ' +
            'The entries below were collected from reports loaded in this session. Where an ' +
            'indicator appeared more than once, the worst reputation score reported by the ' +
            'backend is shown.'
          }
        />

        {total === 0 ? (
          <Panel className="px-6 py-12 text-center">
            <p className="text-[13px] text-ink-2">
              No indicators yet — open or run an analysis and they will appear here.
            </p>
            <div className="mt-4 flex justify-center">
              <Link to="/analyze">
                <Button variant="primary" size="md">
                  <IconUpload size={14} />
                  Upload Email
                </Button>
              </Link>
            </div>
          </Panel>
        ) : (
          <>
            <ThreatIntelligencePanel data={aggregate} />
            <p className="px-1 text-[11px] text-ink-4">
              Collected from {seenReports.length}{' '}
              {seenReports.length === 1 ? 'report' : 'reports'} in this session.
            </p>
          </>
        )}
      </div>
    </>
  );
}
