/* ==========================================================================
   Session store.

   Cases shown here are analyses completed during this browser session. The
   full report cache also avoids an unnecessary fetch when the analyst opens a
   report immediately after analysis.
   ========================================================================== */

import type { ReactNode } from 'react';
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { AnalysisReport, CaseSummary } from '../types/analysis';
import { toCaseSummary } from '../services/api';
import { isThreatVerdict } from '../lib/severity';

export interface DashboardStats {
  analyzed: number;
  threats: number;
  critical: number;
  averageRisk: number | null;
}

interface SessionValue {
  cases: CaseSummary[];
  stats: DashboardStats;
  recordReport: (report: AnalysisReport) => void;
  getReport: (caseId: string) => AnalysisReport | undefined;
  seenReports: AnalysisReport[];
}

const SessionContext = createContext<SessionValue | null>(null);

function computeStats(cases: CaseSummary[]): DashboardStats {
  if (cases.length === 0) {
    return { analyzed: 0, threats: 0, critical: 0, averageRisk: null };
  }

  let threats = 0;
  let critical = 0;
  let total = 0;

  for (const row of cases) {
    if (isThreatVerdict(row.verdict)) threats += 1;
    if (row.verdict === 'CRITICAL' || row.verdict === 'MALICIOUS') critical += 1;
    total += row.risk_score;
  }

  return {
    analyzed: cases.length,
    threats,
    critical,
    averageRisk: Math.round(total / cases.length),
  };
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [reportOrder, setReportOrder] = useState<string[]>([]);
  const reportCache = useRef(new Map<string, AnalysisReport>());

  const recordReport = useCallback((report: AnalysisReport) => {
    reportCache.current.set(report.case_id, report);
    setReportOrder((prev) => [report.case_id, ...prev.filter((id) => id !== report.case_id)]);
    setCases((prev) => {
      const row = toCaseSummary(report);
      return [row, ...prev.filter((item) => item.case_id !== row.case_id)];
    });
  }, []);

  const getReport = useCallback(
    (caseId: string) => reportCache.current.get(caseId),
    [],
  );

  const value = useMemo<SessionValue>(() => {
    const seenReports = reportOrder
      .map((id) => reportCache.current.get(id))
      .filter((report): report is AnalysisReport => Boolean(report));

    return {
      cases,
      stats: computeStats(cases),
      recordReport,
      getReport,
      seenReports,
    };
  }, [cases, recordReport, getReport, reportOrder]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error('useSession must be used inside <SessionProvider>.');
  return value;
}
