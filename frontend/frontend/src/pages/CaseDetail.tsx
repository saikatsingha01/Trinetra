/* ==========================================================================
   CaseDetail — one full security report.
   --------------------------------------------------------------------------
   Reports seen this session come from the session cache; anything else is
   fetched by case id. The report itself is rendered by SecurityReport, which
   only displays what the response contained.
   ========================================================================== */

import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import type { AnalysisReport } from '../types/analysis';
import { Header } from '../components/Header';
import { SecurityReport } from '../components/SecurityReport';
import { Alert } from '../components/Alert';
import { Button, Spinner } from '../components/primitives';
import { IconArrowLeft } from '../components/icons';
import { fetchCase, toUserMessage } from '../services/api';
import { useSession } from '../store/session';

export function CaseDetail() {
  const { caseId = '' } = useParams();
  const { getReport, recordReport } = useSession();

  const cached = getReport(caseId);
  const [report, setReport] = useState<AnalysisReport | null>(cached ?? null);
  const [loading, setLoading] = useState(!cached);
  const [failure, setFailure] = useState<{ message: string; detail?: string } | null>(null);

  useEffect(() => {
    const known = getReport(caseId);
    if (known) {
      setReport(known);
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    let live = true;
    setLoading(true);
    setFailure(null);

    fetchCase(caseId, { signal: controller.signal })
      .then((fetched) => {
        if (!live) return;
        setReport(fetched);
        recordReport(fetched);
      })
      .catch((error: unknown) => {
        if (!live) return;
        if (error instanceof DOMException && error.name === 'AbortError') return;
        setFailure(toUserMessage(error));
      })
      .finally(() => {
        if (live) setLoading(false);
      });

    return () => {
      live = false;
      controller.abort();
    };
  }, [caseId, getReport, recordReport]);

  return (
    <>
      <Header
        title="Security Report"
        description={caseId}
        actions={
          <Link to="/cases">
            <Button variant="ghost" size="sm">
              <IconArrowLeft size={13} />
              All cases
            </Button>
          </Link>
        }
      />

      <div className="px-7 py-6">
        {loading && (
          <div className="flex items-center gap-3 px-1 py-10 text-[12.5px] text-ink-3">
            <Spinner size={14} className="text-steel-hi" />
            Loading report…
          </div>
        )}

        {!loading && failure && (
          <Alert
            tone="error"
            message={failure.message}
            detail={failure.detail}
            action={
              <Link to="/analyze">
                <Button variant="secondary" size="sm">
                  Analyze an email
                </Button>
              </Link>
            }
          />
        )}

        {!loading && !failure && report && <SecurityReport report={report} />}
      </div>
    </>
  );
}
