import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Header } from '../components/Header';
import { SecurityReport } from '../components/SecurityReport';
import { Button } from '../components/primitives';
import { IconArrowLeft } from '../components/icons';
import { useSession } from '../store/session';
import { parseEmlForGmailView } from '../lib/emailViewer';
export function BatchResults() {
  const [params] = useSearchParams();
  const { getReport } = useSession();
  const ids = useMemo(() => (params.get('ids') ?? '').split(',').map((id) => decodeURIComponent(id)).filter(Boolean), [params]);
  const reports = ids.map(getReport).filter(Boolean);
  const [activeIndex, setActiveIndex] = useState(0);
  useEffect(() => { if (activeIndex >= reports.length) setActiveIndex(Math.max(0, reports.length - 1)); }, [reports.length, activeIndex]);
  const activeReport = reports[activeIndex];
  return <>
    <Header title="Security Reports" description={`${reports.length} message${reports.length === 1 ? '' : 's'} assessed — switch between individual reports with tabs.`} actions={<Link to="/analyze"><Button variant="ghost" size="sm"><IconArrowLeft size={13} /> Analyze more</Button></Link>} />
    {reports.length === 0 ? <div className="batch-results-empty">These reports are no longer available in the current browser session.</div> : <div className="batch-results-view">
      <div className="batch-results-tabs" role="tablist" aria-label="Gmail assessment tabs">
        {reports.map((report: any, index) => {
          let subject = report?.email?.subject;
          if ((!subject || subject === '(no subject)') && report?.provided_email) { try { subject = parseEmlForGmailView(report.provided_email).subject; } catch {} }
          subject = subject || report.source_file?.filename || `Message ${index + 1}`;
          const label = String(subject).length > 28 ? `${String(subject).slice(0, 28)}…` : String(subject);
          return <button key={report.case_id} type="button" role="tab" aria-selected={activeIndex === index} className={`batch-results-tab ${activeIndex === index ? 'is-active' : ''}`} onClick={() => setActiveIndex(index)}><span className="batch-results-tab__index">{String(index + 1).padStart(2, '0')}</span><span className="batch-results-tab__label">{label}</span><span className="batch-results-tab__file">{report.source_file?.filename || 'EML'}</span></button>;
        })}
      </div>
      {activeReport && <article className="batch-result-tab-panel" role="tabpanel"><div className="batch-result-layer__index">MESSAGE {String(activeIndex + 1).padStart(2, '0')} / {String(reports.length).padStart(2, '0')}</div><SecurityReport report={activeReport} /></article>}
    </div>}
  </>;
}
