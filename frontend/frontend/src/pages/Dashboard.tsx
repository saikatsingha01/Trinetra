import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { UploadZone } from '../components/UploadZone';
import { CasesTable } from '../components/CasesTable';
import { Alert } from '../components/Alert';
import { PredictiveRibbon, TrinetraBloom } from '../components/ThreeUIVisuals';
import { stagePendingFile } from '../store/pendingUpload';
import { useSession } from '../store/session';

const RECENT_LIMIT = 5;

function Stat({ label, value, note }: { label: string; value: string; note: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{note}</small></div>;
}

export function Dashboard() {
  const navigate = useNavigate();
  const { cases, stats } = useSession();
  const [rejection, setRejection] = useState<string | null>(null);

  function handleSelect(file: File) {
    setRejection(null);
    stagePendingFile(file);
    navigate('/analyze');
  }

  return (
    <div className="home-page">
      <section className="hero">
        <PredictiveRibbon className="hero__ribbon" />
        <div className="hero__noise" aria-hidden="true" />
        <div className="hero__content">
          <div className="hero__eyebrow"><span className="live-pill"><span /> LIVE</span> EMAIL DEFENSE / PRE-DELIVERY ANALYSIS</div>
          <h1>Welcome To <span>TRINETRA</span></h1>
          <div className="hero__tagline">See Threat Before It Sees You!</div>
          <p className="hero__intro">A focused security console for turning suspicious email into a clear verdict, evidence trail and actionable intelligence.</p>
          <div className="hero__meta"><span>ENGINE / CONNECTED</span><span>PIPELINE / ONLINE</span><span>MODE / ANALYSIS</span></div>
          <div className="hero__links">
            <Link to="/analyze" className="hero-cta">Start an analysis <span>↗</span></Link>
            <Link to="/cases" className="hero-link">View recent cases</Link>
          </div>
        </div>

        <div className="hero__identity">
          <div className="bloom-frame"><TrinetraBloom /><div className="bloom-caption">SIGNAL FIELD / TRINETRA</div></div>
          <div className="hero-orbit"><span>01</span><i /><span>SECURITY SIGNAL</span></div>
        </div>
      </section>

      <section className="workspace-section" aria-labelledby="workspace-title">
        <div className="workspace-section__head">
          <div>
            <div className="micro-label">INPUT CHANNEL</div>
            <h2 id="workspace-title">Inspect a message before it reaches the inbox.</h2>
            <p>Drop a raw .EML message into the console. TRINETRA sends it through the existing connected pipeline and returns the full security report.</p>
          </div>
          <span className="format-pill">MESSAGE / RFC822</span>
        </div>
        {rejection && <div className="ingest__alert"><Alert tone="error" message={rejection} /></div>}
        <UploadZone onSelect={handleSelect} onReject={setRejection} />
        <div className="workspace-section__foot">
          <span>ONE MESSAGE PER ANALYSIS</span>
          <span>RAW .EML / RFC822</span>
          <span>RESULTS RETURN TO THIS CONSOLE</span>
        </div>
      </section>

      <section className="metrics">
        <Stat label="ANALYSES" value={String(stats.analyzed)} note="completed this session" />
        <Stat label="THREATS" value={String(stats.threats)} note="high / critical / malicious" />
        <Stat label="CRITICAL" value={String(stats.critical)} note="requires immediate attention" />
        <Stat label="AVERAGE RISK" value={stats.averageRisk === null ? '—' : String(stats.averageRisk)} note="mean completed score" />
      </section>

      <section className="recent">
        <div className="recent__head">
          <div><div className="micro-label">SESSION MEMORY</div><h2>Recent cases</h2></div>
          {cases.length > RECENT_LIMIT && <Link to="/cases">Open archive ↗</Link>}
        </div>
        <div className="recent__table">
          {cases.length === 0 ? <div className="recent__empty"><span>NO_CASES / 000</span><p>Your completed analyses will appear here with their full report.</p></div> : <CasesTable rows={cases.slice(0, RECENT_LIMIT)} />}
        </div>
      </section>
    </div>
  );
}
