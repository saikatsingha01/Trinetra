/* ==========================================================================
   App — layout shell and routes.
   --------------------------------------------------------------------------
   One fixed sidebar, one scrolling column. Each page owns its own Header so
   the title and the page's actions stay together.
   ========================================================================== */

import { Link, Route, Routes } from 'react-router-dom';
import { Header } from './components/Header';
import { Button } from './components/primitives';
import { Dashboard } from './pages/Dashboard';
import { AnalyzeEmail } from './pages/AnalyzeEmail';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { BatchResults } from './pages/BatchResults';
import { ThreatIntel } from './pages/ThreatIntel';
import { Settings } from './pages/Settings';
import { PredictiveRibbon } from './components/ThreeUIVisuals';

function NotFound() {
  return (
    <>
      <Header title="Not found" />
      <div className="px-7 py-16 text-center">
        <p className="text-[13px] text-ink-2">That page does not exist.</p>
        <div className="mt-4 flex justify-center">
          <Link to="/">
            <Button variant="secondary" size="md">
              Back to dashboard
            </Button>
          </Link>
        </div>
      </div>
    </>
  );
}

export default function App() {
  return (
    <div className="app-shell">
      <div className="site-background" aria-hidden="true"><PredictiveRibbon /></div>
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<AnalyzeEmail />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/batch" element={<BatchResults />} />
          <Route path="/cases/:caseId" element={<CaseDetail />} />
          <Route path="/intel" element={<ThreatIntel />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}
