import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
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
    return (_jsxs(_Fragment, { children: [_jsx(Header, { title: "Not found" }), _jsxs("div", { className: "px-7 py-16 text-center", children: [_jsx("p", { className: "text-[13px] text-ink-2", children: "That page does not exist." }), _jsx("div", { className: "mt-4 flex justify-center", children: _jsx(Link, { to: "/", children: _jsx(Button, { variant: "secondary", size: "md", children: "Back to dashboard" }) }) })] })] }));
}
export default function App() {
    return (_jsxs("div", { className: "app-shell", children: [_jsx("div", { className: "site-background", "aria-hidden": "true", children: _jsx(PredictiveRibbon, {}) }), _jsx("main", { className: "app-main", children: _jsxs(Routes, { children: [_jsx(Route, { path: "/", element: _jsx(Dashboard, {}) }), _jsx(Route, { path: "/analyze", element: _jsx(AnalyzeEmail, {}) }), _jsx(Route, { path: "/cases", element: _jsx(Cases, {}) }), _jsx(Route, { path: "/cases/batch", element: _jsx(BatchResults, {}) }), _jsx(Route, { path: "/cases/:caseId", element: _jsx(CaseDetail, {}) }), _jsx(Route, { path: "/intel", element: _jsx(ThreatIntel, {}) }), _jsx(Route, { path: "/settings", element: _jsx(Settings, {}) }), _jsx(Route, { path: "*", element: _jsx(NotFound, {}) })] }) })] }));
}
