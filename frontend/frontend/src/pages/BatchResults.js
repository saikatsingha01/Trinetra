import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
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
    return (_jsxs(_Fragment, { children: [
        _jsx(Header, { title: "Security Reports", description: `${reports.length} message${reports.length === 1 ? '' : 's'} assessed — switch between individual reports with tabs.`, actions: _jsx(Link, { to: "/analyze", children: _jsxs(Button, { variant: "ghost", size: "sm", children: [_jsx(IconArrowLeft, { size: 13 }), " Analyze more"] }) }) }),
        reports.length === 0 ? _jsx("div", { className: "batch-results-empty", children: "These reports are no longer available in the current browser session." }) : _jsxs("div", { className: "batch-results-view", children: [
            _jsx("div", { className: "batch-results-tabs", role: "tablist", "aria-label": "Gmail assessment tabs", children: reports.map((report, index) => {
                let subject = report?.email?.subject;
                if ((!subject || subject === '(no subject)') && report?.provided_email) {
                    try { subject = parseEmlForGmailView(report.provided_email).subject; } catch { /* ignore */ }
                }
                subject = subject || report.source_file?.filename || `Message ${index + 1}`;
                const label = String(subject).length > 28 ? `${String(subject).slice(0, 28)}…` : String(subject);
                return _jsxs("button", { type: "button", role: "tab", "aria-selected": activeIndex === index, className: `batch-results-tab ${activeIndex === index ? 'is-active' : ''}`, onClick: () => setActiveIndex(index), children: [_jsx("span", { className: "batch-results-tab__index", children: String(index + 1).padStart(2, '0') }), _jsx("span", { className: "batch-results-tab__label", children: label }), _jsx("span", { className: "batch-results-tab__file", children: report.source_file?.filename || 'EML' })] }, report.case_id);
            }) }),
            activeReport && _jsxs("article", { className: "batch-result-tab-panel", role: "tabpanel", children: [_jsxs("div", { className: "batch-result-layer__index", children: ["MESSAGE ", String(activeIndex + 1).padStart(2, '0'), " / ", String(reports.length).padStart(2, '0')] }), _jsx(SecurityReport, { report: activeReport })] })
        ] })
    ] }));
}
