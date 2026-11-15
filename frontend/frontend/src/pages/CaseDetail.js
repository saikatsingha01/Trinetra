import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
/* ==========================================================================
   CaseDetail — one full security report.
   --------------------------------------------------------------------------
   Reports seen this session come from the session cache; anything else is
   fetched by case id. The report itself is rendered by SecurityReport, which
   only displays what the response contained.
   ========================================================================== */
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
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
    const [report, setReport] = useState(cached ?? null);
    const [loading, setLoading] = useState(!cached);
    const [failure, setFailure] = useState(null);
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
            if (!live)
                return;
            setReport(fetched);
            recordReport(fetched);
        })
            .catch((error) => {
            if (!live)
                return;
            if (error instanceof DOMException && error.name === 'AbortError')
                return;
            setFailure(toUserMessage(error));
        })
            .finally(() => {
            if (live)
                setLoading(false);
        });
        return () => {
            live = false;
            controller.abort();
        };
    }, [caseId, getReport, recordReport]);
    return (_jsxs(_Fragment, { children: [_jsx(Header, { title: "Security Report", description: caseId, actions: _jsx(Link, { to: "/cases", children: _jsxs(Button, { variant: "ghost", size: "sm", children: [_jsx(IconArrowLeft, { size: 13 }), "All cases"] }) }) }), _jsxs("div", { className: "px-7 py-6", children: [loading && (_jsxs("div", { className: "flex items-center gap-3 px-1 py-10 text-[12.5px] text-ink-3", children: [_jsx(Spinner, { size: 14, className: "text-steel-hi" }), "Loading report\u2026"] })), !loading && failure && (_jsx(Alert, { tone: "error", message: failure.message, detail: failure.detail, action: _jsx(Link, { to: "/analyze", children: _jsx(Button, { variant: "secondary", size: "sm", children: "Analyze an email" }) }) })), !loading && !failure && report && _jsx(SecurityReport, { report: report })] })] }));
}
