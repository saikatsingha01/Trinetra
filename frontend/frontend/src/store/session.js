import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { toCaseSummary } from '../services/api';
import { isThreatVerdict } from '../lib/severity';
const SessionContext = createContext(null);
function computeStats(cases) {
    if (cases.length === 0) {
        return { analyzed: 0, threats: 0, critical: 0, averageRisk: null };
    }
    let threats = 0;
    let critical = 0;
    let total = 0;
    for (const row of cases) {
        if (isThreatVerdict(row.verdict))
            threats += 1;
        if (row.verdict === 'CRITICAL' || row.verdict === 'MALICIOUS')
            critical += 1;
        total += row.risk_score;
    }
    return {
        analyzed: cases.length,
        threats,
        critical,
        averageRisk: Math.round(total / cases.length),
    };
}
export function SessionProvider({ children }) {
    const [cases, setCases] = useState([]);
    const [reportOrder, setReportOrder] = useState([]);
    const reportCache = useRef(new Map());
    const recordReport = useCallback((report) => {
        reportCache.current.set(report.case_id, report);
        setReportOrder((prev) => [report.case_id, ...prev.filter((id) => id !== report.case_id)]);
        setCases((prev) => {
            const row = toCaseSummary(report);
            return [row, ...prev.filter((item) => item.case_id !== row.case_id)];
        });
    }, []);
    const getReport = useCallback((caseId) => reportCache.current.get(caseId), []);
    const value = useMemo(() => {
        const seenReports = reportOrder
            .map((id) => reportCache.current.get(id))
            .filter((report) => Boolean(report));
        return {
            cases,
            stats: computeStats(cases),
            recordReport,
            getReport,
            seenReports,
        };
    }, [cases, recordReport, getReport, reportOrder]);
    return _jsx(SessionContext.Provider, { value: value, children: children });
}
export function useSession() {
    const value = useContext(SessionContext);
    if (!value)
        throw new Error('useSession must be used inside <SessionProvider>.');
    return value;
}
