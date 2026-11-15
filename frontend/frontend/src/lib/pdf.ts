import { config } from '../services/api';
import type { AnalysisReport } from '../types/analysis';

export async function downloadReportPdf(report: AnalysisReport | string): Promise<void> {
  const caseId = typeof report === 'string' ? report : report?.case_id;
  if (!caseId) throw new Error('No case ID is available for PDF export.');
  const payload = typeof report === 'object' && report ? { provided_email: report.provided_email || '' } : {};
  const response = await fetch(`${config.logicBaseUrl}${config.analysisPath}/${encodeURIComponent(caseId)}/pdf`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    let detail = `PDF export failed (${response.status}).`;
    try {
      const result = await response.json();
      if (result?.detail) detail = String(result.detail);
    } catch { /* non-JSON response */ }
    throw new Error(detail);
  }
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match?.[1] || `TRINETRA_Report_${caseId}.pdf`;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}
