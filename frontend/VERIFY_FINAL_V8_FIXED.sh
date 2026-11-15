#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
python -m py_compile logic_receiver.py pdf_report.py
node --check frontend/src/components/SecurityOverview.js
node --check frontend/src/components/SecurityReport.js
node --check frontend/src/lib/pdf.js
node --check frontend/src/pages/BatchResults.js
node --check frontend/src/pages/AnalyzeEmail.js
node --check frontend/src/components/UploadZone.js
python - <<'PY'
from pdf_report import build_report_pdf
sample={
 'case_id':'verify-pdf-001','risk_score':61,'verdict':'HIGH','analysis_mode':'subhom_only',
 'analysis_confidence':{'score':41,'label':'Low','factors':{'evidence_coverage':90,'signal_agreement':60,'ai_availability':0},'rationale':['Ollama AI assessment was unavailable.','Independent Subhom evidence remains available.']},
 'email':{'subject':'Verification email','from':'sender@example.com','to':'user@example.com'},
 'provided_email':'From: sender@example.com\nTo: user@example.com\nDate: Mon, 07 Sep 2026 21:00:00 +0530\nSubject: Verification email\n\nHello, this is a readable body.\nPlease review the attached details.',
 'security_analysis':{'spf':{'result':'pass'},'dkim':{'result':'pass'},'dmarc':{'result':'fail'}},
 'threat_intelligence':{'ips':['1.2.3.4'],'domains':['example.com'],'urls':['https://example.com']},
 'iocs':{'ips':['1.2.3.4']},
 'ai_assessment':{},'reasons':['Authentication anomaly detected.'],'correlations':[],
 'triggered_rules':[{'rule_id':'R1','severity':'HIGH','description':'Example rule'}],
 'score_breakdown':{'authentication':30,'reputation':20,'content':11},
 'model_info':{'model':'ollama'}
}
pdf=build_report_pdf(sample)
assert pdf.startswith(b'%PDF-') and len(pdf)>5000
open('/tmp/trinetra_v8_pdf_check.pdf','wb').write(pdf)
print('PDF generation OK:',len(pdf))
PY
rm -rf /tmp/trinetra_v8_pdf_render
python /home/oai/skills/pdfs/scripts/render_pdf.py /tmp/trinetra_v8_pdf_check.pdf --out_dir /tmp/trinetra_v8_pdf_render --dpi 120
PAGES=$(find /tmp/trinetra_v8_pdf_render -name 'page-*.png' | wc -l)
[ "$PAGES" -ge 2 ]

grep -RIn "WHY THIS CONFIDENCE SCORE\|result-metric-box--risk\|result-metric-box--confidence" frontend/src/components/SecurityOverview.js frontend/src/components/SecurityOverview.tsx frontend/src/index.css >/dev/null
grep -RIn "Export Report as PDF" frontend/src/components/SecurityReport.js frontend/src/components/SecurityReport.tsx >/dev/null
grep -RIn "multiple: true" frontend/src/components/UploadZone.js >/dev/null
grep -RIn "subhom_only" logic_receiver.py frontend/src/components/SecurityReport.js >/dev/null

echo "TRINETRA V8 fixed verification OK ($PAGES PDF pages rendered)"
