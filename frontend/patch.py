from pathlib import Path
import re
root=Path('/mnt/data/trinetra_work')

# AnalysisProgress wording
p=root/'frontend/src/components/AnalysisProgress.tsx'
s=p.read_text()
s=s.replace("case 'subhom': return ['Security analysis', 'Subhom is processing security and threat signals.'];", "case 'subhom': return ['Security analysis', 'TRINETRA is processing security and threat signals.'];")
p.write_text(s)

# types
p=root/'frontend/src/types/analysis.ts'
s=p.read_text()
s=s.replace("  verdict_stability: number;\n  };\n}", "  verdict_stability: number;\n  ai_availability?: number;\n  };\n}")
s=s.replace("  analysis_confidence?: AnalysisConfidence | null;\n", "  analysis_confidence?: AnalysisConfidence | null;\n  analysis_mode?: 'full' | 'subhom_only';\n  confidence_explanation?: string | null;\n  provided_email?: string | null;\n")
p.write_text(s)

# api normalize additions
p=root/'frontend/src/services/api.ts'
s=p.read_text()
s=s.replace("    analysis_confidence: (asRecord(root.analysis_confidence) ?? null) as AnalysisReport['analysis_confidence'],\n", "    analysis_confidence: (asRecord(root.analysis_confidence) ?? null) as AnalysisReport['analysis_confidence'],\n    analysis_mode: root.analysis_mode === 'subhom_only' ? 'subhom_only' : 'full',\n    confidence_explanation: typeof root.confidence_explanation === 'string' ? root.confidence_explanation : null,\n")
p.write_text(s)

# upload zone
p=root/'frontend/src/components/UploadZone.tsx'
s=p.read_text()
s=s.replace("  onSelect: (file: File) => void;", "  onSelect: (files: File[]) => void;")
s=s.replace("  function accept(files: FileList | null) {\n    const file = files?.[0];\n    const rejection = validateEmlFile(file);\n    if (rejection) {\n      onReject(rejection.message);\n      return;\n    }\n    onSelect(file as File);\n  }", "  function accept(files: FileList | null) {\n    const selected = Array.from(files ?? []);\n    if (selected.length === 0) return;\n    if (selected.length > 5) {\n      onReject('You can upload up to 5 Gmail/EML messages at once.');\n      return;\n    }\n    const invalid = selected.map(validateEmlFile).find(Boolean);\n    if (invalid) {\n      onReject(invalid!.message);\n      return;\n    }\n    onSelect(selected);\n  }")
s=s.replace('type="file"', 'type="file"\n        multiple')
s=s.replace('aria-label="Choose an EML file"', 'aria-label="Choose up to five EML files"')
s=s.replace('<strong>Drop your .EML file here</strong>', '<strong>Drop up to 5 .EML / Gmail files here</strong><small>or click to choose multiple messages</small>')
p.write_text(s)

# AnalyzeEmail full replacement
p=root/'frontend/src/pages/AnalyzeEmail.tsx'
p.write_text("""import { useEffect, useRef, useState } from 'react';\nimport { useNavigate } from 'react-router-dom';\nimport { Header } from '../components/Header';\nimport { UploadZone } from '../components/UploadZone';\nimport { FilePreview } from '../components/FilePreview';\nimport { AnalysisProgress } from '../components/AnalysisProgress';\nimport { Alert } from '../components/Alert';\nimport { Button } from '../components/primitives';\nimport { IconArrowRight, IconTrash } from '../components/icons';\nimport { analyzeEmail, toUserMessage } from '../services/api';\nimport { useSession } from '../store/session';\nimport { takePendingFile } from '../store/pendingUpload';\n\ntype Phase = 'choose' | 'ready' | 'running';\ninterface Failure { message: string; detail?: string }\n\nexport function AnalyzeEmail() {\n  const navigate = useNavigate();\n  const { recordReport } = useSession();\n  const [files, setFiles] = useState<File[]>([]);\n  const [phase, setPhase] = useState<Phase>('choose');\n  const [failure, setFailure] = useState<Failure | null>(null);\n  const abortRef = useRef<AbortController | null>(null);\n  const [loaderTarget, setLoaderTarget] = useState(12);\n  const [currentIndex, setCurrentIndex] = useState(0);\n\n  useEffect(() => {\n    const staged = takePendingFile();\n    if (staged) { setFiles([staged]); setPhase('ready'); }\n  }, []);\n  useEffect(() => () => abortRef.current?.abort(), []);\n\n  async function run() {\n    if (!files.length || phase === 'running' || abortRef.current) return;\n    const controller = new AbortController();\n    const analysisStartedAt = performance.now();\n    abortRef.current = controller; setFailure(null); setLoaderTarget(12); setPhase('running');\n    const successful: string[] = [];\n    try {\n      for (let index = 0; index < files.length; index += 1) {\n        const file = files[index];\n        setCurrentIndex(index);\n        setLoaderTarget(Math.max(12, Math.round((index / files.length) * 88)));\n        const report = await analyzeEmail(file, {\n          signal: controller.signal,\n          onProgress: (event) => {\n            const base = (index / files.length) * 88;\n            const span = 88 / files.length;\n            if (event.type === 'upload-start') setLoaderTarget((current) => Math.max(current, base + span * 0.18));\n            if (event.type === 'case-received') setLoaderTarget((current) => Math.max(current, base + span * 0.39));\n            if (event.type === 'security-analysis-received') setLoaderTarget((current) => Math.max(current, base + span * 0.60));\n            if (event.type === 'analysis-complete') setLoaderTarget((current) => Math.max(current, base + span));\n          },\n        });\n        const providedEmail = await file.text();\n        recordReport({\n          ...report,\n          provided_email: providedEmail,\n          processing_time_ms: Math.round(performance.now() - analysisStartedAt),\n        });\n        successful.push(report.case_id);\n      }\n      setLoaderTarget(100);\n      await new Promise((resolve) => window.setTimeout(resolve, 550));\n      if (successful.length === 1) navigate(`/cases/${encodeURIComponent(successful[0])}`, { replace: true });\n      else navigate(`/cases/batch?ids=${encodeURIComponent(successful.join(','))}`, { replace: true });\n    } catch (error) {\n      if (controller.signal.aborted) { setPhase('ready'); return; }\n      setFailure(toUserMessage(error)); setPhase('ready');\n    } finally { abortRef.current = null; }\n  }\n\n  if (phase === 'running') {\n    const label = files.length > 1 ? `Email ${currentIndex + 1} of ${files.length} — ${files[currentIndex]?.name ?? ''}` : files[0]?.name ?? '';\n    return <AnalysisProgress filename={label} externalTarget={loaderTarget} onCancel={() => { abortRef.current?.abort(); setPhase('ready'); }} />;\n  }\n\n  return (\n    <>\n      <Header title="Analyze email" description="Upload up to five .EML messages and review each assessment in a stacked results view." />\n      <div className="internal-pad">\n        <div className="analysis-layout">\n          <div className="analysis-intro">\n            <div className="micro-label">INGESTION WORKSPACE</div>\n            <h2>Submit one or more messages.</h2>\n            <p>TRINETRA sends each message through the same connected pipeline. Multiple uploads are processed safely one by one, then shown together as layered reports.</p>\n            <div className="analysis-note"><span>01</span><div><strong>Upload</strong><small>Choose 1–5 valid .EML messages.</small></div></div>\n            <div className="analysis-note"><span>02</span><div><strong>Analyze</strong><small>TRINETRA processes each message through the connected pipeline.</small></div></div>\n            <div className="analysis-note"><span>03</span><div><strong>Review</strong><small>See the provided Gmail and the full assessment for every message.</small></div></div>\n          </div>\n          <div className="analysis-card">\n            {failure && <Alert tone="error" message={failure.message} detail={failure.detail} action={files.length ? <Button variant="secondary" size="sm" onClick={run}>Retry</Button> : undefined} />}\n            {files.length ? (\n              <>\n                <div className="batch-upload-summary">\n                  <div className="batch-upload-summary__head"><strong>{files.length} {files.length === 1 ? 'Gmail' : 'Gmails'} selected</strong><span>MAX 5</span></div>\n                  <div className="batch-upload-list">\n                    {files.map((file, index) => <FilePreview key={`${file.name}-${file.lastModified}-${index}`} file={file} onRemove={() => setFiles((current) => current.filter((_, i) => i !== index))} />)}\n                  </div>\n                  <div className="batch-upload-actions">\n                    <Button variant="ghost" size="sm" onClick={() => { setFiles([]); setFailure(null); }}><IconTrash size={13} /> Clear</Button>\n                    <Button variant="primary" size="lg" onClick={run} autoFocus>Analyze {files.length > 1 ? 'emails' : 'email'} <IconArrowRight size={15} /></Button>\n                  </div>\n                </div>\n              </>\n            ) : (\n              <UploadZone onSelect={(selected) => { setFailure(null); setFiles(selected); setPhase('ready'); }} onReject={(m) => setFailure({ message: m })} />\n            )}\n          </div>\n        </div>\n      </div>\n    </>\n  );\n}\n""")

# SecurityReport add provided viewer
p=root/'frontend/src/components/SecurityReport.tsx'
s=p.read_text()
insert="""
function ProvidedGmail({ content, filename }: { content?: string | null; filename?: string | null }) {
  const [open, setOpen] = useState(false);
  if (!content) return null;
  return (
    <section className="provided-gmail-shell">
      <div className="provided-gmail-head">
        <div>
          <div className="eyebrow">ORIGINAL MESSAGE</div>
          <h2>Provided Gmail</h2>
          <p>{filename || 'Uploaded EML message'} is shown exactly as supplied to TRINETRA.</p>
        </div>
        <button type="button" className="result-expand-button" onClick={() => setOpen(true)}>SEE PROVIDED GMAIL</button>
      </div>
      {open && (
        <div className="provided-gmail-modal" role="dialog" aria-modal="true" aria-label="Provided Gmail">
          <div className="provided-gmail-modal__backdrop" onClick={() => setOpen(false)} />
          <div className="provided-gmail-modal__panel">
            <div className="provided-gmail-modal__paper">
              <div className="provided-gmail-modal__paper-head">
                <span>TRINETRA / PROVIDED GMAIL</span>
                <button type="button" onClick={() => setOpen(false)} aria-label="Close provided Gmail">CLOSE</button>
              </div>
              <pre>{content}</pre>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
"""
s=s.replace("function ProvenanceNotice", "import { useState } from 'react';\n\n"+insert+"\nfunction ProvenanceNotice")
s=s.replace("      <SecurityOverview report={report} />", "      <SecurityOverview report={report} />\n      {report.analysis_mode === 'subhom_only' && (\n        <div className=\"result-degraded-notice\">\n          <IconAlert size={15} />\n          <div>\n            <strong>AI assessment unavailable.</strong> TRINETRA calculated this risk score from Subhom's security and threat signals only. The confidence score is intentionally lower because Saikat's Ollama signal could not be incorporated. Resend the email for a more precise report.\n          </div>\n        </div>\n      )}\n      <ProvidedGmail content={report.provided_email} filename={report.source_file?.filename} />")
p.write_text(s)

# Batch results page
p=root/'frontend/src/pages/BatchResults.tsx'
p.write_text("""import { useMemo } from 'react';\nimport { Link, useSearchParams } from 'react-router-dom';\nimport { Header } from '../components/Header';\nimport { SecurityReport } from '../components/SecurityReport';\nimport { Button } from '../components/primitives';\nimport { IconArrowLeft } from '../components/icons';\nimport { useSession } from '../store/session';\n\nexport function BatchResults() {\n  const [params] = useSearchParams();\n  const { getReport } = useSession();\n  const ids = useMemo(() => (params.get('ids') ?? '').split(',').map((id) => decodeURIComponent(id)).filter(Boolean), [params]);\n  const reports = ids.map(getReport).filter(Boolean);\n\n  return (\n    <>\n      <Header title="Security Reports" description={`${reports.length} message${reports.length === 1 ? '' : 's'} assessed — stacked for review.`} actions={<Link to="/analyze"><Button variant="ghost" size="sm"><IconArrowLeft size={13} /> Analyze more</Button></Link>} />\n      <div className="batch-results-stack">\n        {reports.length === 0 ? <div className="px-7 py-16 text-center text-ink-3 text-[12.5px]">These reports are no longer available in the current browser session.</div> : reports.map((report, index) => (\n          <article key={report!.case_id} className="batch-result-layer" style={{ zIndex: reports.length - index }}>\n            <div className="batch-result-layer__index">MESSAGE {String(index + 1).padStart(2, '0')} / {String(reports.length).padStart(2, '0')}</div>\n            <SecurityReport report={report!} />\n          </article>\n        ))}\n      </div>\n    </>\n  );\n}\n""")

# App route
p=root/'frontend/src/App.tsx'
s=p.read_text()
s=s.replace("import { CaseDetail } from './pages/CaseDetail';", "import { CaseDetail } from './pages/CaseDetail';\nimport { BatchResults } from './pages/BatchResults';")
s=s.replace('          <Route path="/cases/:caseId" element={<CaseDetail />} />', '          <Route path="/cases/batch" element={<BatchResults />} />\n          <Route path="/cases/:caseId" element={<CaseDetail />} />')
p.write_text(s)

# Backend fallback state and confidence changes
p=root/'logic_receiver.py'
s=p.read_text()
s=s.replace('        "ollama": None,\n', '        "ollama": None,\n        "ollama_failed": False,\n')
# confidence signature: raw_ai can be empty; inject availability
s=s.replace('    if score >= 85:', "    ai_available = bool(raw_ai)\n    if not ai_available:\n        # No Ollama signal: cap confidence so the report clearly communicates\n        # that the decision is based only on Subhom security/threat evidence.\n        score = min(score, 45)\n\n    if score >= 85:")
s=s.replace('    if authentication_consistency >= 0.999:\n', '    if not ai_available:\n        rationale.append("Ollama AI assessment was unavailable; the risk score uses Subhom security and threat signals only.")\n    if authentication_consistency >= 0.999:\n')
s=s.replace('            "verdict_stability": round(verdict_stability * 100),\n', '            "verdict_stability": round(verdict_stability * 100),\n            "ai_availability": 100 if ai_available else 0,\n')
# replace process gate and ai setup
s=s.replace('        ollama = case.get("ollama")\n        email_raw = case.get("email_raw")\n\n        if backend is None or ollama is None:\n            return\n', '        ollama = case.get("ollama")\n        ollama_failed = bool(case.get("ollama_failed"))\n        email_raw = case.get("email_raw")\n\n        if backend is None or (ollama is None and not ollama_failed):\n            return\n')
s=s.replace('_log(case_id, "Calculating risk — security + threat + Ollama inputs present")', '_log(case_id, "Calculating risk — security + threat inputs%s" % (" + Ollama" if ollama is not None else "; Ollama unavailable"))')
s=s.replace('        ai_data = ollama.ai_assessment.model_dump(mode="python")\n\n        model_info = dict(ai_data.get("model_info") or {})\n\n        model_info["grounding"] = ollama.grounding.model_dump(\n            mode="python"\n        )\n\n        model_info["processing_time_seconds"] = (\n            ollama.processing_time_seconds\n        )\n\n        model_info["processing_model_info"] = (\n            ollama.model_info.model_dump(mode="python")\n        )\n\n        ai_data["model_info"] = model_info\n\n        ai_assessment = adapt_ai_assessment(ai_data)', '        if ollama is not None:\n            ai_data = ollama.ai_assessment.model_dump(mode="python")\n\n            model_info = dict(ai_data.get("model_info") or {})\n            model_info["grounding"] = ollama.grounding.model_dump(mode="python")\n            model_info["processing_time_seconds"] = ollama.processing_time_seconds\n            model_info["processing_model_info"] = ollama.model_info.model_dump(mode="python")\n            ai_data["model_info"] = model_info\n            ai_assessment = adapt_ai_assessment(ai_data)\n        else:\n            ai_data = {}\n            ai_assessment = adapt_ai_assessment({})')
# confidence inputs and enriched report
s=s.replace('            raw_ai=ollama.ai_assessment.model_dump(mode="python"),\n            grounding=ollama.grounding.model_dump(mode="python"),', '            raw_ai=ollama.ai_assessment.model_dump(mode="python") if ollama is not None else {},\n            grounding=ollama.grounding.model_dump(mode="python") if ollama is not None else None,')
s=s.replace('            "analysis_confidence": confidence,\n', '            "analysis_confidence": confidence,\n            "analysis_mode": "subhom_only" if ollama is None else "full",\n            "confidence_explanation": (\n                "Confidence is lower because Saikat\'s Ollama assessment failed, so TRINETRA used Subhom security/threat evidence without the independent AI signal. Resend the email for a more precise report."\n                if ollama is None else None\n            ),\n')
s=s.replace('            "ai_assessment": ollama.ai_assessment.model_dump(\n                mode="json",\n            ),', '            "ai_assessment": (\n                ollama.ai_assessment.model_dump(mode="json")\n                if ollama is not None else ai_assessment.model_dump(mode="json")\n            ),')
s=s.replace('            "grounding": ollama.grounding.model_dump(\n                mode="json",\n            ),', '            "grounding": (\n                ollama.grounding.model_dump(mode="json")\n                if ollama is not None else None\n            ),')
s=s.replace('            "processing_time_seconds": (\n                ollama.processing_time_seconds\n            ),\n            "model_info": ollama.model_info.model_dump(\n                mode="json",\n            ),', '            "processing_time_seconds": (ollama.processing_time_seconds if ollama is not None else final_report.get("processing_time_ms", 0) / 1000),\n            "model_info": (\n                ollama.model_info.model_dump(mode="json")\n                if ollama is not None else {"model": "unavailable", "provider": "ollama", "version": "failed"}\n            ),')
# should_process flags
s=s.replace('        should_process = case.get("ollama") is not None\n', '        should_process = case.get("ollama") is not None or bool(case.get("ollama_failed"))\n')
s=s.replace('            _log(case_id, "Both backend and Ollama present — will calculate final risk")\n        elif case["status"] != "processing":\n', '            _log(case_id, "Backend + Ollama outcome present — will calculate final risk")\n        elif case["status"] != "processing":\n', 1)
# Add failure detection before model validate
needle='async def handle_ollama_report(\n    data: dict[str, Any],\n) -> dict[str, Any]:\n\n    report = LogicAnalysisReport.model_validate(data)\n'
repl='async def handle_ollama_report(\n    data: dict[str, Any],\n) -> dict[str, Any]:\n\n    def contains_ollama_failure(value: Any, depth: int = 0) -> bool:\n        if depth > 8 or value is None:\n            return False\n        if isinstance(value, str):\n            return value.strip().upper() == "OLLAMA FAILED"\n        if isinstance(value, list):\n            return any(contains_ollama_failure(item, depth + 1) for item in value)\n        if isinstance(value, dict):\n            return any(contains_ollama_failure(item, depth + 1) for item in value.values())\n        return False\n\n    if contains_ollama_failure(data):\n        case_id = str(data.get("case_id") or data.get("email_id") or "").strip()\n        if not case_id:\n            raise HTTPException(status_code=422, detail="OLLAMA Failed signal must include case_id.")\n        _log(case_id, "Ollama returned OLLAMA Failed — falling back to Subhom-only scoring")\n        async with cases_lock:\n            if case_id not in cases:\n                cases[case_id] = create_case()\n            case = cases[case_id]\n            if case["status"] == "completed":\n                return {"case_id": case_id, "status": "already_completed", "result": case.get("result")}\n            case["ollama"] = None\n            case["ollama_failed"] = True\n            case["updated_at"] = utc_now()\n            should_process = case.get("backend") is not None\n            if should_process:\n                case["status"] = "waiting"\n        if should_process:\n            asyncio.create_task(process_case(case_id))\n        return {"case_id": case_id, "status": "accepted", "message": "Ollama failure accepted; Subhom-only fallback enabled.", "ollama_failed": True}\n\n    report = LogicAnalysisReport.model_validate(data)\n'
if needle not in s: raise SystemExit('needle not found')
s=s.replace(needle,repl)
# status responses
s=s.replace('                "analysis_confidence": result.get("analysis_confidence"),\n', '                "analysis_confidence": result.get("analysis_confidence"),\n                "analysis_mode": result.get("analysis_mode"),\n                "confidence_explanation": result.get("confidence_explanation"),\n')
s=s.replace('                "has_ollama": (\n                case.get("ollama") is not None\n            ),', '                "has_ollama": (case.get("ollama") is not None),\n                "ollama_failed": bool(case.get("ollama_failed")),')
# The above exact indent may not match; generic status block later
s=s.replace('            "has_ollama": (\n                case.get("ollama") is not None\n            ),\n', '            "has_ollama": (case.get("ollama") is not None),\n            "ollama_failed": bool(case.get("ollama_failed")),\n')
p.write_text(s)

# CSS additions
p=root/'frontend/src/index.css'
s=p.read_text()
s += r'''

.batch-upload-summary { display:grid; gap:14px; }
.batch-upload-summary__head { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:2px 2px 0; }
.batch-upload-summary__head strong { color:#dce8eb; font:700 13px/1.2 var(--font-display); }
.batch-upload-summary__head span { color:#6e818a; font:800 7px/1 var(--font-mono); letter-spacing:.12em; }
.batch-upload-list { display:grid; gap:9px; }
.batch-upload-list .settle { background:rgba(255,255,255,.018); }
.batch-upload-actions { display:flex; align-items:center; justify-content:space-between; gap:10px; }

.provided-gmail-shell { margin:0 0 14px; border:1px solid rgba(109,224,242,.16); background:rgba(8,13,17,.82); overflow:hidden; }
.provided-gmail-head { display:flex; align-items:center; justify-content:space-between; gap:18px; padding:16px 18px; }
.provided-gmail-head h2 { margin:6px 0 0; font:700 20px/1 var(--font-display); letter-spacing:-.03em; }
.provided-gmail-head p { margin:7px 0 0; color:#61737c; font-size:10.5px; line-height:1.5; }
.provided-gmail-modal { position:fixed; inset:0; z-index:1000; display:grid; place-items:center; padding:28px; }
.provided-gmail-modal__backdrop { position:absolute; inset:0; background:rgba(1,4,6,.84); backdrop-filter:blur(8px); }
.provided-gmail-modal__panel { position:relative; z-index:1; width:min(1100px, 96vw); max-height:min(88vh, 900px); }
.provided-gmail-modal__paper { position:relative; max-height:min(88vh, 900px); overflow:hidden; border:1px solid rgba(217,190,124,.28); background:linear-gradient(145deg, rgba(16,18,18,.98), rgba(28,27,23,.98)); box-shadow:0 32px 90px rgba(0,0,0,.55), inset 0 0 70px rgba(235,199,119,.035); }
.provided-gmail-modal__paper::before { content:""; position:absolute; inset:0; pointer-events:none; background:repeating-linear-gradient(90deg, transparent 0 46px, rgba(255,255,255,.025) 47px, transparent 48px), linear-gradient(180deg, rgba(255,255,255,.02), transparent 18%, rgba(0,0,0,.08)); mix-blend-mode:screen; }
.provided-gmail-modal__paper-head { position:sticky; top:0; z-index:2; display:flex; justify-content:space-between; gap:12px; padding:13px 16px; border-bottom:1px solid rgba(255,255,255,.08); background:rgba(9,11,11,.94); color:#9e8b63; font:800 8px/1 var(--font-mono); letter-spacing:.14em; }
.provided-gmail-modal__paper-head button { border:0; background:none; color:#82939b; font:800 8px/1 var(--font-mono); letter-spacing:.1em; cursor:pointer; }
.provided-gmail-modal__paper pre { position:relative; z-index:1; max-height:calc(min(88vh, 900px) - 49px); margin:0; padding:22px; overflow:auto; white-space:pre-wrap; word-break:break-word; color:#e7ded0; font:12px/1.65 var(--font-mono); }
.result-degraded-notice { display:flex; align-items:flex-start; gap:9px; margin:0 0 14px; padding:13px 15px; border:1px solid rgba(235,180,96,.28); background:rgba(235,180,96,.065); color:#d8bd8b; }
.result-degraded-notice strong { color:#f0d49d; }
.result-degraded-notice div { font-size:11.5px; line-height:1.55; }
.batch-results-stack { padding:24px 28px 44px; display:grid; }
.batch-result-layer { position:relative; min-width:0; border:1px solid rgba(255,255,255,.08); background:rgba(5,9,12,.72); box-shadow:0 22px 60px rgba(0,0,0,.24); padding-top:18px; }
.batch-result-layer + .batch-result-layer { margin-top:-9px; box-shadow:0 18px 55px rgba(0,0,0,.34); }
.batch-result-layer__index { padding:0 22px 12px; color:#66808a; font:800 7px/1 var(--font-mono); letter-spacing:.15em; }
.batch-result-layer .result-page { padding-inline:22px; }
@media (max-width: 900px) { .provided-gmail-head { align-items:flex-start; flex-direction:column; } .batch-results-stack { padding-inline:14px; } .batch-result-layer .result-page { padding-inline:14px; } }
'''
p.write_text(s)

print('patched')
