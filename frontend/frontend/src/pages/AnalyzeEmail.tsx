import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/Header';
import { UploadZone } from '../components/UploadZone';
import { FilePreview } from '../components/FilePreview';
import { AnalysisProgress } from '../components/AnalysisProgress';
import { Alert } from '../components/Alert';
import { Button } from '../components/primitives';
import { IconArrowRight, IconTrash } from '../components/icons';
import { analyzeEmail, toUserMessage } from '../services/api';
import { useSession } from '../store/session';
import { takePendingFile } from '../store/pendingUpload';

type Phase = 'choose' | 'ready' | 'running';
interface Failure { message: string; detail?: string }

export function AnalyzeEmail() {
  const navigate = useNavigate();
  const { recordReport } = useSession();
  const [files, setFiles] = useState<File[]>([]);
  const [phase, setPhase] = useState<Phase>('choose');
  const [failure, setFailure] = useState<Failure | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const [loaderTarget, setLoaderTarget] = useState(12);
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    const staged = takePendingFile();
    if (staged) { setFiles([staged]); setPhase('ready'); }
  }, []);
  useEffect(() => () => abortRef.current?.abort(), []);

  async function run() {
    if (!files.length || phase === 'running' || abortRef.current) return;
    const controller = new AbortController();
    const analysisStartedAt = performance.now();
    abortRef.current = controller; setFailure(null); setLoaderTarget(12); setPhase('running');
    const successful: string[] = [];
    try {
      for (let index = 0; index < files.length; index += 1) {
        const file = files[index];
        setCurrentIndex(index);
        setLoaderTarget(Math.max(12, Math.round((index / files.length) * 88)));
        const report = await analyzeEmail(file, {
          signal: controller.signal,
          onProgress: (event) => {
            const base = (index / files.length) * 88;
            const span = 88 / files.length;
            if (event.type === 'upload-start') setLoaderTarget((current) => Math.max(current, base + span * 0.18));
            if (event.type === 'case-received') setLoaderTarget((current) => Math.max(current, base + span * 0.39));
            if (event.type === 'security-analysis-received') setLoaderTarget((current) => Math.max(current, base + span * 0.60));
            if (event.type === 'analysis-complete') setLoaderTarget((current) => Math.max(current, base + span));
          },
        });
        const providedEmail = await file.text();
        recordReport({
          ...report,
          provided_email: providedEmail,
          processing_time_ms: Math.round(performance.now() - analysisStartedAt),
        });
        successful.push(report.case_id);
      }
      setLoaderTarget(100);
      await new Promise((resolve) => window.setTimeout(resolve, 550));
      if (successful.length === 1) navigate(`/cases/${encodeURIComponent(successful[0])}`, { replace: true });
      else navigate(`/cases/batch?ids=${encodeURIComponent(successful.join(','))}`, { replace: true });
    } catch (error) {
      if (controller.signal.aborted) { setPhase('ready'); return; }
      setFailure(toUserMessage(error)); setPhase('ready');
    } finally { abortRef.current = null; }
  }

  if (phase === 'running') {
    const label = files.length > 1 ? `Email ${currentIndex + 1} of ${files.length} — ${files[currentIndex]?.name ?? ''}` : files[0]?.name ?? '';
    return <AnalysisProgress filename={label} externalTarget={loaderTarget} onCancel={() => { abortRef.current?.abort(); setPhase('ready'); }} />;
  }

  return (
    <>
      <Header title="Analyze email" description="Upload up to five .EML messages and review each assessment with result tabs." />
      <div className="internal-pad">
        <div className="analysis-layout">
          <div className="analysis-intro">
            <div className="micro-label">INGESTION WORKSPACE</div>
            <h2>Submit one or more messages.</h2>
            <p>TRINETRA sends each message through the same connected pipeline. Multiple uploads are processed safely one by one, then shown together as switchable result tabs.</p>
            <div className="analysis-note"><span>01</span><div><strong>Upload</strong><small>Choose 1–5 valid .EML messages.</small></div></div>
            <div className="analysis-note"><span>02</span><div><strong>Analyze</strong><small>TRINETRA processes each message through the connected pipeline.</small></div></div>
            <div className="analysis-note"><span>03</span><div><strong>Review</strong><small>See the provided Gmail and the full assessment for every message.</small></div></div>
          </div>
          <div className="analysis-card">
            {failure && <Alert tone="error" message={failure.message} detail={failure.detail} action={files.length ? <Button variant="secondary" size="sm" onClick={run}>Retry</Button> : undefined} />}
            {files.length ? (
              <>
                <div className="batch-upload-summary">
                  <div className="batch-upload-add">
                    <UploadZone
                      disabled={files.length >= 5}
                      onSelect={(selected) => {
                        setFailure(null);
                        setFiles((current) => {
                          const seen = new Set(current.map((file) => `${file.name}:${file.size}:${file.lastModified}`));
                          const merged = [...current];
                          for (const file of selected) {
                            const key = `${file.name}:${file.size}:${file.lastModified}`;
                            if (!seen.has(key) && merged.length < 5) {
                              seen.add(key);
                              merged.push(file);
                            }
                          }
                          return merged;
                        });
                        setPhase('ready');
                      }}
                      onReject={(m) => setFailure({ message: m })}
                    />
                    <div className="batch-upload-add__hint">{files.length >= 5 ? 'Maximum of 5 messages reached.' : `Add more Gmail messages (${5 - files.length} slot${5 - files.length === 1 ? '' : 's'} remaining).`}</div>
                  </div>
                  <div className="batch-upload-summary__head"><strong>{files.length} {files.length === 1 ? 'Gmail' : 'Gmails'} selected</strong><span>MAX 5</span></div>
                  <div className="batch-upload-list">
                    {files.map((file, index) => <FilePreview key={`${file.name}-${file.lastModified}-${index}`} file={file} onRemove={() => setFiles((current) => current.filter((_, i) => i !== index))} />)}
                  </div>
                  <div className="batch-upload-actions">
                    <Button variant="ghost" size="sm" onClick={() => { setFiles([]); setFailure(null); }}><IconTrash size={13} /> Clear</Button>
                    <Button variant="primary" size="lg" onClick={run} autoFocus>Analyze {files.length > 1 ? 'emails' : 'email'} <IconArrowRight size={15} /></Button>
                  </div>
                </div>
              </>
            ) : (
              <UploadZone onSelect={(selected) => { setFailure(null); setFiles(selected); setPhase('ready'); }} onReject={(m) => setFailure({ message: m })} />
            )}
          </div>
        </div>
      </div>
    </>
  );
}
