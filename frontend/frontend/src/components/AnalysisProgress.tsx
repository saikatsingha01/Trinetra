import { useEffect, useRef, useState } from 'react';
import { Button } from './primitives';

type LoaderStage = 'upload' | 'parsing' | 'subhom' | 'ollama' | 'finalizing' | 'complete';

const STAGES: Array<{ id: LoaderStage; label: string }> = [
  { id: 'upload', label: 'Email uploaded' },
  { id: 'parsing', label: 'Email parsing' },
  { id: 'subhom', label: 'Security & threat analysis' },
  { id: 'ollama', label: 'Ollama AI assessment' },
  { id: 'finalizing', label: 'Finalizing analysis' },
];

function Spinner() {
  return (
    <div className="trinetra-spinner" aria-hidden="true">
      {Array.from({ length: 8 }, (_, index) => <span key={index} />)}
    </div>
  );
}

function stageForProgress(progress: number): LoaderStage {
  if (progress >= 100) return 'complete';
  if (progress >= 90) return 'finalizing';
  if (progress >= 60) return 'ollama';
  if (progress >= 40) return 'subhom';
  if (progress >= 18) return 'parsing';
  return 'upload';
}

function stageCopy(stage: LoaderStage) {
  switch (stage) {
    case 'upload': return ['Uploading email', 'Sending the message into the connected pipeline.'];
    case 'parsing': return ['Parsing email', 'Reading the message structure, headers and content.'];
    case 'subhom': return ['Security analysis', 'TRINETRA is processing security and threat signal.'];
    case 'ollama': return ['AI assessment', 'Ollama is evaluating the correlated analysis.'];
    case 'finalizing': return ['Finalizing analysis', 'Preparing the complete TRINETRA report.'];
    case 'complete': return ['Analysis complete', 'Opening the final security report.'];
  }
}

export function AnalysisProgress({
  filename,
  onCancel,
  onSubhomReceived,
  onAnalysisComplete,
  externalTarget,
}: {
  filename: string;
  externalTarget?: number;
  onCancel?: () => void;
  onSubhomReceived?: () => void;
  onAnalysisComplete?: () => void;
}) {
  const [target, setTarget] = useState(externalTarget ?? 12);

  useEffect(() => {
    if (typeof externalTarget === 'number') setTarget((value) => Math.max(value, externalTarget));
  }, [externalTarget]);
  const [progress, setProgress] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const completionTriggered = useRef(false);

  // Smoothly chase the target instead of jumping between backend events.
  useEffect(() => {
    const id = window.setInterval(() => {
      setProgress((current) => {
        const delta = target - current;
        if (Math.abs(delta) < 0.35) return target;
        return current + delta * (target >= 90 ? 0.22 : 0.09);
      });
      setElapsedMs((value) => value + 100);
    }, 100);
    return () => window.clearInterval(id);
  }, [target]);

  const stage = stageForProgress(progress);
  const [title, subtitle] = stageCopy(stage);

  useEffect(() => {
    if (target >= 60 && target < 90) onSubhomReceived?.();
  }, [target, onSubhomReceived]);

  useEffect(() => {
    if (target === 100 && progress > 99.5 && !completionTriggered.current) {
      completionTriggered.current = true;
      onAnalysisComplete?.();
    }
  }, [target, progress, onAnalysisComplete]);

  const stageIndex = stage === 'complete' ? STAGES.length : STAGES.findIndex((item) => item.id === stage);

  return (
    <div className="trinetra-loader-page" role="status" aria-live="polite" aria-label="TRINETRA analysis in progress">
      <div className="trinetra-loader-glow" />
      <div className="trinetra-loader-card">
        <div className="trinetra-loader-kicker">TRINETRA // ANALYSIS PIPELINE</div>
        <Spinner />
        <div className="trinetra-loader-percent">{Math.min(100, Math.round(progress))}%</div>
        <h1>{title}</h1>
        <p className="trinetra-loader-subtitle">{subtitle}</p>
        <p className="trinetra-loader-file">{filename}</p>

        <div className="trinetra-progress" aria-label={`Analysis ${Math.round(progress)} percent complete`}>
          <div className="trinetra-progress-value" style={{ width: `${Math.min(100, progress)}%` }} />
        </div>

        <div className="trinetra-stage-list">
          {STAGES.map((item, index) => {
            const done = index < stageIndex;
            const active = index === stageIndex && stage !== 'complete';
            return (
              <div key={item.id} className={`trinetra-stage ${done ? 'is-done' : ''} ${active ? 'is-active' : ''}`}>
                <span className="trinetra-stage-mark">{done ? '✓' : active ? '◉' : '○'}</span>
                <span>{item.label}</span>
              </div>
            );
          })}
        </div>

        <div className="trinetra-loader-footer">
          <span>{(elapsedMs / 1000).toFixed(1)}s elapsed</span>
          {onCancel && <Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>}
        </div>
      </div>
    </div>
  );
}

