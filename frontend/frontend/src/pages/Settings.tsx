/* ========================================================================== 
   Settings — read-only view of the frontend transport configuration.
   ========================================================================== */

import { Header } from '../components/Header';
import { Alert } from '../components/Alert';
import { Field, Section } from '../components/primitives';
import { formatBytes } from '../lib/format';
import { config, describeLogicTarget, describeTarget } from '../services/api';

function EnvRow({
  name,
  value,
  note,
}: {
  name: string;
  value: string;
  note: string;
}) {
  return (
    <tr className="border-b border-line last:border-b-0">
      <td className="datum px-5 py-2.5 align-top text-[11.5px] text-ink">{name}</td>
      <td className="datum px-3 py-2.5 align-top text-[11.5px] text-ink-2 break-all">{value}</td>
      <td className="px-5 py-2.5 align-top text-[12px] leading-snug text-ink-3">{note}</td>
    </tr>
  );
}

export function Settings() {
  return (
    <>
      <Header title="Settings" description="Read-only. Values come from frontend/.env — restart Vite after editing." />

      <div className="max-w-3xl space-y-4 px-7 py-6">
        <Section title="Connection — two base URLs">
          <div className="grid gap-5 px-5 py-5 sm:grid-cols-2">
            <Field label="Backend URL (Subhom upload)" value={config.backendBaseUrl} />
            <Field label="Upload target" value={describeTarget()} />
            <Field label="Logic receiver (poll)" value={config.logicBaseUrl} />
            <Field label="Poll target" value={describeLogicTarget()} />
            <Field label="Final report path" value={`${config.analysisPath}/{case_id}`} />
            <Field label="Poll interval" value={`${config.pollIntervalMs}ms`} />
            <Field label="Timeout" value={`${Math.round(config.timeoutMs / 1000)}s`} />
            <Field label="Upload guard rail" value={formatBytes(config.maxUploadBytes)} />
          </div>
        </Section>

        <Section
          title="Expected API contract"
          caption="Async two-phase: upload to Subhom, poll Logic Receiver (source of truth)."
        >
          <div className="space-y-4 px-5 py-5 text-[12.5px] leading-relaxed text-ink-2">
            <p>
              The browser uploads the original <span className="datum text-ink">.EML</span> file
              with <span className="datum text-ink">POST {config.analyzePath}</span> to{' '}
              <span className="datum text-ink">{config.backendBaseUrl}</span> using
              <span className="datum text-ink"> multipart/form-data</span> and a field named
              <span className="datum text-ink"> email</span>. Backend returns{' '}
              <span className="datum text-ink">202 Accepted + case_id</span> — this means &quot;accepted &amp; processing&quot;, not an error.
            </p>
            <p>
              The backend performs email parsing, security &amp; threat analysis, then forwards
              evidence to Ollama and to MY logic receiver (<span className="datum text-ink">POST /receive-analysis</span>).
              Ollama forwards its result to <span className="datum text-ink">POST /receive-ollama</span>.
              When both parts arrive for the same <span className="datum text-ink">case_id</span>, logic correlates and stores the final report.
            </p>
            <p>
              The browser polls <span className="datum text-ink">GET {config.analysisPath}/&#123;case_id&#125;</span> on{' '}
              <span className="datum text-ink">{config.logicBaseUrl}</span> (Logic Receiver — source of truth)
              until <span className="datum text-ink">status=completed</span> then renders security / threat / AI / verdict.
              The final risk score is owned by the Logic Receiver; it does not travel back through Subhom for display.
              This avoids &quot;Unable to connect to backend&quot; when the backend correctly returned 202 and is still processing.
            </p>
            <p>
              <span className="datum text-ink">GET /health</span> on the logic receiver checks if it&apos;s reachable, distinct from &quot;analysis still processing&quot;.
            </p>
          </div>
        </Section>

        <Section title="Environment" caption="Edit frontend/.env, then restart the Vite server. Do NOT hardcode trycloudflare URLs in source.">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] border-collapse text-left">
              <thead>
                <tr className="border-b border-line">
                  <th scope="col" className="eyebrow px-5 py-2.5 font-semibold">Variable</th>
                  <th scope="col" className="eyebrow px-3 py-2.5 font-semibold">Current</th>
                  <th scope="col" className="eyebrow px-5 py-2.5 font-semibold">Purpose</th>
                </tr>
              </thead>
              <tbody>
                <EnvRow
                  name="VITE_BACKEND_BASE_URL"
                  value={config.backendBaseUrl}
                  note="Subhom public backend — POST /receive-email. Cloudflare tunnel, changes dynamically."
                />
                <EnvRow
                  name="VITE_API_BASE_URL"
                  value={config.backendBaseUrl}
                  note="Legacy alias for VITE_BACKEND_BASE_URL."
                />
                <EnvRow
                  name="VITE_LOGIC_BASE_URL"
                  value={config.logicBaseUrl}
                  note="Logic Receiver — GET /analysis/{case_id}. Same-machine: http://127.0.0.1:8000, multi-machine: https://<logic>.trycloudflare.com. Must be reachable by browser."
                />
                <EnvRow
                  name="VITE_ANALYZE_PATH"
                  value={config.analyzePath}
                  note="Accepts the .EML upload."
                />
                <EnvRow
                  name="VITE_ANALYSIS_PATH"
                  value={config.analysisPath}
                  note="Returns {status, result} for a case_id (polled)."
                />
                <EnvRow
                  name="VITE_API_TIMEOUT_MS"
                  value={String(config.timeoutMs)}
                  note="Polling deadline."
                />
                <EnvRow
                  name="VITE_ANALYSIS_POLL_INTERVAL_MS"
                  value={String(config.pollIntervalMs)}
                  note="Interval between poll requests."
                />
                <EnvRow
                  name="VITE_MAX_UPLOAD_MB"
                  value={String(Math.round(config.maxUploadBytes / (1024 * 1024)))}
                  note="Browser-side guard rail only."
                />
              </tbody>
            </table>
          </div>
        </Section>

        <Alert
          tone="info"
          message="The browser does not perform security analysis."
          detail="Parsing, authentication checks, threat intelligence, AI assessment, scoring, correlation and verdict logic remain server-side. The browser only uploads and polls by case_id."
        />
      </div>
    </>
  );
}
