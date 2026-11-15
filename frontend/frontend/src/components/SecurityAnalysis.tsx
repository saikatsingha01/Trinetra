/* ==========================================================================
   SecurityAnalysisPanel — renders backend.security_analysis.
   --------------------------------------------------------------------------
   SPF / DKIM / DMARC results, sender identity and header findings, exactly as
   supplied. The frontend does not evaluate authentication; it labels the
   result strings that logic/models.py defines.
   ========================================================================== */

import type { SecurityAnalysis } from '../types/analysis';
import { authTone, neutralTone, severityTone } from '../lib/severity';
import { humanizeToken } from '../lib/format';
import { Badge, Chip, EmptyNote, Field, Section, StatusRow } from './primitives';

export function SecurityAnalysisPanel({ data }: { data?: SecurityAnalysis | null }) {
  if (!data) {
    return (
      <Section title="Security analysis">
        <EmptyNote>The response did not include a security analysis.</EmptyNote>
      </Section>
    );
  }

  const identity = data.sender_identity;
  const headers = data.header_analysis;

  return (
    <Section title="Security analysis">
      {/* --- authentication ------------------------------------------------ */}
      <div>
        <StatusRow
          label="SPF"
          tone={authTone(data.spf.result)}
          status={data.spf.result}
          detail={
            data.spf.domain || data.spf.record
              ? [data.spf.domain, data.spf.record].filter(Boolean).join(' · ')
              : undefined
          }
        />
        <StatusRow
          label="DKIM"
          tone={authTone(data.dkim.result)}
          status={data.dkim.result}
          detail={
            data.dkim.domain || data.dkim.selector
              ? [data.dkim.domain, data.dkim.selector && `selector: ${data.dkim.selector}`]
                  .filter(Boolean)
                  .join(' · ')
              : undefined
          }
        />
        <StatusRow
          label="DMARC"
          tone={authTone(data.dmarc.result)}
          status={data.dmarc.result}
          detail={
            data.dmarc.policy || data.dmarc.alignment
              ? [
                  data.dmarc.domain,
                  data.dmarc.policy && `policy: ${data.dmarc.policy}`,
                  data.dmarc.alignment && `alignment: ${data.dmarc.alignment}`,
                ]
                  .filter(Boolean)
                  .join(' · ')
              : undefined
          }
        />
      </div>

      {/* --- DNS ------------------------------------------------------------ */}
      <div className="border-t border-line px-5 py-5">
        <div className="flex items-center justify-between gap-3">
          <span className="eyebrow">DNS analysis</span>
          {data.dns && (
            <Badge tone={neutralTone}>Workflow 2 evidence</Badge>
          )}
        </div>

        {data.dns ? (
          <>
            {data.dns.dns_report.length > 0 ? (
              <div className="mt-4 space-y-4">
                {data.dns.dns_report.map((report) => (
                  <div key={report.domain} className="rounded-sm border border-line bg-inset p-3">
                    <div className="datum text-[12px] font-medium text-ink">{report.domain}</div>
                    <div className="mt-3 space-y-2">
                      {Object.entries(report.records).map(([recordType, values]) => (
                        <div key={`${report.domain}-${recordType}`} className="grid gap-2 sm:grid-cols-[72px_1fr]">
                          <span className="eyebrow pt-1">{recordType}</span>
                          <div className="space-y-1">
                            {(Array.isArray(values) ? values : []).length > 0 ? (
                              values.map((value, index) => (
                                <div key={`${recordType}-${index}`} className="datum break-all rounded-sm border border-line px-2.5 py-1.5 text-[11px] text-ink-2">
                                  {value}
                                </div>
                              ))
                            ) : (
                              <span className="text-[11px] text-ink-4">No value returned.</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-3 text-[12px] text-ink-3">No DNS domain reports were returned.</p>
            )}

            {data.dns.reverse_dns_report.length > 0 && (
              <div className="mt-5 border-t border-line pt-4">
                <span className="eyebrow">Reverse DNS</span>
                <div className="mt-3 space-y-2">
                  {data.dns.reverse_dns_report.map((report) => (
                    <div key={report.ip} className="rounded-sm border border-line bg-inset px-3 py-2.5">
                      <div className="datum text-[11.5px] text-ink">{report.ip}</div>
                      <div className="mt-1 text-[11px] text-ink-3">
                        {report.hosts.length > 0 ? report.hosts.join(' · ') : 'No reverse DNS host returned.'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <p className="mt-3 text-[12px] text-ink-3">DNS evidence was not included in the returned security analysis.</p>
        )}
      </div>

      {/* --- sender identity ----------------------------------------------- */}
      <div className="border-t border-line px-5 py-5">
        <div className="flex items-center justify-between gap-3">
          <span className="eyebrow">Sender identity</span>
          {identity && (
            <Badge
              tone={identity.domain_consistent ? authTone('pass') : severityTone('high')}
            >
              {identity.domain_consistent ? 'Consistent' : 'Inconsistent'}
            </Badge>
          )}
        </div>

        {identity ? (
          <div className="mt-4 grid gap-5 sm:grid-cols-3">
            <Field label="From" value={identity.from} />
            <Field label="Return-Path" value={identity.return_path} />
            <Field label="Reply-To" value={identity.reply_to} />
          </div>
        ) : (
          <p className="mt-3 text-[12.5px] text-ink-3">No sender identity was reported.</p>
        )}
      </div>

      {/* --- header analysis ----------------------------------------------- */}
      <div className="border-t border-line px-5 py-5">
        <div className="flex items-center justify-between gap-3">
          <span className="eyebrow">Header analysis</span>
          <Badge tone={headers.relay_anomaly ? severityTone('high') : neutralTone}>
            {headers.relay_anomaly ? 'Relay anomaly' : 'No relay anomaly'}
          </Badge>
        </div>

        <div className="mt-4 grid gap-5 sm:grid-cols-2">
          <Field label="IP hops" value={String(headers.ip_hops)} />
          <Field label="Suspicious headers" value={String(headers.suspicious_headers.length)} />
        </div>

        {headers.suspicious_headers.length > 0 && (
          <ul className="mt-4 space-y-1.5">
            {headers.suspicious_headers.map((header) => (
              <li
                key={header}
                className="datum rounded-sm border border-line bg-inset px-2.5 py-1.5 text-[11.5px] text-ink-2"
              >
                {header}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* --- suspicious indicators ----------------------------------------- */}
      {data.suspicious_indicators.length > 0 && (
        <div className="border-t border-line px-5 py-5">
          <span className="eyebrow">Suspicious indicators</span>
          <div className="mt-2.5 flex flex-wrap gap-1.5">
            {data.suspicious_indicators.map((indicator) => (
              <Chip key={indicator}>{humanizeToken(indicator)}</Chip>
            ))}
          </div>
        </div>
      )}
    </Section>
  );
}
