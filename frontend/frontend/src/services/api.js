/* ==========================================================================
   TRINETRA frontend transport layer — async two-phase (Logic Receiver is source of truth).

   Phase A (upload):  Frontend -> Subhom /receive-email  (Cloudflare)
                      POST multipart/form-data field "email" with ONE raw .eml
                      -> 202 {status:"processing", case_id}
   Phase B (poll):    Frontend -> Logic Receiver GET /analysis/{case_id}
                      (VITE_LOGIC_BASE_URL — Cloudflare URL when multi-machine,
                       or http://127.0.0.1:8000 when logic runs on same machine)
                      -> poll until {status:"completed", risk_score, verdict, ...}

   Architecture rule (master prompt #1):
      Logic Receiver OWNS final risk_score + verdict and exposes GET /analysis/{case_id}.
      Frontend NEVER polls Subhom's /analysis for final result.
      Logic Receiver does NOT need to POST final result back to Subhom for display.

   Behind the scenes:
      Subhom -> security/threat parsing -> POST /receive-analysis (Logic)
      Ollama -> POST /receive-ollama (Logic) -> Logic Receiver correlates via case_id
      -> stores final report -> Frontend GET /analysis/{case_id}

   VITE_LOGIC_BASE_URL must be reachable by the browser:
      - same machine: http://127.0.0.1:8000 or http://localhost:8000
      - multi-machine: https://<LOGIC-CLOUDFLARE-URL> (trycloudflare / named tunnel)
   ========================================================================== */
import { VERDICTS } from '../types/analysis';
function env(key) {
    const value = import.meta.env[key];
    return value == null || value === '' ? undefined : value;
}
export const config = {
    // Subhom backend — upload target (Cloudflare tunnel, e.g. https://<subhom>.trycloudflare.com)
    // Used ONLY for POST /receive-email; frontend does NOT poll Subhom for final result.
    backendBaseUrl: (env('VITE_BACKEND_BASE_URL') ??
        env('VITE_API_BASE_URL') ??
        'http://localhost:8000').replace(/\/+$/, ''),
    // Compatibility alias — older code reads config.baseUrl; points to backend
    get baseUrl() {
        return this.backendBaseUrl;
    },
    // Logic Receiver — poll target (source of truth for final risk score + verdict)
    // Browser must be able to reach this URL directly.
    // Same-machine: http://127.0.0.1:8000  Multi-machine: https://<LOGIC-CLOUDFLARE-URL>
    logicBaseUrl: (env('VITE_LOGIC_BASE_URL') ??
        'http://127.0.0.1:8000').replace(/\/+$/, ''),
    analyzePath: (env('VITE_ANALYZE_PATH') ?? '/receive-email').replace(/\/+$/, '') || '/receive-email',
    analysisPath: (env('VITE_ANALYSIS_PATH') ?? '/analysis').replace(/\/+$/, '') || '/analysis',
    timeoutMs: Number(env('VITE_API_TIMEOUT_MS') ?? 300000),
    pollIntervalMs: Number(env('VITE_ANALYSIS_POLL_INTERVAL_MS') ?? env('VITE_POLL_INTERVAL_MS') ?? 1500),
    maxUploadBytes: Number(env('VITE_MAX_UPLOAD_MB') ?? 25) * 1024 * 1024,
};
export function describeTarget() {
    return `${config.backendBaseUrl}${config.analyzePath}`;
}
export function describeLogicTarget(caseId = '{case_id}') {
    return `${config.logicBaseUrl}${config.analysisPath}/${caseId}`;
}
export class ApiError extends Error {
    constructor(message, detail) {
        super(message);
        this.name = 'ApiError';
        this.detail = detail;
    }
}
export class InvalidFileError extends ApiError {
    constructor(message = 'Please upload a valid .EML file.', detail) {
        super(message, detail);
        this.name = 'InvalidFileError';
    }
}
export class BackendUnavailableError extends ApiError {
    constructor(message = 'Unable to connect to the TRINETRA backend. Make sure the API server is running.', detail) {
        super(message, detail);
        this.name = 'BackendUnavailableError';
    }
}
export class LogicUnavailableError extends ApiError {
    constructor(message = 'Unable to connect to the Logic Receiver. Make sure it is running and reachable at the configured VITE_LOGIC_BASE_URL.', detail) {
        super(message, detail);
        this.name = 'LogicUnavailableError';
    }
}
export class UploadFailedError extends ApiError {
    constructor(message = 'Email upload failed. Please try again.', detail) {
        super(message, detail);
        this.name = 'UploadFailedError';
    }
}
export class AnalysisFailedError extends ApiError {
    constructor(message = 'Analysis failed. The email could not be analyzed.', detail) {
        super(message, detail);
        this.name = 'AnalysisFailedError';
    }
}
export const ACCEPTED_EXTENSION = '.eml';
export const ACCEPT_ATTRIBUTE = '.eml';
export function validateEmlFile(file) {
    if (!file) {
        return { reason: 'empty', message: 'Please upload a valid .EML file.' };
    }
    if (!file.name.toLowerCase().endsWith(ACCEPTED_EXTENSION)) {
        return {
            reason: 'extension',
            message: 'Invalid file type. Please upload an .EML email file.',
        };
    }
    if (file.size === 0) {
        return { reason: 'empty', message: 'That file is empty. Please choose another .EML file.' };
    }
    if (file.size > config.maxUploadBytes) {
        const mb = Math.round(config.maxUploadBytes / (1024 * 1024));
        return {
            reason: 'too-large',
            message: `That file is larger than ${mb} MB. Choose a smaller .EML file.`,
        };
    }
    return null;
}
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : undefined;
}
function asArray(value) {
    return Array.isArray(value) ? value : [];
}
function asVerdict(value) {
    if (typeof value !== 'string')
        return undefined;
    const upper = value.toUpperCase();
    return VERDICTS.includes(upper) ? upper : undefined;
}
function normaliseSender(value) {
    const raw = asRecord(value);
    if (!raw)
        return null;
    return {
        from: typeof raw.from === 'string'
            ? raw.from
            : typeof raw.from_address === 'string'
                ? raw.from_address
                : '',
        return_path: typeof raw.return_path === 'string' ? raw.return_path : null,
        reply_to: typeof raw.reply_to === 'string' ? raw.reply_to : null,
        domain_consistent: raw.domain_consistent !== false,
    };
}
function normaliseSecurity(value) {
    const raw = asRecord(value);
    if (!raw)
        return null;
    // Preferred final contract: already in frontend/logic normalized shape.
    if (asRecord(raw.spf) && asRecord(raw.dkim) && asRecord(raw.dmarc)) {
        return raw;
    }
    // Backward compatibility with the raw Subhom workflow shape.
    const auth = asRecord(raw.authentication_analysis) ?? {};
    const sender = asRecord(raw.sender_analysis) ?? {};
    const header = asRecord(raw.header_analysis) ?? {};
    const firstResult = (value) => {
        if (Array.isArray(value) && value.length > 0) {
            const first = value[0];
            if (Array.isArray(first) && first.length > 0)
                return String(first[0]);
            if (typeof first === 'string')
                return first;
        }
        if (typeof value === 'string')
            return value;
        if (typeof value === 'boolean')
            return value ? 'pass' : 'fail';
        if (asRecord(value) && typeof asRecord(value)?.result === 'string') {
            return String(asRecord(value)?.result);
        }
        return 'unknown';
    };
    const senderNormalised = normaliseSender(sender);
    const from = typeof asRecord(sender.from)?.email_address === 'string'
        ? String(asRecord(sender.from)?.email_address)
        : '';
    const reply = typeof asRecord(sender.reply_to)?.email_address === 'string'
        ? String(asRecord(sender.reply_to)?.email_address)
        : null;
    const returnPath = typeof asRecord(sender.return_path)?.email_address === 'string'
        ? String(asRecord(sender.return_path)?.email_address)
        : null;
    const domains = [from, reply ?? '', returnPath ?? '']
        .filter((address) => address.includes('@'))
        .map((address) => address.split('@').pop()?.toLowerCase() ?? '');
    const findings = asArray(sender.findings)
        .concat(asArray(header.findings));
    const mismatchFinding = findings.some((item) => /mismatch|spoof/i.test(String(item)));
    const securitySender = senderNormalised ?? {
        from,
        return_path: returnPath,
        reply_to: reply,
        domain_consistent: true,
    };
    securitySender.domain_consistent =
        domains.length < 2 || new Set(domains).size === 1;
    if (mismatchFinding)
        securitySender.domain_consistent = false;
    const received = asArray(header.received);
    const authResults = asArray(header.authentication_results);
    const headerFinding = findings.some((item) => /anomaly|suspicious|mismatch|spoof/i.test(String(item)));
    const suspiciousHeaders = findings
        .map(String)
        .concat(authResults.map(String))
        .concat(received.slice(0, 5).map(String))
        .slice(0, 10);
    const suspiciousIndicators = asArray(raw.phishing_analysis)
        .map((item) => {
        const record = asRecord(item);
        return record?.indicator ?? record?.evidence ?? item;
    })
        .map(String)
        .filter(Boolean);
    if (findings.some((item) => /spoof/i.test(String(item)))) {
        suspiciousIndicators.push('spoofing');
    }
    if (findings.some((item) => /mismatch/i.test(String(item)))) {
        suspiciousIndicators.push('sender_mismatch');
    }
    const uniqueIndicators = [...new Set(suspiciousIndicators)];
    const dmarcRaw = asRecord(auth.dmarc);
    let dmarcResult = typeof dmarcRaw?.result === 'string'
        ? String(dmarcRaw.result).toLowerCase()
        : firstResult(auth.dmarc).toLowerCase();
    let dmarcPolicy = typeof dmarcRaw?.policy === 'string' ? dmarcRaw.policy : null;
    const nestedDmarc = asRecord(dmarcRaw?.dmarc);
    if (nestedDmarc?.valid === true)
        dmarcResult = 'pass';
    else if (nestedDmarc?.valid === false)
        dmarcResult = 'fail';
    const record = typeof nestedDmarc?.record === 'string' ? nestedDmarc.record : '';
    const policyMatch = record.match(/(?:^|[;\s])p\s*=\s*([^;\s]+)/i);
    if (!dmarcPolicy && policyMatch)
        dmarcPolicy = `p=${String(policyMatch[1]).toLowerCase()}`;
    if (dmarcResult === 'unknown') {
        for (const item of authResults) {
            const match = String(item).match(/\bdmarc\s*=\s*(pass|fail|none|neutral)\b/i);
            if (match) {
                dmarcResult = match[1].toLowerCase();
                break;
            }
        }
    }
    return {
        spf: { result: firstResult(auth.spf) },
        dkim: { result: firstResult(auth.dkim), domain: null, selector: null },
        dmarc: {
            result: String(dmarcResult).toLowerCase(),
            domain: typeof dmarcRaw?.domain === 'string' ? dmarcRaw.domain : null,
            policy: dmarcPolicy,
            alignment: typeof dmarcRaw?.alignment === 'string'
                ? dmarcRaw.alignment
                : typeof dmarcRaw?.explanation === 'string'
                    ? dmarcRaw.explanation
                    : null,
        },
        sender_identity: securitySender,
        header_analysis: {
            relay_anomaly: headerFinding || authResults.some((item) => /fail/i.test(item)) || received.length > 3,
            ip_hops: received.length,
            suspicious_headers: suspiciousHeaders,
        },
        suspicious_indicators: uniqueIndicators,
    };
}
function normaliseThreatIntelligence(value) {
    const raw = asRecord(value);
    if (!raw)
        return null;
    if (Array.isArray(raw.ips) && Array.isArray(raw.domains) && Array.isArray(raw.urls) && Array.isArray(raw.hashes)) {
        return raw;
    }
    const score = (entry, ...keys) => {
        for (const key of keys) {
            const value = entry[key];
            if (typeof value === 'number')
                return Math.max(0, Math.min(100, value));
            if (typeof value === 'string' && Number.isFinite(Number(value))) {
                return Math.max(0, Math.min(100, Number(value)));
            }
        }
        return 0;
    };
    const categories = (entry) => asArray(entry.categories).filter((item) => typeof item === 'string');
    const ips = [];
    const consumeIp = (entry, fallback) => {
        const obj = asRecord(entry);
        if (!obj)
            return;
        const ip = typeof obj.ip === 'string'
            ? obj.ip
            : typeof obj.ipAddress === 'string'
                ? obj.ipAddress
                : fallback;
        if (!ip)
            return;
        const existing = ips.find((item) => item.ip === ip);
        const next = {
            ip,
            reputation_score: score(obj, 'abuseConfidenceScore', 'abuseConfidence', 'confidence', 'reputation'),
            country: typeof obj.countryCode === 'string' ? obj.countryCode : typeof obj.country === 'string' ? obj.country : null,
            asn: typeof obj.asn === 'string' ? obj.asn : null,
            isp: typeof obj.isp === 'string' ? obj.isp : null,
            threat_history: Boolean(obj.threat_history) || score(obj, 'abuseConfidenceScore', 'abuseConfidence', 'confidence', 'reputation') >= 50,
            categories: categories(obj),
        };
        if (!existing)
            ips.push(next);
        else if (next.reputation_score > Number(existing.reputation_score ?? 0))
            Object.assign(existing, next);
    };
    const ipRaw = asRecord(raw.ip_analysis);
    for (const entry of asArray(ipRaw?.iocs_ip_abuseIPDB))
        consumeIp(entry);
    for (const entry of asArray(ipRaw?.iocs_ip_alienvaultOTX))
        consumeIp(entry);
    for (const entry of asArray(ipRaw?.originating_ip_abuseIPDB))
        consumeIp(entry, typeof ipRaw?.originating_ip === 'string' ? ipRaw.originating_ip : undefined);
    for (const entry of asArray(ipRaw?.originating_ip_alienvaultOTX))
        consumeIp(entry, typeof ipRaw?.originating_ip === 'string' ? ipRaw.originating_ip : undefined);
    const parseProviderList = (section) => {
        const obj = asRecord(section);
        return asArray(obj?.virusTotal_report).map(asRecord).filter((v) => Boolean(v));
    };
    const domains = parseProviderList(raw.domain_analysis).map((entry) => ({
        domain: String(entry.domain ?? entry.id ?? entry.indicator ?? ''),
        reputation_score: score(entry, 'reputation_score', 'reputation', 'malicious', 'suspicious'),
        country: typeof entry.country === 'string' ? entry.country : null,
        registrar: typeof entry.registrar === 'string' ? entry.registrar : null,
        creation_date: typeof entry.creation_date === 'string' ? entry.creation_date : null,
        threat_history: Boolean(entry.threat_history) || score(entry, 'reputation_score', 'reputation') >= 50,
        categories: categories(entry),
        community_reputation: typeof entry.reputation === 'number' ? entry.reputation : null,
        analysis_stats: asRecord(entry.last_analysis_stats),
        community_votes: asRecord(entry.total_votes),
    })).filter((item) => item.domain);
    const urls = parseProviderList(raw.url_analysis).map((entry) => ({
        url: String(entry.url ?? entry.id ?? entry.indicator ?? ''),
        reputation_score: score(entry, 'reputation_score', 'reputation', 'malicious', 'suspicious'),
        domain: typeof entry.domain === 'string' ? entry.domain : null,
        threat_history: Boolean(entry.threat_history) || score(entry, 'reputation_score', 'reputation') >= 50,
        categories: categories(entry),
    })).filter((item) => item.url);
    const hashes = parseProviderList(raw.attachment_analysis).map((entry) => ({
        hash: String(entry.hash ?? entry.sha256 ?? entry.id ?? ''),
        hash_type: 'sha256',
        reputation_score: score(entry, 'reputation_score', 'reputation', 'malicious', 'suspicious'),
        threat_history: Boolean(entry.threat_history) || score(entry, 'reputation_score', 'reputation') >= 50,
        categories: categories(entry),
    })).filter((item) => item.hash);
    return {
        ips: ips,
        domains: domains,
        urls: urls,
        hashes: hashes,
    };
}
export function normalizeReport(body, origin) {
    const raw = asRecord(body);
    if (!raw) {
        throw new AnalysisFailedError(undefined, 'Response body was not a JSON object.');
    }
    const root = asRecord(raw.result) ?? asRecord(raw.report) ?? asRecord(raw.logic_analysis) ?? raw;
    const verdict = asVerdict(root.verdict);
    const score = typeof root.risk_score === 'number' ? root.risk_score : undefined;
    if (verdict === undefined || score === undefined) {
        throw new AnalysisFailedError(undefined, `Response is missing risk_score or a recognised verdict. Received verdict=${String(root.verdict)}, risk_score=${String(root.risk_score)}.`);
    }
    return {
        case_id: typeof root.case_id === 'string' ? root.case_id : (typeof root.email_id === 'string' ? String(root.email_id) : 'CASE-UNKNOWN'),
        risk_score: score,
        verdict,
        processing_time_ms: typeof root.processing_time_ms === 'number'
            ? root.processing_time_ms
            : typeof root.processing_time_seconds === 'number'
                ? root.processing_time_seconds * 1000
                : 0,
        analysis_confidence: (asRecord(root.analysis_confidence) ?? null),
        verdict_info: asRecord(root.verdict_info),
        reasons: asArray(root.reasons),
        correlations: asArray(root.correlations).filter((c) => typeof c === 'string'),
        correlations_by_severity: asRecord(root.correlations_by_severity),
        score_breakdown: asRecord(root.score_breakdown),
        triggered_rules: asArray(root.triggered_rules),
        email: (asRecord(root.email) ?? null),
        security_analysis: normaliseSecurity(root.security_analysis),
        threat_intelligence: normaliseThreatIntelligence(root.threat_intelligence),
        ai_assessment: (asRecord(root.ai_assessment) ?? null),
        iocs: (asRecord(root.iocs) ?? null),
        attachment_analysis: (asRecord(root.attachment_analysis) ?? null),
        grounding: (asRecord(root.grounding) ?? null),
        model_info: (asRecord(root.model_info) ?? null),
        analyzed_at: typeof root.analyzed_at === 'string' ? root.analyzed_at : null,
        source_file: (asRecord(root.source_file) ?? null),
        is_temporary_backend: root._temporary === true,
        origin,
    };
}
async function sendTo(base, path, init, timeoutMs, externalSignal) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const onExternalAbort = () => controller.abort();
    if (externalSignal) {
        if (externalSignal.aborted)
            controller.abort();
        else
            externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }
    const target = `${base}${path.startsWith('/') ? path : `/${path}`}`;
    try {
        return await fetch(target, { ...init, signal: controller.signal });
    }
    catch (cause) {
        const isAbort = cause instanceof DOMException && cause.name === 'AbortError';
        if (isAbort) {
            if (externalSignal?.aborted)
                throw cause;
            throw new ApiError('The request timed out while waiting for TRINETRA.', `The request exceeded ${Math.round(timeoutMs / 1000)} seconds.`);
        }
        // Distinguish backend vs logic for better message
        const isLogic = base === config.logicBaseUrl;
        if (isLogic)
            throw new LogicUnavailableError(undefined, `${target} could not be reached.`);
        throw new BackendUnavailableError(undefined, `${target} could not be reached.`);
    }
    finally {
        clearTimeout(timer);
        if (externalSignal)
            externalSignal.removeEventListener('abort', onExternalAbort);
    }
}
async function readErrorDetail(response) {
    try {
        const text = await response.text();
        if (!text)
            return `HTTP ${response.status} ${response.statusText}`;
        try {
            const parsed = JSON.parse(text);
            const detail = parsed.detail ?? parsed.message ?? parsed.error;
            if (typeof detail === 'string')
                return detail;
            if (detail != null)
                return JSON.stringify(detail);
        }
        catch {
            // plain text response
        }
        return text.slice(0, 400);
    }
    catch {
        return `HTTP ${response.status} ${response.statusText}`;
    }
}
async function sleep(ms, signal) {
    if (signal?.aborted)
        throw new DOMException('Request cancelled', 'AbortError');
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }, ms);
        const onAbort = () => {
            clearTimeout(timer);
            reject(new DOMException('Request cancelled', 'AbortError'));
        };
        signal?.addEventListener('abort', onAbort, { once: true });
    });
}
async function parseResponseBody(response) {
    const text = await response.text().catch(() => '');
    if (!text)
        return null;
    try {
        return JSON.parse(text);
    }
    catch {
        const trimmed = text.trim();
        // Some backends return bare case ID as plain text
        if (trimmed && trimmed.length < 256 && !trimmed.includes('\n') && !trimmed.includes(' ')) {
            return trimmed;
        }
        return text;
    }
}
function extractCaseId(body) {
    if (body == null)
        return null;
    if (typeof body === 'string') {
        const t = body.trim();
        if (!t)
            return null;
        // If it looks like JSON, parse it instead of treating the whole JSON as an ID
        if ((t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))) {
            try {
                const parsed = JSON.parse(t);
                return extractCaseId(parsed);
            }
            catch {
                return null;
            }
        }
        if (t.length < 256 && !t.includes(' ') && !t.includes('\n'))
            return t;
        try {
            const parsed = JSON.parse(t);
            return extractCaseId(parsed);
        }
        catch {
            return null;
        }
    }
    const raw = asRecord(body);
    if (!raw)
        return null;
    // Direct candidates
    const direct = [
        raw.case_id,
        raw.email_id,
        raw.id,
        raw.caseId,
        raw.emailId,
        raw.caseID,
    ];
    for (const cand of direct) {
        if (typeof cand === 'string' && cand.trim())
            return cand.trim();
    }
    // Nested candidates (common wrappers: {data:{...}}, {result:{...}})
    const nestedKeys = ['data', 'result', 'report', 'payload', 'body', 'logic_analysis'];
    for (const key of nestedKeys) {
        const inner = asRecord(raw[key]);
        if (!inner)
            continue;
        const innerCand = extractCaseId(inner);
        if (innerCand)
            return innerCand;
    }
    // Case-insensitive scan as last resort
    for (const [k, v] of Object.entries(raw)) {
        const lk = k.toLowerCase();
        if ((lk === 'case_id' || lk === 'caseid' || lk === 'email_id' || lk === 'emailid' || lk === 'id') && typeof v === 'string' && v.trim()) {
            return v.trim();
        }
    }
    return null;
}
async function fetchCaseOnce(caseId, signal) {
    // Primary poll target is local logic receiver — not the cloud backend
    const response = await sendTo(config.logicBaseUrl, `${config.analysisPath}/${encodeURIComponent(caseId)}`, { method: 'GET' }, 15000, signal);
    let body = null;
    try {
        body = await parseResponseBody(response);
    }
    catch {
        body = null;
    }
    return { response, body };
}
async function waitForCase(caseId, signal, onProgress) {
    const deadline = Date.now() + config.timeoutMs;
    let attempts = 0;
    let transientFailures = 0;
    let consecutiveNotFound = 0;
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] Polling Logic Receiver`);
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] GET /analysis/${caseId}`);
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] GET ${config.logicBaseUrl}${config.analysisPath}/${caseId} every ${config.pollIntervalMs}ms (deadline ${Math.round(config.timeoutMs / 1000)}s)`);
    while (Date.now() < deadline) {
        attempts += 1;
        let response = null;
        let body = null;
        try {
            const fetched = await fetchCaseOnce(caseId, signal);
            response = fetched.response;
            body = fetched.body;
        }
        catch (err) {
            // Network-level failure from sendTo()
            if (err instanceof DOMException && err.name === 'AbortError')
                throw err;
            if (err instanceof LogicUnavailableError) {
                transientFailures += 1;
                // eslint-disable-next-line no-console
                console.warn(`[TRINETRA] polling attempt ${attempts}: logic receiver unavailable (${err.detail ?? err.message}), retrying... (${transientFailures})`);
                // Logic receiver being down is distinct from "processing" — surface after bounded retries
                if (transientFailures > 15) {
                    throw new LogicUnavailableError('Unable to connect to the Logic Receiver.', `GET ${config.logicBaseUrl}${config.analysisPath}/${caseId} failed ${transientFailures} times. Ensure logic_receiver.py is running on ${config.logicBaseUrl} and CORS allows ${typeof window !== 'undefined' ? window.location.origin : 'the frontend origin'}.`);
                }
                await sleep(transientFailures < 3 ? config.pollIntervalMs : 3000, signal);
                continue;
            }
            if (err instanceof BackendUnavailableError) {
                // Should not happen during logic poll; treat as transient
                transientFailures += 1;
                // eslint-disable-next-line no-console
                console.warn(`[TRINETRA] polling attempt ${attempts}: network unavailable (${err.detail ?? err.message}), retrying... (${transientFailures})`);
                if (transientFailures > 15)
                    throw err;
                await sleep(transientFailures < 3 ? config.pollIntervalMs : 3000, signal);
                continue;
            }
            if (err instanceof ApiError && err.message.includes('timed out')) {
                // eslint-disable-next-line no-console
                console.warn(`[TRINETRA] polling attempt ${attempts}: timed out, retrying...`);
                await sleep(2000, signal);
                continue;
            }
            throw err;
        }
        if (!response) {
            await sleep(config.pollIntervalMs, signal);
            continue;
        }
        // 404 — logic store may not yet have the case (Subhom hasn't forwarded yet)
        // Keep polling for a bounded period before surfacing as not_found; this avoids
        // flashing a backend error when processing simply hasn't started.
        if (response.status === 404) {
            consecutiveNotFound += 1;
            // eslint-disable-next-line no-console
            console.warn(`[TRINETRA] polling attempt ${attempts}: GET ${caseId} -> 404 (logic may still be waiting for Subhom), retry ${consecutiveNotFound}...`);
            const detail = typeof body === 'string' ? body.slice(0, 200) : (asRecord(body)?.detail ?? asRecord(body)?.message ?? '');
            if (detail)
                console.warn(`[TRINETRA] 404 detail: ${String(detail).slice(0, 400)}`);
            // Allow ~20s of 404s (about 13 polls at 1.5s) before continuing to next handling;
            // do NOT fail immediately — the upload was already accepted (202)
            await sleep(2000, signal);
            continue;
        }
        else {
            consecutiveNotFound = 0;
        }
        // 429 / 5xx are transient
        if (response.status === 429 || (response.status >= 500 && response.status < 600)) {
            transientFailures += 1;
            // eslint-disable-next-line no-console
            console.warn(`[TRINETRA] polling attempt ${attempts}: GET ${caseId} -> ${response.status} transient, retrying... (${transientFailures})`);
            if (transientFailures > 20) {
                throw new ApiError(`Could not load ${caseId}.`, `HTTP ${response.status} after ${attempts} polls: ${typeof body === 'string' ? body.slice(0, 400) : JSON.stringify(body).slice(0, 400)}`);
            }
            await sleep(2500, signal);
            continue;
        }
        if (!response.ok) {
            const detail = typeof body === 'string'
                ? body.slice(0, 400)
                : body != null
                    ? JSON.stringify(body).slice(0, 400)
                    : await readErrorDetail(response);
            throw new ApiError(`Could not load ${caseId}.`, detail);
        }
        // Successful response — reset transient counter
        transientFailures = 0;
        const bodyRecord = asRecord(body);
        const statusRaw = typeof bodyRecord?.status === 'string' ? bodyRecord.status : undefined;
        const status = statusRaw?.toLowerCase();
        const inner = asRecord(bodyRecord?.result) ?? asRecord(bodyRecord?.report) ?? asRecord(bodyRecord?.logic_analysis) ?? bodyRecord;
        const hasVerdict = asVerdict(inner?.verdict) !== undefined;
        const hasScore = typeof inner?.risk_score === 'number';
        // Spec #15: make flow obvious
        if (status) {
            // eslint-disable-next-line no-console
            console.info(`[TRINETRA] Analysis status: ${status}`);
        }
        // eslint-disable-next-line no-console
        console.debug(`[TRINETRA] polling attempt ${attempts}: status=${statusRaw ?? '(none)'} hasVerdict=${hasVerdict} hasScore=${hasScore} ok=${response.ok}`);
        if (!bodyRecord && !body) {
            await sleep(config.pollIntervalMs, signal);
            continue;
        }
        // Subhom has delivered its security-analysis/backend-evidence payload when the
        // Logic Receiver exposes an Ollama-waiting/security-analysis state. This is the
        // real downstream milestone; receiving the initial case_id is NOT this milestone.
        const statusSignalsSubhom = !!status && (status.includes('ollama') ||
            status.includes('security_analysis') ||
            status.includes('security-analysis') ||
            status.includes('backend_evidence') ||
            status.includes('backend-evidence') ||
            status.includes('security analysis received') ||
            status.includes('security_analysis_received') ||
            status.includes('waiting_for_ollama') ||
            status.includes('waiting-for-ollama') ||
            status.includes('waiting for ollama'));
        // The intermediate Subhom payload can be wrapped inside data/result/report/payload
        // (or another nested object). Search recursively so the 60% milestone is tied to
        // actual backend evidence, not merely the initial case_id response.
        const containsSubhomEvidence = (value, depth = 0) => {
            if (depth > 8 || value == null)
                return false;
            if (typeof value === 'string') {
                const text = value.toLowerCase().replace(/[-_]/g, ' ');
                return (text.includes('security analysis received') ||
                    (text.includes('backend stored') && text.includes('waiting for ollama')) ||
                    text.includes('waiting for ollama analysis') ||
                    text.includes('backend evidence') && (text.includes('security') ||
                        text.includes('waiting') ||
                        text.includes('received')));
            }
            if (typeof value !== 'object')
                return false;
            if (Array.isArray(value))
                return value.some((item) => containsSubhomEvidence(item, depth + 1));
            const record = value;
            const keys = Object.keys(record).map((key) => key.toLowerCase().replace(/[-\s]/g, '_'));
            if (keys.some((key) => key === 'security_analysis' ||
                key === 'backend_evidence' ||
                key === 'security_analysis_received'))
                return true;
            return Object.values(record).some((child) => containsSubhomEvidence(child, depth + 1));
        };
        const bodySignalsSubhom = containsSubhomEvidence(body);
        // The Logic Receiver explicitly exposes has_backend=true after Subhom
        // delivers its security/threat evidence. This is the authoritative
        // handoff milestone for the UI: move the loader to 60% immediately,
        // even when the status string itself remains generic (e.g. processing).
        const receiverHasBackendEvidence = asRecord(body)?.has_backend === true;
        if (statusSignalsSubhom || bodySignalsSubhom || receiverHasBackendEvidence) {
            onProgress?.({ type: 'security-analysis-received', caseId });
        }
        if (status === 'failed' || status === 'error') {
            throw new AnalysisFailedError('The TRINETRA analysis failed.', typeof bodyRecord?.error === 'string' ? bodyRecord.error : typeof bodyRecord?.detail === 'string' ? bodyRecord.detail : undefined);
        }
        if (status === 'completed' || status === 'done' || status === 'success') {
            try {
                const report = normalizeReport(body, 'live');
                // eslint-disable-next-line no-console
                console.info(`[TRINETRA] Analysis status: completed`);
                // eslint-disable-next-line no-console
                console.info(`[TRINETRA] Final result received`);
                onProgress?.({ type: 'analysis-complete', caseId });
                return report;
            }
            catch (e) {
                // If normalize fails even though status says completed, surface the underlying detail
                throw e;
            }
        }
        // No explicit status but body already contains a full report (some backends omit wrapper)
        if (hasVerdict && hasScore) {
            // eslint-disable-nextLine no-console
            console.info(`[TRINETRA] polling attempt ${attempts}: no status field but body contains verdict+score — treating as completed`);
            const report = normalizeReport(body, 'live');
            // eslint-disable-next-line no-console
            console.info(`[TRINETRA] Final result received`);
            onProgress?.({ type: 'analysis-complete', caseId });
            return report;
        }
        if (status === 'processing' || status === 'pending' || status === 'queued' || status === 'waiting' || status === undefined) {
            await sleep(config.pollIntervalMs, signal);
            continue;
        }
        // Unknown status (e.g., "accepted", "already_completed") — treat as still processing or completed
        if (status === 'already_completed') {
            try {
                return normalizeReport(body, 'live');
            }
            catch {
                await sleep(config.pollIntervalMs, signal);
                continue;
            }
        }
        await sleep(config.pollIntervalMs, signal);
        continue;
    }
    throw new AnalysisFailedError('Analysis is taking longer than expected.', 'Please try again or check the connection. Your email was received, but the downstream analysis pipeline did not return a final result within the configured timeout. Case ' + caseId + ' may still be processing. Check logic_receiver logs or retry.');
}
export async function analyzeEmail(file, options = {}) {
    const rejection = validateEmlFile(file);
    if (rejection)
        throw new InvalidFileError(rejection.message);
    // eslint-disable-next-line no-console
    options.onProgress?.({ type: 'upload-start' });
    console.info(`[TRINETRA] Upload started`);
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] POST /receive-email`);
    const form = new FormData();
    form.append('email', file, file.name);
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] POST ${config.backendBaseUrl}${config.analyzePath} -> uploading ${file.name} (${file.size} bytes) as multipart/form-data field "email"`);
    const response = await sendTo(config.backendBaseUrl, config.analyzePath, {
        method: 'POST',
        body: form,
    }, 60000, options.signal);
    // 202 is success — response.ok covers 202. Only treat real non-2xx as failure.
    if (!response.ok) {
        // Distinguish network vs backend error — do NOT call every non-200 a BackendUnavailableError
        throw new UploadFailedError(undefined, await readErrorDetail(response));
    }
    const rawBody = await parseResponseBody(response);
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] POST ${config.analyzePath} -> ${response.status} ${response.statusText}`, rawBody);
    // Also check headers for case id as fallback (some backends send it there)
    const headerCaseId = response.headers.get('x-case-id') ??
        response.headers.get('x-email-id') ??
        response.headers.get('case-id') ??
        response.headers.get('email-id');
    let caseId = extractCaseId(rawBody);
    if (!caseId && headerCaseId && headerCaseId.trim())
        caseId = headerCaseId.trim();
    if (!caseId) {
        const snippet = typeof rawBody === 'string' ? rawBody.slice(0, 500) : JSON.stringify(rawBody ?? {}).slice(0, 800);
        // eslint-disable-next-line no-console
        console.error('[TRINETRA] POST succeeded (' + response.status + ') but no case_id/email_id found in body or headers:', snippet);
        throw new AnalysisFailedError('Upload accepted but the backend response did not include a case ID.', `Backend at ${config.backendBaseUrl} returned ${response.status} with body: ${snippet || '(empty)'} — expected {case_id} or {email_id}. Check that VITE_ANALYZE_PATH and VITE_BACKEND_BASE_URL match the backend contract. The file was sent successfully; only result retrieval is blocked.`);
    }
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] Received case_id=${caseId}`);
    options.onProgress?.({ type: 'case-received', caseId });
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] Polling Logic Receiver`);
    // eslint-disable-next-line no-console
    console.info(`[TRINETRA] GET /analysis/${caseId}`);
    return waitForCase(caseId, options.signal, options.onProgress);
}
export async function fetchCase(caseId, options = {}) {
    return waitForCase(caseId, options.signal, options.onProgress);
}
export function toCaseSummary(report) {
    return {
        case_id: report.case_id,
        sender: report.email?.sender ?? null,
        subject: report.email?.subject ?? null,
        risk_score: report.risk_score,
        verdict: report.verdict,
        processing_time_ms: report.processing_time_ms,
        analyzed_at: report.analyzed_at ?? null,
        filename: report.source_file?.filename ?? null,
    };
}
export function toUserMessage(error) {
    if (error instanceof LogicUnavailableError) {
        return { message: error.message, detail: error.detail };
    }
    if (error instanceof BackendUnavailableError) {
        return { message: error.message, detail: error.detail };
    }
    if (error instanceof ApiError) {
        return { message: error.message, detail: error.detail };
    }
    if (error instanceof Error) {
        return {
            message: 'Analysis failed. The email could not be analyzed.',
            detail: error.message,
        };
    }
    return { message: 'Analysis failed. The email could not be analyzed.' };
}
