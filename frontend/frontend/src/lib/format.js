/* ==========================================================================
   Display formatting only. Nothing here derives a security conclusion.
   ========================================================================== */
/** 284000 -> "284 KB". Uses KB/MB as an analyst would read them. */
export function formatBytes(bytes) {
    if (bytes == null || Number.isNaN(bytes))
        return '—';
    if (bytes < 1024)
        return `${bytes} B`;
    const kb = bytes / 1024;
    if (kb < 1024)
        return `${kb < 10 ? kb.toFixed(1) : Math.round(kb)} KB`;
    const mb = kb / 1024;
    return `${mb < 10 ? mb.toFixed(1) : Math.round(mb)} MB`;
}
/** 0.91 -> "91%". Probabilities arrive as 0.0-1.0 floats. */
export function formatProbability(value) {
    if (value == null || Number.isNaN(value))
        return '—';
    return `${Math.round(value * 100)}%`;
}
/** ISO timestamp -> "29 Aug 2026, 14:32". Returns the raw string if unparseable. */
export function formatDateTime(iso) {
    if (!iso)
        return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime()))
        return iso;
    return new Intl.DateTimeFormat(undefined, {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
    }).format(d);
}
/** ISO timestamp -> "29 Aug 2026". */
export function formatDate(iso) {
    if (!iso)
        return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime()))
        return iso;
    return new Intl.DateTimeFormat(undefined, {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
    }).format(d);
}
/** Milliseconds straight from processing_time_ms. Never computed here. */
export function formatDuration(ms) {
    if (ms == null || Number.isNaN(ms))
        return '—';
    if (ms < 1000)
        return `${ms} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
}
/** "credential_harvesting" -> "Credential harvesting". */
export function humanizeToken(token) {
    if (!token)
        return '';
    const spaced = token.replace(/[_-]+/g, ' ').trim();
    return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}
/** Long values (hashes, message IDs) shortened for table cells. */
export function truncateMiddle(value, head = 14, tail = 8) {
    if (value.length <= head + tail + 1)
        return value;
    return `${value.slice(0, head)}…${value.slice(-tail)}`;
}
/** One-line clamp for table cells. */
export function truncateEnd(value, max = 60) {
    if (value.length <= max)
        return value;
    return `${value.slice(0, max - 1)}…`;
}
/** Grammatical plural without a library. */
export function pluralize(count, singular, plural) {
    return count === 1 ? singular : (plural ?? `${singular}s`);
}
