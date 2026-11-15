/* ==========================================================================
   Presentation mapping for backend risk vocabulary.
   --------------------------------------------------------------------------
   This file decides how a verdict or severity LOOKS. It never decides what a
   verdict IS — that always arrives from logic/verdict.py.

   Colour discipline: these are the only saturated colours in the product.
   ========================================================================== */
const NEUTRAL = {
    text: 'text-ink-2',
    bg: 'bg-ink-4/10',
    border: 'border-line-strong',
    solid: 'bg-ink-4',
    label: 'Not evaluated',
};
/* --------------------------------------------------------------------------
   Verdicts. CRITICAL and MALICIOUS are both red per the brief; they are told
   apart by weight rather than hue — MALICIOUS is the only tone that ever gets
   a solid fill behind white text.
   -------------------------------------------------------------------------- */
const VERDICT_TONES = {
    LOW: {
        text: 'text-low',
        bg: 'bg-low/10',
        border: 'border-low/35',
        solid: 'bg-low',
        label: 'Low',
    },
    MEDIUM: {
        text: 'text-medium',
        bg: 'bg-medium/10',
        border: 'border-medium/35',
        solid: 'bg-medium',
        label: 'Medium',
    },
    HIGH: {
        text: 'text-high',
        bg: 'bg-high/12',
        border: 'border-high/40',
        solid: 'bg-high',
        label: 'High',
    },
    CRITICAL: {
        text: 'text-critical',
        bg: 'bg-critical/12',
        border: 'border-critical/45',
        solid: 'bg-critical',
        label: 'Critical',
    },
    MALICIOUS: {
        text: 'text-malicious',
        bg: 'bg-malicious/15',
        border: 'border-malicious/55',
        solid: 'bg-malicious',
        label: 'Malicious',
    },
};
export function verdictTone(verdict) {
    if (!verdict)
        return NEUTRAL;
    return VERDICT_TONES[verdict.toUpperCase()] ?? NEUTRAL;
}
/** True for verdicts that should read as an active threat. */
export function isThreatVerdict(verdict) {
    const v = (verdict ?? '').toUpperCase();
    return v === 'HIGH' || v === 'CRITICAL' || v === 'MALICIOUS';
}
/* --------------------------------------------------------------------------
   Reason / correlation severities (lowercase in the Python model).
   -------------------------------------------------------------------------- */
const SEVERITY_TONES = {
    low: { ...VERDICT_TONES.LOW, label: 'Low' },
    medium: { ...VERDICT_TONES.MEDIUM, label: 'Medium' },
    high: { ...VERDICT_TONES.HIGH, label: 'High' },
    critical: { ...VERDICT_TONES.CRITICAL, label: 'Critical' },
};
export function severityTone(severity) {
    if (!severity)
        return NEUTRAL;
    return SEVERITY_TONES[severity.toLowerCase()] ?? NEUTRAL;
}
/** Order used when grouping findings: worst first. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
export function severityRank(severity) {
    const i = SEVERITY_ORDER.indexOf((severity ?? '').toLowerCase());
    return i === -1 ? SEVERITY_ORDER.length : i;
}
/* --------------------------------------------------------------------------
   Email authentication results.
   -------------------------------------------------------------------------- */
const AUTH_PASS = { ...VERDICT_TONES.LOW, label: 'Pass' };
const AUTH_FAIL = { ...VERDICT_TONES.CRITICAL, label: 'Fail' };
const AUTH_SOFT = { ...VERDICT_TONES.MEDIUM, label: 'Softfail' };
export function authTone(result) {
    switch (result) {
        case 'pass':
            return AUTH_PASS;
        case 'fail':
            return AUTH_FAIL;
        case 'softfail':
            return AUTH_SOFT;
        default:
            // neutral / none / unknown — absence of a result is not a failure.
            return { ...NEUTRAL, label: result || 'unknown' };
    }
}
/* --------------------------------------------------------------------------
   Threat-intelligence reputation.

   reputation_score is 0-100 where HIGHER IS WORSE, and logic/rules.py treats
   >= 70 as malicious (REPUTATION_THRESHOLD). The bands below are labels for
   that same backend number — the frontend does not re-score anything.
   -------------------------------------------------------------------------- */
/** Mirrors SecurityRules.REPUTATION_THRESHOLD in logic/rules.py. */
export const REPUTATION_THRESHOLD = 70;
/** Mirrors CorrelationEngine.REPUTATION_HIGH / REPUTATION_MEDIUM. */
export const REPUTATION_HIGH = 80;
export const REPUTATION_MEDIUM = 50;
export function reputationTone(score) {
    if (score >= REPUTATION_HIGH)
        return { ...VERDICT_TONES.MALICIOUS, label: 'Malicious' };
    if (score >= REPUTATION_THRESHOLD)
        return { ...VERDICT_TONES.CRITICAL, label: 'Malicious' };
    if (score >= REPUTATION_MEDIUM)
        return { ...VERDICT_TONES.MEDIUM, label: 'Suspicious' };
    return { ...VERDICT_TONES.LOW, label: 'Clean' };
}
/** A boolean flag from the AI assessment, toned only when it means trouble. */
export function flagTone(value) {
    return value ? { ...VERDICT_TONES.HIGH, label: 'Yes' } : { ...NEUTRAL, label: 'No' };
}
export { NEUTRAL as neutralTone };
