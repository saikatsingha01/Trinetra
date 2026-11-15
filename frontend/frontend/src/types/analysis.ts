/* ==========================================================================
   TRINETRA analysis types
   --------------------------------------------------------------------------
   These types MIRROR the existing Python contract. They are a transcription,
   not a design. Nothing here is invented by the frontend.

   Sources of truth (do not edit those files — read them):
     logic/models.py  -> SecurityAnalysis, ThreatIntelligence, AIAssessment,
                         EmailMetadata, IOCData, CorrelationReason, LogicOutput
     logic/engine.py  -> LogicEngine.get_detailed_report() response shape
     logic/verdict.py -> the five verdict values and their thresholds
     logic/rules.py   -> the 17 rule ids
     logic/scoring.py -> ScoreBreakdown fields

   Every section is optional on the wire. The engine's get_detailed_report()
   does not return the email / security / intel / AI inputs — the API layer
   echoes those back so the report can show them. A different backend build
   may omit them, so every renderer must tolerate their absence.
   ========================================================================== */

/* -------------------------------------------------------------------------
   Verdict + severity vocabulary (logic/verdict.py, logic/models.py)
   ------------------------------------------------------------------------- */

/** The five verdicts the backend can return. Do not add to this union. */
export type Verdict = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'MALICIOUS';

export const VERDICTS: readonly Verdict[] = [
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
  'MALICIOUS',
] as const;

/** CorrelationReason.severity — lowercase in the Python model. */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/* -------------------------------------------------------------------------
   Security analysis (logic/models.py :: SecurityAnalysis)
   ------------------------------------------------------------------------- */

export type SPFVerdict = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown';
export type DKIMVerdict = 'pass' | 'fail' | 'none' | 'unknown';
export type DMARCVerdict = 'pass' | 'fail' | 'none' | 'unknown';

export interface SPFResult {
  result: SPFVerdict;
  domain?: string | null;
  record?: string | null;
}

export interface DKIMResult {
  result: DKIMVerdict;
  domain?: string | null;
  selector?: string | null;
}

export interface DMARCResult {
  result: DMARCVerdict;
  domain?: string | null;
  policy?: string | null;
  alignment?: string | null;
}

export interface SenderIdentity {
  /**
   * Serialised as "from" — SenderIdentity.from_address carries
   * validation_alias="from" in logic/models.py.
   */
  from: string;
  return_path?: string | null;
  reply_to?: string | null;
  domain_consistent: boolean;
}

export interface HeaderAnalysis {
  relay_anomaly: boolean;
  ip_hops: number;
  suspicious_headers: string[];
}

export interface DNSDomainReport {
  domain: string;
  records: Record<string, string[]>;
}

export interface DNSReverseDNSReport {
  ip: string;
  hosts: string[];
}

export interface DNSAnalysis {
  dns_report: DNSDomainReport[];
  reverse_dns_report: DNSReverseDNSReport[];
}

export interface SecurityAnalysis {
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  sender_identity?: SenderIdentity | null;
  header_analysis: HeaderAnalysis;
  suspicious_indicators: string[];
  /** Additive response field carrying Workflow 2 DNS evidence. */
  dns?: DNSAnalysis | null;
}

/* -------------------------------------------------------------------------
   Threat intelligence (logic/models.py :: ThreatIntelligence)
   reputation_score is 0-100 where HIGHER IS WORSE.
   logic/rules.py flags anything >= 70 (REPUTATION_THRESHOLD).
   ------------------------------------------------------------------------- */

export type HashType = 'md5' | 'sha1' | 'sha256' | 'sha512';

export interface IPThreatIntel {
  ip: string;
  reputation_score: number;
  country?: string | null;
  asn?: string | null;
  isp?: string | null;
  threat_history: boolean;
  categories: string[];
}

export interface DomainThreatIntel {
  domain: string;
  reputation_score: number;
  country?: string | null;
  registrar?: string | null;
  creation_date?: string | null;
  threat_history: boolean;
  categories: string[];
  community_reputation?: number | null;
  analysis_stats?: Record<string, number> | null;
  community_votes?: Record<string, number> | null;
}

export interface URLThreatIntel {
  url: string;
  reputation_score: number;
  domain?: string | null;
  threat_history: boolean;
  categories: string[];
}

export interface HashThreatIntel {
  hash: string;
  hash_type: HashType;
  reputation_score: number;
  threat_history: boolean;
  categories: string[];
}

export interface ThreatIntelligence {
  ips: IPThreatIntel[];
  domains: DomainThreatIntel[];
  urls: URLThreatIntel[];
  hashes: HashThreatIntel[];
}

export interface AttachmentAnalysis {
  attachment_risk_detected: boolean;
  malicious_attachment_detected: boolean;
  attachment_findings: string[];
}

export interface GroundingInfo {
  grounded: boolean;
  unsupported_claims: string[];
  evidence_references: string[];
}

/* -------------------------------------------------------------------------
   AI assessment (logic/models.py :: AIAssessment)
   Probabilities are 0.0-1.0 floats, NOT percentages.
   ------------------------------------------------------------------------- */

export interface AIAssessment {
  phishing_probability: number;
  bec_probability: number;
  social_engineering_probability: number;
  urgency_detected: boolean;
  credential_request_detected: boolean;
  financial_request_detected: boolean;
  suspicious_language: string[];
  detected_patterns: string[];
  explanation: string;
  model_info?: Record<string, unknown> | null;
}

/* -------------------------------------------------------------------------
   Email + IOCs (logic/models.py :: EmailMetadata, IOCData)
   ------------------------------------------------------------------------- */

export interface EmailMetadata {
  sender: string;
  recipient: string;
  subject: string;
  date?: string | null;
  message_id?: string | null;
}

export interface IOCData {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
}

/* -------------------------------------------------------------------------
   Engine output (logic/engine.py :: get_detailed_report())
   ------------------------------------------------------------------------- */

export interface DetectionReason {
  description: string;
  /** e.g. ["security_analysis"], ["threat_intelligence", "ai_assessment"] */
  evidence_sources: string[];
  severity: Severity;
}

/** logic/verdict.py :: VerdictEngine.get_verdict_info() */
export interface VerdictInfo {
  score: number;
  verdict: Verdict;
  /** Band label -> inclusive range string, e.g. { HIGH: "41-60" }. */
  thresholds: Partial<Record<Verdict, string>>;
}

/** One entry of score_breakdown.category_scores. */
export interface CategoryScore {
  score: number;
  triggered: number;
  total: number;
  rules: string[];
}

/**
 * logic/engine.py flattens ScoreBreakdown by hand. Note two easy traps:
 *   - the key is `max_possible`, not `max_possible_score`
 *   - `triggered_rules` here is a COUNT; the top-level `triggered_rules` is an array
 */
export interface ScoreBreakdown {
  raw_score: number;
  max_possible: number;
  normalized_score: number;
  /** "capped" | "linear" | "sqrt" — chosen server-side. */
  method: string;
  triggered_rules: number;
  total_rules: number;
  category_scores: Record<string, CategoryScore>;
}

export interface TriggeredRule {
  /** One of the 17 ids in logic/rules.py RULE_WEIGHTS. */
  rule_id: string;
  description: string;
  weight: number;
  evidence: string;
}

export type CorrelationsBySeverity = Partial<Record<Severity, string[]>>;

/* -------------------------------------------------------------------------
   The full report the frontend renders.
   ------------------------------------------------------------------------- */

/**
 * Provenance of a report, so the UI can be honest about what produced it.
 * Nothing is inferred from the data itself.
 */
export type ReportOrigin = 'live';

/** Describes the uploaded file, echoed by the API layer. */
export interface SourceFile {
  filename: string;
  size_bytes?: number | null;
}

export interface AnalysisConfidence {
  score: number;
  label: 'Very high' | 'High' | 'Moderate' | 'Low';
  rationale: string[];
  factors: {
    evidence_coverage: number;
    signal_agreement: number;
    provider_coverage: number;
    authentication_consistency: number;
    grounding_quality: number;
    verdict_stability: number;
  ai_availability?: number;
  };
}

export interface AnalysisReport {
  /* --- always present -------------------------------------------------- */
  case_id: string;
  risk_score: number;
  verdict: Verdict;
  processing_time_ms: number;
  analysis_confidence?: AnalysisConfidence | null;
  analysis_mode?: 'full' | 'subhom_only';
  confidence_explanation?: string | null;
  provided_email?: string | null;

  /* --- from get_detailed_report(), may be absent on a leaner backend --- */
  verdict_info?: VerdictInfo;
  reasons: DetectionReason[];
  correlations: string[];
  correlations_by_severity?: CorrelationsBySeverity;
  score_breakdown?: ScoreBreakdown;
  triggered_rules: TriggeredRule[];

  /* --- engine inputs, echoed by the API so the report can show them ---- */
  email?: EmailMetadata | null;
  security_analysis?: SecurityAnalysis | null;
  threat_intelligence?: ThreatIntelligence | null;
  ai_assessment?: AIAssessment | null;
  iocs?: IOCData | null;
  attachment_analysis?: AttachmentAnalysis | null;
  grounding?: GroundingInfo | null;
  model_info?: Record<string, unknown> | null;

  /* --- envelope -------------------------------------------------------- */
  analyzed_at?: string | null;
  source_file?: SourceFile | null;
  /**
   * True when the responding backend declared itself a temporary stand-in
   * (the `_temporary` flag). Surfaced in the UI rather than hidden, so a
   * demo is never mistaken for a production result.
   */
  is_temporary_backend?: boolean;
  /** Set by the frontend: did this come off the wire, or from a fixture? */
  origin: ReportOrigin;
}

/** Row shape for the Cases table. */
export interface CaseSummary {
  case_id: string;
  sender?: string | null;
  subject?: string | null;
  risk_score: number;
  verdict: Verdict;
  processing_time_ms: number;
  analyzed_at?: string | null;
  filename?: string | null;
}
