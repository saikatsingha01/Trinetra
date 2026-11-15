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
export const VERDICTS = [
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL',
    'MALICIOUS',
];
