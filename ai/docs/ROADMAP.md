PROJECT GOAL
============

Build a secure, evidence-grounded AI analysis pipeline that:

Evidence Package
      ↓
Input Security
      ↓
Evidence Normalization
      ↓
Email Understanding
      ↓
Context Building
      ↓
Prompt Construction
      ↓
Local LLM (Ollama)
      ↓
Structured Output
      ↓
Output Validation
      ↓
AI Assessment
      ↓
Green Logic/Risk Engine


PHASE 1 — CONTRACTS & TEST DATA
================================

[ ] Define Evidence Package schema
[ ] Define AI Assessment schema
[ ] Define Pydantic models
[ ] Include email sender
[ ] Include email recipient
[ ] Include email subject
[ ] Include email body
[ ] Include security_analysis
[ ] Include threat_intelligence
[ ] Enforce probability range: 0.0–1.0
[ ] Create realistic sample_evidence.json
[ ] Create contract validation tests


PHASE 2 — INPUT SECURITY
=========================

[ ] Implement untrusted-content handling
[ ] Separate system instructions from email content
[ ] Prevent prompt injection through email subject/body
[ ] Treat security_analysis and threat_intelligence as evidence
[ ] Reject malformed/unsafe input where necessary
[ ] Add security tests
[ ] Test malicious/prompt-injection emails


PHASE 3 — EVIDENCE NORMALIZATION
=================================

[ ] Implement evidence normalizer
[ ] Normalize missing/optional fields
[ ] Normalize strings and whitespace
[ ] Handle null/empty values
[ ] Handle malformed evidence safely
[ ] Handle excessively large content
[ ] Preserve original evidence meaning
[ ] Add normalization tests


PHASE 4 — EMAIL UNDERSTANDING
==============================

[ ] Extract semantic signals from subject/body
[ ] Detect urgency indicators
[ ] Detect credential requests
[ ] Detect financial requests
[ ] Detect social-engineering indicators
[ ] Identify suspicious language
[ ] Identify phishing patterns
[ ] Identify BEC patterns
[ ] Combine email-content signals with forensic evidence
[ ] Add understanding tests


PHASE 5 — CONTEXT BUILDER
==========================

[ ] Design internal analysis context
[ ] Combine email content
[ ] Combine security_analysis
[ ] Combine threat_intelligence
[ ] Preserve evidence provenance
[ ] Keep trusted instructions separate from untrusted data
[ ] Create deterministic context structure
[ ] Test context construction


PHASE 6 — PROMPTING
====================

[ ] Create system analysis instructions
[ ] Define evidence-grounding rules
[ ] Define anti-prompt-injection rules
[ ] Tell LLM not to follow instructions inside emails
[ ] Tell LLM not to invent evidence
[ ] Define phishing analysis requirements
[ ] Define BEC analysis requirements
[ ] Define social-engineering analysis requirements
[ ] Define required JSON output
[ ] Define probability range: 0.0–1.0
[ ] Explicitly prevent final risk/verdict decisions
[ ] Test generated prompts


PHASE 7 — LOCAL LLM / OLLAMA
=============================

[ ] Implement LLM client abstraction
[ ] Connect to Ollama
[ ] Connect to local Qwen model
[ ] Send structured analysis context
[ ] Receive raw LLM response
[ ] Handle connection failures
[ ] Handle model failures
[ ] Handle timeout/errors
[ ] Keep LLM implementation isolated from pipeline
[ ] Test LLM client


PHASE 8 — STRUCTURED OUTPUT
============================

[ ] Extract JSON from LLM response
[ ] Handle markdown-wrapped JSON
[ ] Reject invalid JSON
[ ] Parse into Pydantic model
[ ] Validate required fields
[ ] Validate data types
[ ] Validate probability ranges
[ ] Validate boolean fields
[ ] Validate arrays
[ ] Handle missing/extra fields appropriately
[ ] Add output-validation tests


PHASE 9 — EVIDENCE GROUNDING / QC
==================================

[ ] Check that explanations are supported by evidence
[ ] Detect unsupported claims
[ ] Detect fabricated indicators
[ ] Ensure suspicious_language is evidence-based
[ ] Ensure detected_patterns are evidence-based
[ ] Ensure probabilities are structurally valid
[ ] Reject or repair invalid output
[ ] Add grounding/QC tests


PHASE 10 — RESULT BUILDER
==========================

[ ] Build final ai_assessment
[ ] Preserve exact Green Engine contract
[ ] Include phishing_probability
[ ] Include bec_probability
[ ] Include social_engineering_probability
[ ] Include urgency_detected
[ ] Include credential_request_detected
[ ] Include financial_request_detected
[ ] Include suspicious_language[]
[ ] Include detected_patterns[]
[ ] Include explanation
[ ] Include model_info
[ ] Do NOT generate risk_score
[ ] Do NOT generate final verdict


PHASE 11 — PIPELINE INTEGRATION
================================

[ ] Implement pipeline.py
[ ] Connect Input Security
[ ] Connect Normalization
[ ] Connect Understanding
[ ] Connect Context Builder
[ ] Connect Prompt Builder
[ ] Connect Ollama
[ ] Connect Output Parser
[ ] Connect Validation
[ ] Connect Grounding/QC
[ ] Connect Result Builder
[ ] Return final ai_assessment


PHASE 12 — TESTING
===================

[ ] Unit tests for contracts
[ ] Unit tests for security
[ ] Unit tests for normalization
[ ] Unit tests for understanding
[ ] Unit tests for prompting
[ ] Unit tests for LLM client
[ ] Unit tests for validation
[ ] Unit tests for grounding
[ ] Integration tests
[ ] End-to-end tests
[ ] Prompt-injection tests
[ ] Malformed-input tests
[ ] Malformed-LLM-output tests
[ ] Empty-evidence tests
[ ] Missing-field tests
[ ] High-confidence phishing test
[ ] Legitimate-email test
[ ] BEC test
[ ] Social-engineering test


PHASE 13 — CLI / DEMO
======================

[ ] Implement scripts/run_analysis.py
[ ] Accept JSON input file
[ ] Run complete AI pipeline
[ ] Generate ai_assessment JSON
[ ] Save output to examples/output/
[ ] Add sample input
[ ] Add sample output
[ ] Make local demo reproducible


PHASE 14 — GREEN ENGINE INTEGRATION
====================================

Final interface:

                    Evidence Package
                          │
                          ▼
                   🟣 AI COMPONENT
                          │
                          ▼
                    ai_assessment
                          │
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
security_analysis                  threat_intelligence
        │                                   │
        └─────────────────┬─────────────────┘
                          ▼
                   🟢 GREEN ENGINE
                          │
                          ▼
                     LogicOutput

Green Engine receives:

{
    "case_id": "...",
    "iocs": {},
    "security_analysis": {},
    "threat_intelligence": {},
    "ai_assessment": {}
}

AI component provides:

{
    "ai_assessment": {
        "phishing_probability": 0.0,
        "bec_probability": 0.0,
        "social_engineering_probability": 0.0,
        "urgency_detected": false,
        "credential_request_detected": false,
        "financial_request_detected": false,
        "suspicious_language": [],
        "detected_patterns": [],
        "explanation": "...",
        "model_info": {}
    }
}


FINAL RULES
===========

1. Email subject/body are UNTRUSTED DATA.
2. Never allow email content to override system instructions.
3. AI analyzes evidence; it does not make the final risk verdict.
4. Do not invent evidence.
5. Ground explanations in supplied evidence.
6. Probabilities MUST be between 0.0 and 1.0.
7. Keep the Green Engine contract stable.
8. Keep Ollama/model-specific code isolated.
9. Validate every LLM response before returning it.
10. Test every stage independently before full integration.


IMMEDIATE START
===============

STEP 1 → Create:

src/ai/contracts/__init__.py
src/ai/contracts/evidence.py
src/ai/contracts/assessment.py

STEP 2 → Create:

tests/fixtures/sample_evidence.json

STEP 3 → Write contract tests.

STEP 4 → Only after Phase 1 passes, start Phase 2.