#!/usr/bin/env python
"""
TEMPORARY MANUAL INTEGRATION TEST HARNESS — DO NOT MODIFY THE AI ARCHITECTURE

This is a DISPOSABLE manual integration test harness for testing the completed
V2 pipeline with a real JSON file.

It does NOT:
- Modify the AI architecture
- Create a second pipeline
- Add backend integration
- Create a CLI or API
- Add new models

It ONLY:
1. Reads a JSON file from manual_test/input/
2. Calls the EXISTING pipeline entry point (src.ai.analyze)
3. Writes the result to manual_test/output/
4. Is fully disposable - can be deleted without affecting the AI subsystem

DELETE THIS ENTIRE DIRECTORY WHEN DONE TESTING.
"""

import json
import sys
from pathlib import Path

# Add project root to path so we can import src.ai
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.ai.contracts import EvidencePackage
from src.ai import analyze


def main():
    # Paths
    input_dir = Path(__file__).parent / "input"
    output_dir = Path(__file__).parent / "output"
    input_file = input_dir / "sample_evidence.json"
    output_file = output_dir / "analysis_result.json"

    # Check input exists
    if not input_file.exists():
        print(f"ERROR: Input file not found: {input_file}")
        print("Create a sample_evidence.json in manual_test/input/")
        sys.exit(1)

    # Load and validate input
    print(f"Loading evidence from: {input_file}")
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    try:
        evidence_package = EvidencePackage.model_validate(data)
        print(f"Loaded EvidencePackage: case_id={evidence_package.case_id}")
        print(f"  Forensic evidence keys: {list(evidence_package.forensic_evidence.keys())}")
    except Exception as e:
        print(f"ERROR: Invalid EvidencePackage: {e}")
        sys.exit(1)

    # Run the EXISTING pipeline (this calls the existing pipeline.py analyze() function)
    print("\nRunning AI analysis pipeline...")
    try:
        result = analyze(evidence_package)
    except Exception as e:
        print(f"ERROR: Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Prepare output
    output_data = {
        "case_id": result.case_id,
        "ai_assessment": {
            "phishing_probability": result.ai_assessment.phishing_probability,
            "bec_probability": result.ai_assessment.bec_probability,
            "social_engineering_probability": result.ai_assessment.social_engineering_probability,
            "urgency_detected": result.ai_assessment.urgency_detected,
            "credential_request_detected": result.ai_assessment.credential_request_detected,
            "financial_request_detected": result.ai_assessment.financial_request_detected,
            "suspicious_language": result.ai_assessment.suspicious_language,
            "detected_patterns": result.ai_assessment.detected_patterns,
            "explanation": result.ai_assessment.explanation,
            "model_info": {
                "model_name": result.ai_assessment.model_info.model_name if result.ai_assessment.model_info else "",
                "model_version": result.ai_assessment.model_info.model_version if result.ai_assessment.model_info else "",
                "provider": result.ai_assessment.model_info.provider if result.ai_assessment.model_info else "",
                "parameters": result.ai_assessment.model_info.parameters if result.ai_assessment.model_info else {},
            },
            "attachment_risk_detected": result.ai_assessment.attachment_risk_detected,
            "malicious_attachment_detected": result.ai_assessment.malicious_attachment_detected,
            "attachment_findings": [
                {
                    "finding_type": f.finding_type,
                    "evidence_path": f.evidence_path,
                    "explanation": f.explanation,
                    "evidence_strength": f.evidence_strength,
                }
                for f in result.ai_assessment.attachment_findings
            ],
        },
        "grounding": {
            "grounded": result.grounding.grounded,
            "unsupported_claims": result.grounding.unsupported_claims,
            "evidence_references": result.grounding.evidence_references,
        },
        "processing_time_seconds": result.processing_time_seconds,
        "model_info": result.model_info,
    }

    # Write output
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"\nAnalysis complete!")
    print(f"Output written to: {output_file}")
    print(f"Processing time: {result.processing_time_seconds:.2f}s")
    print(f"Phishing probability: {result.ai_assessment.phishing_probability}")
    print(f"BEC probability: {result.ai_assessment.bec_probability}")
    print(f"Grounded: {result.grounding.grounded}")
    print(f"Attachment findings: {len(result.ai_assessment.attachment_findings)}")
    if result.grounding.unsupported_claims:
        print(f"Unsupported claims: {result.grounding.unsupported_claims}")


if __name__ == "__main__":
    main()