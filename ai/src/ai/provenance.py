from __future__ import annotations

import copy
from typing import Any

from src.ai.contracts import AIAssessment


def extract_allowed_provenance_paths(context: Any, understanding: Any) -> list[str]:
    """
    Derive the exact valid evidence_path values for this specific case.

    Source of truth is the canonical forensic provenance already emitted by the
    understanding layer as ``Signal.source``. Those sources are:
    - trusted (derived from ``normalized_forensic_evidence`` via deterministic walk)
    - already in the exact ``forensic_evidence.*`` dotted/indexed notation used by
      ``ForensicFinding.evidence_path`` and by ``grounding.resolve_forensic_path``
    - already filtered to resolvable leaf fields (the walk only yields real objects)

    We collect from both ``context.forensic_indicators`` (SignalContext) and
    ``understanding.forensic_indicators`` (Signal) to be robust against either
    representation, deduplicate, and sort for determinism.

    No path is invented. No index is guessed. No collapsed label is emitted.
    The result is scoped to this single request/case; callers must not reuse it
    across cases.
    """
    raw: list[str] = []

    # From AnalysisContext.forensic_indicators (SignalContext)
    try:
        fis = getattr(context, "forensic_indicators", None)
        if isinstance(fis, list):
            for sig in fis:
                src = getattr(sig, "source", None)
                if isinstance(src, str) and src.strip():
                    raw.append(src.strip())
    except Exception:
        pass

    # From UnderstandingResult.forensic_indicators (Signal)
    try:
        fis2 = getattr(understanding, "forensic_indicators", None)
        if isinstance(fis2, list):
            for sig in fis2:
                src = getattr(sig, "source", None)
                if isinstance(src, str) and src.strip():
                    raw.append(src.strip())
    except Exception:
        pass

    # Deduplicate and filter collapsed labels (defense in depth - understanding
    # should never produce them, but we guard anyway)
    from src.ai.contracts.assessment import _COLLAPSED_PROVENANCE_LABELS

    seen: set[str] = set()
    filtered: list[str] = []
    for p in raw:
        if not p:
            continue
        # Generic labels are forbidden as standalone evidence_path values.
        # Understanding emits only full dotted paths, so this is just safety.
        if p.strip().lower() in _COLLAPSED_PROVENANCE_LABELS:
            continue
        # Must be rooted at forensic_evidence or threat_intelligence or other
        # evidence tree. We accept any path that contains a dot and is not collapsed.
        # The strictest check (forensic_evidence. prefix) would reject
        # threat_intelligence paths that prompt currently documents as example,
        # so we allow any dotted path that is not a bare label.
        if "." not in p:
            continue
        if p not in seen:
            seen.add(p)
            filtered.append(p)

    # Deterministic order: sort lexicographically. This makes the schema enum
    # stable across runs and the prompt section reproducible.
    filtered.sort()
    return filtered


def build_dynamic_assessment_schema(allowed_paths: list[str] | tuple[str, ...] | None) -> dict[str, Any]:
    """
    Build a request-specific JSON schema for Ollama structured output.

    Takes the global ``AIAssessment.model_json_schema()`` and, when
    ``allowed_paths`` is non-empty, constrains
    ``$defs.ForensicFinding.properties.evidence_path`` to an enum of exactly
    those paths.

    Returns a deep-copied dict so the global schema is never mutated.
    If ``allowed_paths`` is empty/None, the original schema is returned
    (deep-copied) without enum injection - the prompt will instead instruct
    the model to omit attachment_findings.
    """
    base = AIAssessment.model_json_schema()
    # Deep copy to avoid mutating cached schema
    schema = copy.deepcopy(base)

    if not allowed_paths:
        return schema

    # Normalize to sorted unique strings
    uniq = sorted({str(p).strip() for p in allowed_paths if isinstance(p, str) and str(p).strip()})
    if not uniq:
        return schema

    # Inject enum into ForensicFinding.evidence_path
    try:
        defs = schema.get("$defs", {})
        ff = defs.get("ForensicFinding")
        if isinstance(ff, dict):
            props = ff.get("properties", {})
            ev_path = props.get("evidence_path")
            if isinstance(ev_path, dict):
                # Preserve original description/title but add enum constraint
                ev_path["enum"] = uniq
                # Also update description to reinforce selection
                orig_desc = ev_path.get("description", "")
                # Keep concise: append allowed list hint
                # Do not duplicate if already contains enum hint
                if "Must be one of" not in orig_desc:
                    ev_path["description"] = (
                        orig_desc
                        + " Must be exactly one of the allowed provenance paths supplied for this case."
                    )
    except Exception:
        # If schema shape changes, return base without crashing - strict
        # validation remains the safety net.
        pass

    return schema


def format_allowed_paths_section(allowed_paths: list[str] | tuple[str, ...] | None) -> str:
    """
    Render the allowed provenance paths section for the user prompt.

    When paths exist, emits a bullet list of exact strings the model must
    copy verbatim. When none exist, emits an explicit instruction to omit
    attachment_findings.
    """
    if not allowed_paths:
        return (
            "(none - no valid attachment provenance paths exist for this case)\n"
            "INSTRUCTION: You MUST NOT emit any attachment_findings for this case. "
            "Use \"attachment_findings\": [] and set attachment_risk_detected/malicious_attachment_detected accordingly. "
            "Do NOT invent a path such as \"attachments\", \"attachment_analysis\", \"backend\", or \"forensic_evidence\"."
        )

    # Limit to reasonable display count? Input guard caps evidence size, but we
    # still bound to first 100 to keep prompt size sane. The schema enum carries
    # the full set, so truncation here does not weaken enforcement - it is just
    # prompt brevity.
    max_display = 100
    display = list(allowed_paths)[:max_display]
    lines = []
    for p in display:
        lines.append(f"  - {p}")
    if len(allowed_paths) > max_display:
        lines.append(f"  - ... and {len(allowed_paths) - max_display} more (see schema enum for full list)")
    return "\n".join(lines)


def is_provenance_validation_error(exc: Exception) -> bool:
    """
    Return True iff this LLMSchemaValidationError is due to evidence_path
    provenance (collapsed generic label).

    Only provenance errors are eligible for the single targeted retry.
    Other schema errors (missing phishing_probability etc.) should fail fast
    via the existing PipelineValidationError path without retry.
    """
    msg = str(exc).lower()
    # The validator emits "generic label, not a provenance path" for collapsed labels
    if "evidence_path" in msg or "provenance" in msg or "generic label" in msg:
        return True
    # Also check raw_response if available
    raw = getattr(exc, "raw_response", None)
    if isinstance(raw, str) and "evidence_path" in raw.lower():
        return True
    return False
