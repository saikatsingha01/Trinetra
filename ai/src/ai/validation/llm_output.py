# from __future__ import annotations

# import json
# import re
# from typing import Any

# from src.ai.contracts import AIAssessment


# class LLMOutputValidationError(Exception):
#     def __init__(self, message: str, raw_response: str | None = None):
#         super().__init__(message)
#         self.raw_response = raw_response


# class LLMExtractionError(LLMOutputValidationError):
#     pass


# class LLMJSONParseError(LLMOutputValidationError):
#     pass


# class LLMSchemaValidationError(LLMOutputValidationError):
#     pass


# def _extract_json_from_text(text: str) -> str:
#     """
#     Extract a JSON object from text.

#     Supports:
#     1. Pure JSON object
#     2. JSON surrounded by text
#     3. Markdown fenced JSON (```json ... ```)

#     Returns the extracted JSON string.
#     Raises LLMExtractionError if extraction is ambiguous or no JSON found.
#     """
#     if not text or not text.strip():
#         raise LLMExtractionError("Response is empty or whitespace only", raw_response=text)

#     stripped = text.strip()

#     # Case 1: Pure JSON object - but must be ONLY the JSON object (no extra data)
#     if stripped.startswith("{") and stripped.endswith("}"):
#         # Verify it's valid JSON and no extra data
#         try:
#             json.loads(stripped)
#             return stripped
#         except json.JSONDecodeError:
#             pass  # Fall through to other extraction methods

#     # Case 2: Markdown fenced JSON
#     fence_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
#     matches = re.findall(fence_pattern, stripped, re.DOTALL)
#     if len(matches) == 1:
#         return matches[0].strip()
#     elif len(matches) > 1:
#         raise LLMExtractionError(
#             f"Multiple JSON objects found in markdown fences ({len(matches)})",
#             raw_response=text,
#         )

#     # Case 3: JSON object somewhere in text
#     # Find all balanced JSON-like objects
#     json_objects = _find_balanced_json_objects(stripped)
#     if len(json_objects) == 1:
#         return json_objects[0]
#     elif len(json_objects) > 1:
#         # If multiple, check if one is clearly the assessment (has required fields)
#         assessment_candidates = [
#             obj for obj in json_objects
#             if "phishing_probability" in obj or "bec_probability" in obj
#         ]
#         if len(assessment_candidates) == 1:
#             return assessment_candidates[0]
#         raise LLMExtractionError(
#             f"Multiple JSON objects found ({len(json_objects)}), cannot determine assessment",
#             raw_response=text,
#         )

#     raise LLMExtractionError("No JSON object found in response", raw_response=text)


# def _find_balanced_json_objects(text: str) -> list[str]:
#     """Find all balanced JSON objects in text."""
#     objects = []
#     stack = []
#     start = None

#     for i, char in enumerate(text):
#         if char == "{":
#             if not stack:
#                 start = i
#             stack.append("{")
#         elif char == "}":
#             if stack:
#                 stack.pop()
#                 if not stack and start is not None:
#                     obj = text[start:i + 1]
#                     # Quick validation - must look like our assessment
#                     try:
#                         json.loads(obj)
#                         objects.append(obj)
#                     except json.JSONDecodeError:
#                         pass
#                     start = None

#     return objects


# def validate_llm_output(raw_response: str) -> AIAssessment:
#     """
#     Validate raw LLM response and return AIAssessment.

#     Pipeline:
#     1. Extract JSON from raw response
#     2. Parse JSON
#     3. Validate against AIAssessment schema (strict mode)

#     Raises:
#         LLMExtractionError: JSON cannot be extracted unambiguously
#         LLMJSONParseError: JSON is malformed
#         LLMSchemaValidationError: JSON doesn't match AIAssessment schema
#     """
#     if not isinstance(raw_response, str):
#         raise LLMExtractionError(
#             f"Expected string response, got {type(raw_response).__name__}",
#             raw_response=str(raw_response),
#         )

#     # Extract JSON
#     try:
#         json_str = _extract_json_from_text(raw_response)
#     except LLMExtractionError:
#         raise
#     except Exception as e:
#         raise LLMExtractionError(
#             f"Unexpected error during JSON extraction: {e}",
#             raw_response=raw_response,
#         ) from e

#     # Parse JSON
#     try:
#         data = json.loads(json_str)
#     except json.JSONDecodeError as e:
#         raise LLMJSONParseError(
#             f"Failed to parse extracted JSON: {e}",
#             raw_response=raw_response,
#         ) from e

#     # Normalize single top-level wrapper {"assessment": {...}} before strict validation
#     # Minimal unwrapping: only when the parsed object is exactly {"assessment": dict}
#     if isinstance(data, dict) and set(data.keys()) == {"assessment"} and isinstance(data["assessment"], dict):
#         data = data["assessment"]

#     # Validate against AIAssessment schema with strict mode
#     # strict=True prevents coercion (e.g., "yes" -> True, 1 -> True)
#     try:
#         assessment = AIAssessment.model_validate(data, strict=True)
#     except Exception as e:
#         raise LLMSchemaValidationError(
#             f"LLM output failed schema validation: {e}",
#             raw_response=raw_response,
#         ) from e

#     return assessment

from __future__ import annotations

import json
import re
from typing import Any

from src.ai.contracts import AIAssessment


class LLMOutputValidationError(Exception):
    def __init__(self, message: str, raw_response: str | None = None):
        super().__init__(message)
        self.raw_response = raw_response


class LLMExtractionError(LLMOutputValidationError):
    pass


class LLMJSONParseError(LLMOutputValidationError):
    pass


class LLMSchemaValidationError(LLMOutputValidationError):
    pass


def _extract_json_from_text(text: str) -> str:
    """
    Extract a JSON object from text.

    Supports:
    1. Pure JSON object
    2. JSON surrounded by text
    3. Markdown fenced JSON (```json ... ```)

    Returns the extracted JSON string.
    Raises LLMExtractionError if extraction is ambiguous or no JSON found.
    """
    if not text or not text.strip():
        raise LLMExtractionError("Response is empty or whitespace only", raw_response=text)

    stripped = text.strip()

    # Case 1: Pure JSON object - but must be ONLY the JSON object (no extra data)
    if stripped.startswith("{") and stripped.endswith("}"):
        # Verify it's valid JSON and no extra data
        try:
            json.loads(stripped)
            return stripped
        except json.JSONDecodeError:
            pass  # Fall through to other extraction methods

    # Case 2: Markdown fenced JSON
    fence_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    matches = re.findall(fence_pattern, stripped, re.DOTALL)
    if len(matches) == 1:
        return matches[0].strip()
    elif len(matches) > 1:
        raise LLMExtractionError(
            f"Multiple JSON objects found in markdown fences ({len(matches)})",
            raw_response=text,
        )

    # Case 3: JSON object somewhere in text
    # Find all balanced JSON-like objects
    json_objects = _find_balanced_json_objects(stripped)
    if len(json_objects) == 1:
        return json_objects[0]
    elif len(json_objects) > 1:
        # If multiple, check if one is clearly the assessment (has required fields)
        assessment_candidates = [
            obj for obj in json_objects
            if "phishing_probability" in obj or "bec_probability" in obj
        ]
        if len(assessment_candidates) == 1:
            return assessment_candidates[0]
        raise LLMExtractionError(
            f"Multiple JSON objects found ({len(json_objects)}), cannot determine assessment",
            raw_response=text,
        )

    raise LLMExtractionError("No JSON object found in response", raw_response=text)


# Known wording drift observed from local models that otherwise follow the
# schema correctly: the system prompt explicitly forbids these words for
# evidence_strength, but a model still occasionally substitutes a familiar
# severity word for the required categorical value. Mapping only these exact,
# previously-observed synonyms - and leaving every other string untouched -
# repairs that drift without silently accepting a truly malformed value.
_EVIDENCE_STRENGTH_SYNONYMS: dict[str, str] = {
    "high": "explicit_detection",
    "strong": "explicit_detection",
    "confirmed": "explicit_detection",
    "detected": "explicit_detection",
    "explicit": "explicit_detection",
    "severe": "explicit_detection",
    "critical": "explicit_detection",
    "medium": "reported_indicator",
    "moderate": "reported_indicator",
    "reported": "reported_indicator",
    "suspicious": "reported_indicator",
    "indicator": "reported_indicator",
    "low": "weak_observation",
    "weak": "weak_observation",
    "minor": "weak_observation",
    "observation": "weak_observation",
    "informational": "weak_observation",
}


_PROBABILITY_FIELDS = ("phishing_probability", "bec_probability", "social_engineering_probability")


def _normalize_probability_ranges(data: Any) -> Any:
    """
    Clamp a numeric probability field that falls outside [0.0, 1.0] back to
    the nearest boundary, instead of hard-failing validation.

    Observed drift from a smaller local instruct model: it emits a plain
    number like 3 for phishing_probability - not a percentage, not a
    documented alternate scale, just a value outside the range it was told to
    use. Clamping to the nearest boundary preserves the value's apparent
    direction (something above 1 reads as "very confident/high", so it
    clamps up to 1.0; a negative value clamps down to 0.0) without guessing
    at an unstated alternate scale - e.g. dividing by 100 or by 10 - which
    could silently invert what the model meant.
    """
    if not isinstance(data, dict):
        return data

    for field_name in _PROBABILITY_FIELDS:
        value = data.get(field_name)
        if isinstance(value, bool):
            continue  # bool is a subclass of int; never touch True/False here
        if isinstance(value, (int, float)):
            clamped = float(value)
            if clamped > 1.0:
                clamped = 1.0
            elif clamped < 0.0:
                clamped = 0.0
            data[field_name] = round(clamped, 2)

    return data


def _normalize_attachment_finding_strengths(data: Any) -> Any:
    """
    Rewrite recognized evidence_strength synonyms in-place, in attachment
    findings only. Does not touch any other field. A value not present in
    ``_EVIDENCE_STRENGTH_SYNONYMS`` is left exactly as the model produced it,
    so schema validation still catches genuinely invalid output.
    """
    if not isinstance(data, dict):
        return data

    findings = data.get("attachment_findings")
    if not isinstance(findings, list):
        return data

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        value = finding.get("evidence_strength")
        if not isinstance(value, str):
            continue
        canonical = _EVIDENCE_STRENGTH_SYNONYMS.get(value.strip().lower())
        if canonical is not None:
            finding["evidence_strength"] = canonical

    return data


def validate_llm_output(raw_response: str) -> AIAssessment:
    """
    Validate raw LLM response and return AIAssessment.

    Pipeline:
    1. Extract JSON from raw response
    2. Parse JSON
    3. Validate against AIAssessment schema (strict mode)

    Raises:
        LLMExtractionError: JSON cannot be extracted unambiguously
        LLMJSONParseError: JSON is malformed
        LLMSchemaValidationError: JSON doesn't match AIAssessment schema
    """
    if not isinstance(raw_response, str):
        raise LLMExtractionError(
            f"Expected string response, got {type(raw_response).__name__}",
            raw_response=str(raw_response),
        )

    # Extract JSON
    try:
        json_str = _extract_json_from_text(raw_response)
    except LLMExtractionError:
        raise
    except Exception as e:
        raise LLMExtractionError(
            f"Unexpected error during JSON extraction: {e}",
            raw_response=raw_response,
        ) from e

    # Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise LLMJSONParseError(
            f"Failed to parse extracted JSON: {e}",
            raw_response=raw_response,
        ) from e

    # Normalize single top-level wrapper {"assessment": {...}} before strict validation
    # Minimal unwrapping: only when the parsed object is exactly {"assessment": dict}
    if isinstance(data, dict) and set(data.keys()) == {"assessment"} and isinstance(data["assessment"], dict):
        data = data["assessment"]

    # Repair known evidence_strength wording drift before strict validation.
    data = _normalize_attachment_finding_strengths(data)

    # Repair known out-of-range probability values before strict validation.
    data = _normalize_probability_ranges(data)

    # Validate against AIAssessment schema with strict mode
    # strict=True prevents coercion (e.g., "yes" -> True, 1 -> True)
    try:
        assessment = AIAssessment.model_validate(data, strict=True)
    except Exception as e:
        raise LLMSchemaValidationError(
            f"LLM output failed schema validation: {e}",
            raw_response=raw_response,
        ) from e

    return assessment


def _find_balanced_json_objects(text: str) -> list[str]:
    """Find all balanced JSON objects in text."""
    objects = []
    stack = []
    start = None

    for i, char in enumerate(text):
        if char == "{":
            if not stack:
                start = i
            stack.append("{")
        elif char == "}":
            if stack:
                stack.pop()
                if not stack and start is not None:
                    obj = text[start:i + 1]
                    # Quick validation - must look like our assessment
                    try:
                        json.loads(obj)
                        objects.append(obj)
                    except json.JSONDecodeError:
                        pass
                    start = None

    return objects