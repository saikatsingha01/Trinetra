from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.ai.contracts import EvidencePackage


@dataclass(frozen=True)
class GuardConfig:
    max_subject_length: int = 1000
    max_body_length: int = 100_000
    max_security_analysis_keys: int = 100
    max_threat_intel_keys: int = 100
    max_forensic_evidence_keys: int = 200
    max_nested_depth: int = 15
    max_list_items: int = 500
    max_string_length: int = 10_000


class InputGuardError(Exception):
    def __init__(
        self,
        message: str,
        field: str | None = None,
    ):
        super().__init__(message)
        self.field = field


def _check_dict_size(
    value: dict[str, Any],
    max_keys: int,
    path: str,
) -> None:

    if len(value) > max_keys:
        raise InputGuardError(
            (
                f"{path} has too many keys: "
                f"{len(value)} > {max_keys}"
            ),
            field=path,
        )


def _check_list_size(
    value: list[Any],
    max_items: int,
    path: str,
) -> None:

    if len(value) > max_items:
        raise InputGuardError(
            (
                f"{path} has too many items: "
                f"{len(value)} > {max_items}"
            ),
            field=path,
        )


def _check_string_length(
    value: str,
    max_length: int,
    path: str,
) -> None:

    if len(value) > max_length:
        raise InputGuardError(
            (
                f"{path} exceeds max string length: "
                f"{len(value)} > {max_length}"
            ),
            field=path,
        )


def _check_nested_depth(
    obj: Any,
    max_depth: int,
    current_depth: int = 0,
    path: str = "",
) -> None:

    if current_depth > max_depth:
        raise InputGuardError(
            (
                f"Nesting too deep at {path}: "
                f"{current_depth} > {max_depth}"
            ),
            field=path,
        )

    if isinstance(obj, dict):

        for key, value in obj.items():
            _check_nested_depth(
                value,
                max_depth,
                current_depth + 1,
                f"{path}.{key}",
            )

    elif isinstance(obj, list):

        for index, value in enumerate(obj):
            _check_nested_depth(
                value,
                max_depth,
                current_depth + 1,
                f"{path}[{index}]",
            )


def _validate_structured_evidence(
    obj: Any,
    max_depth: int,
    max_list_items: int,
    max_string_length: int,
    path: str = "",
) -> None:
    """
    Recursively validate dictionary/list/string structures.
    """

    if isinstance(obj, dict):

        for key, value in obj.items():
            _validate_structured_evidence(
                value,
                max_depth,
                max_list_items,
                max_string_length,
                f"{path}.{key}",
            )

    elif isinstance(obj, list):

        _check_list_size(
            obj,
            max_list_items,
            path,
        )

        for index, value in enumerate(obj):
            _validate_structured_evidence(
                value,
                max_depth,
                max_list_items,
                max_string_length,
                f"{path}[{index}]",
            )

    elif isinstance(obj, str):

        _check_string_length(
            obj,
            max_string_length,
            path,
        )


def validate_evidence_package(
    pkg: EvidencePackage,
    config: GuardConfig | None = None,
) -> None:
    """
    Validate the authoritative Ollama EvidencePackage.

    The package itself comes from ollama_model.py.

    Security analysis and threat intelligence are serialized into
    dictionaries only for size/depth inspection.
    """

    cfg = config or GuardConfig()

    # ----------------------------------------------------------
    # Case ID
    # ----------------------------------------------------------

    if not pkg.case_id or not pkg.case_id.strip():

        raise InputGuardError(
            "case_id is empty",
            field="case_id",
        )

    # ----------------------------------------------------------
    # Email
    # ----------------------------------------------------------

    email = pkg.email

    # ollama_model.EmailModel.from_ -> sender internally
    if not email.from_ or not email.from_.strip():

        raise InputGuardError(
            "email.from is empty",
            field="email.from",
        )

    # ollama_model.EmailModel.to
    if not email.to or not email.to.strip():

        raise InputGuardError(
            "email.to is empty",
            field="email.to",
        )

    # Subject
    subject = email.subject or ""

    if len(subject) > cfg.max_subject_length:

        raise InputGuardError(
            (
                "email.subject exceeds max length: "
                f"{len(subject)} > "
                f"{cfg.max_subject_length}"
            ),
            field="email.subject",
        )

    # Content
    if len(email.content) > cfg.max_body_length:

        raise InputGuardError(
            (
                "email.content exceeds max length: "
                f"{len(email.content)} > "
                f"{cfg.max_body_length}"
            ),
            field="email.content",
        )

    # ----------------------------------------------------------
    # Pydantic models -> dictionaries for recursive inspection
    # ----------------------------------------------------------

    security_analysis = (
        pkg.security_analysis.model_dump(
            by_alias=True
        )
    )

    threat_intelligence = (
        pkg.threat_intelligence.model_dump(
            by_alias=True
        )
    )

    forensic_evidence = dict(
        pkg.forensic_evidence
    )

    # ----------------------------------------------------------
    # Top-level size checks
    # ----------------------------------------------------------

    _check_dict_size(
        security_analysis,
        cfg.max_security_analysis_keys,
        "security_analysis",
    )

    _check_dict_size(
        threat_intelligence,
        cfg.max_threat_intel_keys,
        "threat_intelligence",
    )

    _check_dict_size(
        forensic_evidence,
        cfg.max_forensic_evidence_keys,
        "forensic_evidence",
    )

    # ----------------------------------------------------------
    # Depth checks
    # ----------------------------------------------------------

    _check_nested_depth(
        security_analysis,
        cfg.max_nested_depth,
        path="security_analysis",
    )

    _check_nested_depth(
        threat_intelligence,
        cfg.max_nested_depth,
        path="threat_intelligence",
    )

    _check_nested_depth(
        forensic_evidence,
        cfg.max_nested_depth,
        path="forensic_evidence",
    )

    # ----------------------------------------------------------
    # Recursive content checks
    # ----------------------------------------------------------

    _validate_structured_evidence(
        security_analysis,
        cfg.max_nested_depth,
        cfg.max_list_items,
        cfg.max_string_length,
        "security_analysis",
    )

    _validate_structured_evidence(
        threat_intelligence,
        cfg.max_nested_depth,
        cfg.max_list_items,
        cfg.max_string_length,
        "threat_intelligence",
    )

    _validate_structured_evidence(
        forensic_evidence,
        cfg.max_nested_depth,
        cfg.max_list_items,
        cfg.max_string_length,
        "forensic_evidence",
    )