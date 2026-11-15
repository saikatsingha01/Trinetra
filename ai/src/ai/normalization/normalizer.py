from __future__ import annotations

import copy

from dataclasses import dataclass, field

from typing import Any

from src.ai.security import (
    IsolatedEvidence,
    UntrustedEmailContent,
)


@dataclass(frozen=True)
class NormalizedEmailContent:
    """
    Normalized email content preserving forensic integrity.

    The names in this class are internal pipeline names.

    The authoritative backend model is still EmailModel from
    ollama_model.py.
    """

    sender: str
    recipient: str

    original_subject: str
    original_body: str

    normalized_subject: str
    normalized_body: str

    # Backend metadata — preserved as normalized UNTRUSTED evidence.
    date: str | None = None
    originating_ip: str | None = None

    received: list[Any] = field(
        default_factory=list
    )

    reply_to: str | None = None
    return_path: str | None = None
    message_id: str | None = None

    content_type: list[Any] = field(
        default_factory=list
    )

    file_names: list[str] = field(
        default_factory=list
    )

    attachments: dict[str, Any] = field(
        default_factory=dict
    )

    dkim_signature: str | None = None

    authentication_results: list[Any] = field(
        default_factory=list
    )

    iocs: dict[str, Any] = field(
        default_factory=dict
    )

    @classmethod
    def from_untrusted(
        cls,
        email: UntrustedEmailContent,
    ) -> NormalizedEmailContent:

        return cls(
            sender=_normalize_whitespace(
                email.sender
            ),

            recipient=_normalize_whitespace(
                email.recipient
            ),

            original_subject=email.subject,

            original_body=email.body,

            normalized_subject=_normalize_subject(
                email.subject
            ),

            normalized_body=_normalize_body(
                email.body
            ),

            date=(
                _normalize_whitespace(email.date)
                if email.date is not None
                else None
            ),

            originating_ip=(
                _normalize_whitespace(
                    email.originating_ip
                )
                if email.originating_ip is not None
                else None
            ),

            received=(
                _normalize_structured_value(
                    email.received
                )
                if email.received
                else []
            ),

            reply_to=(
                _normalize_whitespace(
                    email.reply_to
                )
                if email.reply_to is not None
                else None
            ),

            return_path=(
                _normalize_whitespace(
                    email.return_path
                )
                if email.return_path is not None
                else None
            ),

            message_id=(
                _normalize_whitespace(
                    email.message_id
                )
                if email.message_id is not None
                else None
            ),

            content_type=(
                _normalize_structured_value(
                    email.content_type
                )
                if email.content_type
                else []
            ),

            file_names=(
                [
                    _normalize_forensic_string(
                        filename
                    )
                    for filename in email.file_names
                ]
                if email.file_names
                else []
            ),

            attachments=(
                _normalize_structured_value(
                    email.attachments
                )
                if email.attachments
                else {}
            ),

            dkim_signature=(
                _normalize_whitespace(
                    email.dkim_signature
                )
                if email.dkim_signature is not None
                else None
            ),

            authentication_results=(
                _normalize_structured_value(
                    email.authentication_results
                )
                if email.authentication_results
                else []
            ),

            iocs=(
                _normalize_structured_value(
                    email.iocs
                )
                if email.iocs
                else {}
            ),
        )


@dataclass(frozen=True)
class NormalizedEvidence:
    """
    Fully normalized evidence package ready for downstream analysis.
    """

    case_id: str

    email: NormalizedEmailContent

    security_analysis: dict[str, Any]

    threat_intelligence: dict[str, Any]

    original_forensic_evidence: dict[str, Any] = field(
        default_factory=dict
    )

    normalized_forensic_evidence: dict[str, Any] = field(
        default_factory=dict
    )

    @classmethod
    def from_isolated(
        cls,
        isolated: IsolatedEvidence,
    ) -> NormalizedEvidence:

        return cls(
            case_id=_normalize_whitespace(
                isolated.case_id
            ),

            email=NormalizedEmailContent.from_untrusted(
                isolated.email
            ),

            security_analysis=_normalize_dict(
                isolated.security_analysis
            ),

            threat_intelligence=_normalize_dict(
                isolated.threat_intelligence
            ),

            original_forensic_evidence=(
                _preserve_forensic_evidence(
                    isolated.forensic_evidence
                )
            ),

            normalized_forensic_evidence=(
                _normalize_forensic_evidence(
                    isolated.forensic_evidence
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to a dictionary for downstream processing.
        """

        return {
            "case_id": self.case_id,

            "email": {
                "sender": self.email.sender,
                "recipient": self.email.recipient,

                "original_subject": (
                    self.email.original_subject
                ),

                "original_body": (
                    self.email.original_body
                ),

                "normalized_subject": (
                    self.email.normalized_subject
                ),

                "normalized_body": (
                    self.email.normalized_body
                ),

                "date": self.email.date,

                "originating_ip": (
                    self.email.originating_ip
                ),

                "received": self.email.received,

                "reply_to": self.email.reply_to,
                "return_path": self.email.return_path,
                "message_id": self.email.message_id,

                "content_type": (
                    self.email.content_type
                ),

                "file_names": (
                    self.email.file_names
                ),

                "attachments": (
                    self.email.attachments
                ),

                "dkim_signature": (
                    self.email.dkim_signature
                ),

                "authentication_results": (
                    self.email.authentication_results
                ),

                "iocs": self.email.iocs,
            },

            "security_analysis": (
                self.security_analysis
            ),

            "threat_intelligence": (
                self.threat_intelligence
            ),

            "original_forensic_evidence": (
                self.original_forensic_evidence
            ),

            "normalized_forensic_evidence": (
                self.normalized_forensic_evidence
            ),
        }


def normalize_evidence(
    isolated: IsolatedEvidence,
) -> NormalizedEvidence:
    """
    Main normalization entry point.
    """

    return NormalizedEvidence.from_isolated(
        isolated
    )


def _normalize_whitespace(
    text: str,
) -> str:

    if not isinstance(text, str):
        return str(text)

    return text.strip()


def _normalize_subject(
    subject: str,
) -> str:

    if not isinstance(subject, str):
        return str(subject)

    stripped = subject.strip()

    return " ".join(
        stripped.split()
    )


def _normalize_body(
    body: str,
) -> str:

    if not isinstance(body, str):
        return str(body)

    return body.strip()


_HEX_DIGITS = frozenset(
    "0123456789abcdefABCDEF"
)

_HASH_HEX_LENGTHS = frozenset(
    {
        32,
        40,
        56,
        64,
        96,
        128,
    }
)


def _is_hex_of_length(
    value: Any,
    length: int,
) -> bool:

    if not isinstance(value, str):
        return False

    if len(value) != length:
        return False

    return all(
        character in _HEX_DIGITS
        for character in value
    )


def _is_sha256(
    value: str,
) -> bool:

    return _is_hex_of_length(
        value,
        64,
    )


def _is_hash_like(
    value: Any,
) -> bool:

    if not isinstance(value, str):
        return False

    if len(value) not in _HASH_HEX_LENGTHS:
        return False

    return all(
        character in _HEX_DIGITS
        for character in value
    )


def _normalize_forensic_string(
    value: str,
) -> str:

    if _is_hash_like(value):
        return value

    return value.strip()


def _normalize_structured_value(
    value: Any,
) -> Any:

    if isinstance(value, dict):

        return {
            key: _normalize_structured_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):

        return [
            _normalize_structured_value(item)
            for item in value
        ]

    if isinstance(value, str):

        return _normalize_forensic_string(
            value
        )

    return value


def _preserve_forensic_evidence(
    evidence: dict[str, Any],
) -> dict[str, Any]:

    if not isinstance(evidence, dict):
        return {}

    return copy.deepcopy(
        evidence
    )


def _normalize_forensic_evidence(
    evidence: dict[str, Any],
) -> dict[str, Any]:

    if not isinstance(evidence, dict):
        return {}

    return _normalize_structured_value(
        evidence
    )


def _normalize_dict(
    value: dict[str, Any],
) -> dict[str, Any]:

    if not isinstance(value, dict):
        return {}

    return {
        key: _normalize_structured_value(item)
        for key, item in value.items()
    }