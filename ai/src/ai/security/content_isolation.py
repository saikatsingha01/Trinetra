from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.ai.contracts import EmailModel, EvidencePackage


@dataclass(frozen=True)
class UntrustedEmailContent:
    """
    Explicit representation of untrusted email content for safe downstream
    consumption.

    The authoritative incoming Pydantic model is EmailModel from
    ollama_model.py.

    This dataclass is the internal security-boundary representation used by
    the downstream pipeline.
    """

    sender: str
    recipient: str
    subject: str
    body: str

    # Backend metadata preserved as untrusted evidence.
    date: str | None = None
    originating_ip: str | None = None
    received: list[Any] = field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    message_id: str | None = None
    content_type: list[Any] = field(default_factory=list)
    file_names: list[str] = field(default_factory=list)
    attachments: dict[str, Any] = field(default_factory=dict)
    dkim_signature: str | None = None
    authentication_results: list[Any] = field(default_factory=list)
    iocs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_email_model(
        cls,
        email: EmailModel,
    ) -> UntrustedEmailContent:
        """
        Convert the authoritative ollama_model.EmailModel into the internal
        untrusted representation used by the security pipeline.

        Important:
        - EmailModel.from_    -> sender
        - EmailModel.to        -> recipient
        - EmailModel.content   -> body
        - EmailModel.file_name -> file_names

        These renamed fields are INTERNAL names only.
        """

        iocs_dict: dict[str, Any] = {
            "ip_address": list(email.iocs.ip_address),
            "url": list(email.iocs.url),
            "domain": list(email.iocs.domain),
        }

        return cls(
            sender=email.from_ or "",
            recipient=email.to or "",
            subject=email.subject or "",
            body=email.content,

            date=email.date,
            originating_ip=email.originating_ip,

            received=list(email.received),

            reply_to=email.reply_to,
            return_path=email.return_path,
            message_id=email.message_id,

            content_type=list(email.content_type),
            file_names=list(email.file_name),

            attachments=email.attachments.model_dump(
                by_alias=True
            ),

            dkim_signature=email.dkim_signature,

            authentication_results=list(
                email.authentication_results
            ),

            iocs=iocs_dict,
        )

    @classmethod
    def from_evidence_package(
        cls,
        pkg: EvidencePackage,
    ) -> UntrustedEmailContent:
        """
        Extract the authoritative EmailModel from EvidencePackage and
        convert it into the internal security representation.
        """
        return cls.from_email_model(pkg.email)

    def to_trusted_dict(self) -> dict[str, Any]:
        """
        Serialize the isolated email for downstream prompt construction.

        All email-derived information remains explicitly marked as
        untrusted evidence.
        """

        return {
            "untrusted_sender": self.sender,
            "untrusted_recipient": self.recipient,
            "untrusted_subject": self.subject,
            "untrusted_body": self.body,

            "untrusted_date": self.date,
            "untrusted_originating_ip": self.originating_ip,

            "untrusted_received": self.received,

            "untrusted_reply_to": self.reply_to,
            "untrusted_return_path": self.return_path,
            "untrusted_message_id": self.message_id,

            "untrusted_content_type": self.content_type,
            "untrusted_file_names": self.file_names,
            "untrusted_attachments": self.attachments,

            "untrusted_dkim_signature": self.dkim_signature,
            "untrusted_authentication_results": (
                self.authentication_results
            ),

            "untrusted_iocs": self.iocs,
        }


@dataclass(frozen=True)
class IsolatedEvidence:
    """
    Complete isolated evidence package with explicit trust boundaries.
    """

    case_id: str
    email: UntrustedEmailContent
    security_analysis: dict[str, Any]
    threat_intelligence: dict[str, Any]
    forensic_evidence: dict[str, Any]

    @classmethod
    def from_evidence_package(
        cls,
        pkg: EvidencePackage,
    ) -> IsolatedEvidence:

        return cls(
            case_id=pkg.case_id,

            email=UntrustedEmailContent.from_evidence_package(
                pkg
            ),

            # Pydantic models from ollama_model.py must be serialized
            # before entering the internal dictionary-based stages.
            security_analysis=(
                pkg.security_analysis.model_dump(
                    by_alias=True
                )
            ),

            threat_intelligence=(
                pkg.threat_intelligence.model_dump(
                    by_alias=True
                )
            ),

            forensic_evidence=dict(
                pkg.forensic_evidence
            ),
        )

    def to_prompt_dict(self) -> dict[str, Any]:
        """
        Convert isolated evidence into a prompt-safe dictionary.
        """

        return {
            "case_id": self.case_id,

            **self.email.to_trusted_dict(),

            "untrusted_security_analysis": (
                self.security_analysis
            ),

            "untrusted_threat_intelligence": (
                self.threat_intelligence
            ),

            "untrusted_forensic_evidence": (
                self.forensic_evidence
            ),
        }


def isolate_evidence(
    pkg: EvidencePackage,
) -> IsolatedEvidence:
    """
    Main security-boundary entry point.
    """

    return IsolatedEvidence.from_evidence_package(
        pkg
    )