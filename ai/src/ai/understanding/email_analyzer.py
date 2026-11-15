# from __future__ import annotations

# from dataclasses import dataclass, field
# from typing import Any

# from src.ai.normalization import NormalizedEvidence


# @dataclass(frozen=True)
# class Signal:
#     """
#     Represents a single observable signal with provenance.

#     Each signal captures what was found, where it was found, and the category.

#     ``source`` names the origin of the evidence. For email-derived signals this
#     is a coarse label ("urgency", "sender", "security_analysis"). For signals
#     derived from nested forensic evidence it is the full path to the field that
#     justified the signal, e.g.
#     ``forensic_evidence.attachments[0].analysis.embedded_files[0].malicious``.

#     A signal means "this evidence was observed". It is never a verdict.
#     """
#     category: str
#     indicator: str
#     source: str
#     context: str = ""


# @dataclass(frozen=True)
# class UnderstandingResult:
#     """
#     Structured understanding signals extracted from normalized evidence.

#     This is intermediate data - signals for downstream reasoning, NOT final decisions.

#     The six email signal categories are unchanged. ``forensic_indicators`` is an
#     additive seventh bucket holding attachment/forensic-evidence observations;
#     it is never populated from email text and never replaces the other six.
#     """
#     urgency: list[Signal] = field(default_factory=list)
#     credential_request: list[Signal] = field(default_factory=list)
#     financial_request: list[Signal] = field(default_factory=list)
#     social_engineering: list[Signal] = field(default_factory=list)
#     phishing_indicators: list[Signal] = field(default_factory=list)
#     bec_indicators: list[Signal] = field(default_factory=list)
#     forensic_indicators: list[Signal] = field(default_factory=list)

#     def to_dict(self) -> dict[str, Any]:
#         """Serialize to dictionary."""
#         return {
#             "urgency": [s.__dict__ for s in self.urgency],
#             "credential_request": [s.__dict__ for s in self.credential_request],
#             "financial_request": [s.__dict__ for s in self.financial_request],
#             "social_engineering": [s.__dict__ for s in self.social_engineering],
#             "phishing_indicators": [s.__dict__ for s in self.phishing_indicators],
#             "bec_indicators": [s.__dict__ for s in self.bec_indicators],
#             "forensic_indicators": [s.__dict__ for s in self.forensic_indicators],
#         }

#     def has_signals(self) -> bool:
#         """Check if any signals were detected."""
#         return any([
#             self.urgency,
#             self.credential_request,
#             self.financial_request,
#             self.social_engineering,
#             self.phishing_indicators,
#             self.bec_indicators,
#             self.forensic_indicators,
#         ])


# _URGENCY_PATTERNS = [
#     ("urgent", "urgent"),
#     ("immediately", "immediately"),
#     ("asap", "asap"),
#     ("right now", "right now"),
#     ("within", "time-bound deadline"),
#     ("deadline", "deadline"),
#     ("action required", "action required"),
#     ("act now", "act now"),
#     ("time sensitive", "time sensitive"),
#     ("expire", "expiration threat"),
#     ("last chance", "last chance"),
#     ("hurry", "hurry"),
#     ("prompt", "prompt action"),
# ]

# _CREDENTIAL_PATTERNS = [
#     ("password", "password request"),
#     ("username", "username request"),
#     ("login", "login credentials"),
#     ("credential", "credential request"),
#     ("authentication code", "auth code"),
#     ("otp", "one-time password"),
#     ("one-time password", "otp"),
#     ("2fa", "two-factor authentication"),
#     ("two-factor", "two-factor auth"),
#     ("mfa", "multi-factor authentication"),
#     ("verify your account", "account verification"),
#     ("confirm your password", "password confirmation"),
#     ("security code", "security code"),
#     ("access code", "access code"),
#     ("pin", "pin request"),
# ]

# _FINANCIAL_PATTERNS = [
#     ("wire transfer", "wire transfer"),
#     ("bank transfer", "bank transfer"),
#     ("payment", "payment request"),
#     ("invoice", "invoice"),
#     ("payroll", "payroll"),
#     ("salary", "salary"),
#     ("direct deposit", "direct deposit"),
#     ("bank account", "bank account"),
#     ("routing number", "routing number"),
#     ("account number", "account number"),
#     ("swift", "swift code"),
#     ("iban", "iban"),
#     ("ach", "ach transfer"),
#     ("remittance", "remittance"),
#     ("funds", "funds transfer"),
#     ("money", "money transfer"),
#     ("financial", "financial request"),
#     ("transfer", "transfer request"),
#     ("deposit", "deposit"),
#     ("withdrawal", "withdrawal"),
# ]

# _SOCIAL_ENGINEERING_PATTERNS = [
#     ("ceo", "executive impersonation"),
#     ("cfo", "executive impersonation"),
#     ("president", "executive impersonation"),
#     ("director", "executive impersonation"),
#     ("manager", "authority impersonation"),
#     ("supervisor", "authority impersonation"),
#     ("confidential", "secrecy request"),
#     ("secret", "secrecy request"),
#     ("private", "secrecy request"),
#     ("do not tell", "secrecy request"),
#     ("do not share", "secrecy request"),
#     ("bypass", "procedure bypass"),
#     ("override", "procedure override"),
#     ("exception", "exception request"),
#     ("special", "special treatment"),
#     ("personal favor", "personal favor"),
#     ("help me", "emotional manipulation"),
#     ("trust", "trust exploitation"),
#     ("believe", "belief manipulation"),
# ]

# _PHISHING_PATTERNS = [
#     # Merely asking the recipient to click a link is not sufficient evidence
#     # of phishing. Actual URL/domain threat intelligence is handled separately
#     # by _extract_domain_signals() and remains a phishing signal when supplied.
#     ("verify your account", "account verification"),
#     ("update your account", "account update"),
#     ("confirm your identity", "identity confirmation"),
#     ("suspended", "account suspension threat"),
#     ("locked", "account lock threat"),
#     ("unauthorized", "unauthorized access"),
#     ("security alert", "security alert"),
#     ("verify now", "immediate verification"),
#     ("login to", "login link"),
#     ("sign in to", "sign in link"),
#     ("reset your password", "password reset"),
#     ("unusual activity", "unusual activity alert"),
#     ("security check", "security check"),
# ]

# _BEC_PATTERNS = [
#     ("change payment", "payment change request"),
#     ("update payment", "payment update request"),
#     ("new account", "new account details"),
#     ("new bank", "new bank details"),
#     ("vendor", "vendor payment"),
#     ("supplier", "supplier payment"),
#     ("outstanding", "outstanding payment"),
#     ("overdue", "overdue payment"),
#     ("immediate payment", "immediate payment"),
#     ("today", "same-day payment"),
#     ("reply to", "reply-to manipulation"),
#     ("from my phone", "mobile excuse"),
#     ("sent from my", "mobile excuse"),
# ]


# def _find_patterns(text: str, patterns: list[tuple[str, str]], source: str) -> list[Signal]:
#     """Find pattern matches in text and return Signal objects."""
#     if not text:
#         return []

#     text_lower = text.lower()
#     signals = []

#     for pattern, label in patterns:
#         if pattern in text_lower:
#             # Find context around the match
#             idx = text_lower.find(pattern)
#             start = max(0, idx - 50)
#             end = min(len(text), idx + len(pattern) + 50)
#             context = text[start:end].strip()

#             signals.append(Signal(
#                 category=source,
#                 indicator=label,
#                 source=source,
#                 context=context,
#             ))

#     return signals


# def _extract_domain_signals(
#     normalized: NormalizedEvidence,
# ) -> list[Signal]:
#     """
#     Extract deterministic signals from the exact SecurityAnalysisModel and
#     ThreatAnalysisModel structures defined by ollama_model.py.

#     This function does not invent a new schema. The normalized dictionaries
#     are produced from the Pydantic models, and every field accessed here
#     corresponds to a field in those models.
#     """

#     signals: list[Signal] = []

#     # ============================================================
#     # SECURITY ANALYSIS
#     # ============================================================

#     sec = normalized.security_analysis

#     if isinstance(sec, dict):

#         authentication = sec.get(
#             "authentication_analysis",
#             {},
#         )

#         if isinstance(authentication, dict):

#             # ----------------------------------------------------
#             # SPF
#             # SecurityAnalysisModel.spf is:
#             # list[tuple[str, str]]
#             #
#             # pyspf check2() normally returns tuples such as:
#             # ("fail", "...")
#             # ----------------------------------------------------

#             spf_results = authentication.get(
#                 "spf",
#                 [],
#             )

#             if isinstance(spf_results, list):

#                 for spf_result in spf_results:

#                     if not isinstance(
#                         spf_result,
#                         (list, tuple),
#                     ):
#                         continue

#                     if not spf_result:
#                         continue

#                     status = str(
#                         spf_result[0]
#                     ).strip().lower()

#                     if status == "fail":

#                         explanation = (
#                             str(
#                                 spf_result[1]
#                             )
#                             if len(spf_result) > 1
#                             else "SPF authentication failed"
#                         )

#                         signals.append(
#                             Signal(
#                                 category="authentication",
#                                 indicator="spf_fail",
#                                 source=(
#                                     "security_analysis."
#                                     "authentication_analysis.spf"
#                                 ),
#                              context=explanation,
#                             )
#                         )

#                     elif status == "pass":

#                         signals.append(
#                             Signal(
#                                 category="authentication",
#                                 indicator="spf_pass",
#                                 source=(
#                                     "security_analysis."
#                                     "authentication_analysis.spf"
#                                 ),
#                                 context=(
#                                     str(spf_result[1])
#                                     if len(spf_result) > 1
#                                     else "SPF authentication passed"
#                                 ),
#                             )
#                         )

#             # ----------------------------------------------------
#             # DKIM
#             # SecurityAnalysisModel.dkim is bool
#             # ----------------------------------------------------

#             dkim_result = authentication.get(
#                 "dkim"
#             )

#             if dkim_result is False:

#                 signals.append(
#                     Signal(
#                         category="authentication",
#                         indicator="dkim_fail",
#                         source=(
#                             "security_analysis."
#                             "authentication_analysis.dkim"
#                         ),
#                     context="DKIM authentication failed",
#                     )
#                 )
#             elif dkim_result is True:

#                 signals.append(
#                     Signal(
#                         category="authentication",
#                         indicator="dkim_pass",
#                         source=(
#                             "security_analysis."
#                             "authentication_analysis.dkim"
#                         ),
#                         context="DKIM authentication passed",
#                     )
#                 )

#             # ----------------------------------------------------
#             # DMARC
#             # SecurityAnalysisModel.dmarc is Any.
#             #
#             # Do not assume a particular nested checkdmarc schema.
#             # Preserve and inspect only explicit textual failures.
#             # ----------------------------------------------------

#             dmarc_result = authentication.get(
#                 "dmarc"
#             )

#             if dmarc_result is not None:

#                 dmarc_text = str(
#                     dmarc_result
#                 ).lower()

#                 if "fail" in dmarc_text:

#                    signals.append(
#                         Signal(
#                             category="authentication",
#                             indicator="dmarc_fail",
#                             source=(
#                                 "security_analysis."
#                                 "authentication_analysis.dmarc"
#                             ),
#                             context=(
#                                 f"DMARC result: "
#                                 f"{dmarc_result}"
#                             ),
#                         )
#                     )

#                 elif "pass" in dmarc_text:

#                     signals.append(
#                         Signal(
#                             category="authentication",
#                             indicator="dmarc_pass",
#                             source=(
#                                 "security_analysis."
#                                 "authentication_analysis.dmarc"
#                             ),
#                             context=(
#                                 f"DMARC result: "
#                                 f"{dmarc_result}"
#                             ),
#                         )
#                     )

#             # ----------------------------------------------------
#             # DNS
#             # SecurityAnalysisModel.dns contains:
#             #
#             # dns_report
#             # reverse_dns_report
#             #
#             # Preserve these as observable signals when reports
#             # actually exist.
#             # ----------------------------------------------------

#             dns = authentication.get(
#                 "dns",
#                 {},
#             )

#             if isinstance(dns, dict):

#                 dns_reports = dns.get(
#                     "dns_report",
#                     [],
#                 )

#                 if isinstance(
#                     dns_reports,
#                     list,
#                 ) and dns_reports:

#                     signals.append(
#                         Signal(
#                             category="authentication",
#                             indicator="dns_analysis_available",
#                             source=(
#                                 "security_analysis."
#                                 "authentication_analysis.dns."
#                                 "dns_report"
#                             ),
#                             context=(
#                                 f"{len(dns_reports)} DNS "
#                                 f"domain report(s) supplied"
#                             ),
#                         )
#                     )

#                 reverse_dns_reports = dns.get(
#                     "reverse_dns_report",
#                     [],
#                 )

#                 if isinstance(
#                     reverse_dns_reports,
#                     list,
#                 ) and reverse_dns_reports:

#                     signals.append(
#                         Signal(
#                             category="authentication",
#                             indicator="reverse_dns_analysis_available",
#                             source=(
#                                 "security_analysis."
#                                 "authentication_analysis.dns."
#                                 "reverse_dns_report"
#                             ),
#                             context=(
#                                 f"{len(reverse_dns_reports)} "
#                                 f"reverse-DNS report(s) supplied"
#                             ),
#                         )
#                     )

#         # --------------------------------------------------------
#         # Sender analysis
#         # --------------------------------------------------------

#         sender_analysis = sec.get(
#             "sender_analysis",
#             {},
#         )

#         if isinstance(
#             sender_analysis,
#             dict,
#         ):

#             sender_findings = sender_analysis.get(
#                 "findings",
#                 [],
#             )

#             if isinstance(
#                 sender_findings,
#                 list,
#             ):

#                 for finding in sender_findings:

#                     signals.append(
#                         Signal(
#                             category="sender",
#                             indicator="sender_finding",
#                             source=(
#                                 "security_analysis."
#                                 "sender_analysis.findings"
#                             ),
#                         context=str(finding),
#                         )
#                     )

#         # --------------------------------------------------------
#         # Header analysis
#         # --------------------------------------------------------

#         header_analysis = sec.get(
#             "header_analysis",
#             {},
#         )

#         if isinstance(
#             header_analysis,
#             dict,
#         ):

#             header_findings = header_analysis.get(
#                 "findings",
#                 [],
#             )

#             if isinstance(
#                 header_findings,
#                 list,
#             ):

#                 for finding in header_findings:

#                     signals.append(
#                         Signal(
#                             category="header",
#                             indicator="header_finding",
#                             source=(
#                                 "security_analysis."
#                                 "header_analysis.findings"
#                             ),
#                             context=str(finding),
#                         )
#                     )

#         # --------------------------------------------------------
#         # Phishing analysis
#         # SecurityAnalysisModel.phishing_analysis is list[str]
#         # --------------------------------------------------------

#         phishing_analysis = sec.get(
#             "phishing_analysis",
#             [],
#         )

#         if isinstance(
#             phishing_analysis,
#             list,
#         ):

#             for finding in phishing_analysis:

#                 signals.append(
#                     Signal(
#                         category="phishing",
#                         indicator="phishing_analysis",
#                         source=(
#                             "security_analysis."
#                             "phishing_analysis"
#                         ),
#                         context=str(finding),
#                     )
#                 )

#     # ============================================================
#     # THREAT ANALYSIS
#     # ============================================================

#     ti = normalized.threat_intelligence

#     if isinstance(ti, dict):

#         # --------------------------------------------------------
#         # IP analysis
#         # --------------------------------------------------------

#         ip_analysis = ti.get(
#             "ip_analysis",
#             {},
#         )

#         if isinstance(
#             ip_analysis,
#             dict,
#         ):

#             originating_ip = ip_analysis.get(
#                 "originating_ip"
#             )

#             if originating_ip:

#                 signals.append(
#                     Signal(
#                         category="threat_intelligence",
#                         indicator="originating_ip_analyzed",
#                         source=(
#                             "threat_intelligence."
#                             "ip_analysis.originating_ip"
#                         ),
#                         context=(
#                             f"Originating IP: "
#                             f"{originating_ip}"
#                         ),
#                     )
#                 )

#             abuse_reports = ip_analysis.get(
#                 "iocs_ip_abuseIPDB",
#                 [],
#             )

#             if isinstance(
#                 abuse_reports,
#                 list,
#             ) and abuse_reports:

#                 signals.append(
#                     Signal(
#                         category="threat_intelligence",
#                         indicator="ip_abuseipdb_report",
#                         source=(
#                             "threat_intelligence."
#                             "ip_analysis.iocs_ip_abuseIPDB"
#                         ),
#                         context=(
#                             f"{len(abuse_reports)} "
#                             f"AbuseIPDB report(s) supplied"
#                         ),
#                     )
#                 )

#             otx_reports = ip_analysis.get(
#                 "iocs_ip_alienvaultOTX",
#                 [],
#             )

#             if isinstance(
#                 otx_reports,
#                 list,
#             ) and otx_reports:

#                 signals.append(
#                     Signal(
#                         category="threat_intelligence",
#                         indicator="ip_alienvault_otx_report",
#                         source=(
#                             "threat_intelligence."
#                             "ip_analysis.iocs_ip_alienvaultOTX"
#                         ),
#                         context=(
#                             f"{len(otx_reports)} "
#                             f"AlienVault OTX report(s) supplied"
#                         ),
#                     )
#                 )

#             originating_abuse_reports = ip_analysis.get(
#                 "originating_ip_abuseIPDB",
#                 [],
#             )

#             if isinstance(
#                 originating_abuse_reports,
#                 list,
#             ) and originating_abuse_reports:

#                 signals.append(
#                     Signal(
#                         category="threat_intelligence",
#                         indicator="originating_ip_abuseipdb_report",
#                         source=(
#                             "threat_intelligence."
#                             "ip_analysis.originating_ip_abuseIPDB"
#                         ),
#                         context=(
#                             f"{len(originating_abuse_reports)} "
#                             f"originating-IP AbuseIPDB report(s) supplied"
#                         ),
#                     )
#                 )

#             originating_otx_reports = ip_analysis.get(
#                 "originating_ip_alienvaultOTX",
#                 [],
#             )

#             if isinstance(
#                 originating_otx_reports,
#                 list,
#             ) and originating_otx_reports:

#                 signals.append(
#                     Signal(
#                         category="threat_intelligence",
#                         indicator="originating_ip_alienvault_otx_report",
#                         source=(
#                             "threat_intelligence."
#                             "ip_analysis.originating_ip_alienvaultOTX"
#                         ),
#                         context=(
#                             f"{len(originating_otx_reports)} "
#                             f"originating-IP OTX report(s) supplied"
#                         ),
#                     )
#                 )

#         # --------------------------------------------------------
#         # VirusTotal URL analysis
#         # --------------------------------------------------------

#         url_analysis = ti.get(
#             "url_analysis",
#             {},
#         )

#         if isinstance(
#             url_analysis,
#             dict,
#         ):

#             url_reports = url_analysis.get(
#                 "virusTotal_report",
#                 [],
#             )

#             if isinstance(
#                 url_reports,
#                 list,
#             ) and url_reports:

#                 signals.append(
#                     Signal(
#                         category="phishing",
#                         indicator="url_virustotal_report",
#                         source=(
#                             "threat_intelligence."
#                             "url_analysis.virusTotal_report"
#                         ),
#                         context=(
#                             f"{len(url_reports)} "
#                             f"VirusTotal URL report(s) supplied"
#                         ),
#                     )
#                 )

#         # --------------------------------------------------------
#         # VirusTotal domain analysis
#         # --------------------------------------------------------

#         domain_analysis = ti.get(
#             "domain_analysis",
#             {},
#         )

#         if isinstance(
#             domain_analysis,
#             dict,
#         ):

#             domain_reports = domain_analysis.get(
#                 "virusTotal_report",
#                 [],
#             )

#             if isinstance(
#                 domain_reports,
#                 list,
#             ) and domain_reports:

#                 signals.append(
#                     Signal(
#                         category="phishing",
#                         indicator="domain_virustotal_report",
#                         source=(
#                             "threat_intelligence."
#                             "domain_analysis.virusTotal_report"
#                         ),
#                         context=(
#                             f"{len(domain_reports)} "
#                             f"VirusTotal domain report(s) supplied"
#                         ),
#                     )
#                 )

#         # --------------------------------------------------------
#         # VirusTotal attachment analysis
#         # --------------------------------------------------------

#         attachment_analysis = ti.get(
#             "attachment_analysis",
#             {},
#         )

#         if isinstance(
#             attachment_analysis,
#             dict,
#         ):

#             attachment_reports = attachment_analysis.get(
#                 "virusTotal_report",
#                 [],
#             )

#             if isinstance(
#                 attachment_reports,
#                 list,
#             ) and attachment_reports:

#                 signals.append(
#                     Signal(
#                         category="threat_intelligence",
#                         indicator="attachment_virustotal_report",
#                         source=(
#                             "threat_intelligence."
#                             "attachment_analysis."
#                             "virusTotal_report"
#                         ),
#                         context=(
#                             f"{len(attachment_reports)} "
#                             f"VirusTotal attachment report(s) supplied"
#                         ),
#                     )
#                 )

#     return signals


# # ---------------------------------------------------------------------------
# # Attachment / forensic evidence understanding
# #
# # The backend supplies arbitrarily nested forensic JSON whose schema is not
# # fixed and may gain fields at any time. Everything below is deterministic
# # evidence extraction: a signal is emitted only when a supplied field
# # explicitly states the finding. Nothing is looked up externally, nothing is
# # inferred from weak context, and no score, probability or verdict is produced.
# # ---------------------------------------------------------------------------

# # Path prefix used when reporting where forensic evidence was found.
# _FORENSIC_ROOT = "forensic_evidence"

# # Recursion backstop only. The input guard already caps nesting at 15 levels;
# # this exists purely so a hand-built pathological structure cannot exhaust the
# # stack. It is far above any depth real evidence can reach.
# _MAX_TRAVERSAL_DEPTH = 200

# # Context strings are bounded so one huge evidence value cannot dominate output.
# _MAX_CONTEXT_LENGTH = 300

# _HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# # Hex digest lengths for the hash algorithms a forensic backend may report:
# # MD5 (32), SHA-1 (40), SHA-224 (56), SHA-256 (64), SHA-384 (96), SHA-512 (128).
# _HASH_HEX_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})

# # Accepted spellings for explicit backend findings, in canonical form (see
# # _canon_key). Tuples rather than sets so iteration order is stable across
# # processes and the extracted signals are reproducible.
# _MALWARE_FLAG_KEYS = ("malwaredetected", "malwarefound", "ismalware", "containsmalware")
# _MALICIOUS_FLAG_KEYS = ("malicious", "ismalicious")
# _KNOWN_MALICIOUS_FLAG_KEYS = ("knownmalicious", "knownbad", "hashknownmalicious", "blacklisted")
# _SUSPICIOUS_FLAG_KEYS = ("suspicious", "issuspicious")

# _REPUTATION_KEYS = ("reputation", "hashreputation", "filereputation", "threatreputation")
# _MALICIOUS_REPUTATIONS = frozenset({"malicious", "known_malicious", "known malicious", "bad", "known_bad", "known bad"})
# _SUSPICIOUS_REPUTATIONS = frozenset({"suspicious", "poor"})

# # A non-empty list under one of these keys is an explicit threat-intelligence
# # result, whatever the surrounding schema looks like.
# _TI_MATCH_LIST_KEYS = ("findings", "matches", "detections", "hits", "threatmatches", "iocmatches")

# _ABUSE_CONFIDENCE_KEYS = ("abuseconfidencescore", "abuseconfidence")

# # AbuseIPDB reports 0-100, where 100 is maximum confidence of abuse. 75 is the
# # conventional "high confidence" cutoff. Below it, no signal is emitted at all:
# # a mid-range score is not a finding.
# _ABUSE_CONFIDENCE_HIGH_THRESHOLD = 75

# _FILENAME_KEYS = ("filename", "originalfilename", "originalname", "displayname", "name")

# _HASH_KEY_HINTS = ("sha256", "sha512", "sha384", "sha1", "md5", "filehash", "hash", "digest")

# # Directly executable / script file types. Used only for a weak
# # suspicious_file_type observation, never for a maliciousness claim. Archive
# # formats (.zip, .rar, .7z) are deliberately absent: they are far too common to
# # be worth observing, and a malicious payload inside one is caught by walking
# # into the embedded-file evidence instead.
# _SUSPICIOUS_EXTENSIONS = frozenset({
#     "application", "bat", "cmd", "com", "cpl", "dll", "exe", "gadget", "hta",
#     "inf", "jar", "js", "jse", "lnk", "msi", "msp", "mst", "pif", "ps1",
#     "psm1", "reg", "scf", "scr", "sct", "shb", "shs", "vbe", "vbs", "ws",
#     "wsf", "wsh",
# })


# def _canon_key(key: Any) -> str:
#     """
#     Canonical form of an evidence key, so camelCase and snake_case agree.

#     ``abuseConfidenceScore`` and ``abuse_confidence_score`` both canonicalize to
#     ``abuseconfidencescore``. Only used for lookups; the original key spelling
#     is always what gets reported in a signal's provenance.
#     """
#     if not isinstance(key, str):
#         return ""
#     return key.lower().replace("_", "").replace("-", "").replace(" ", "")


# def _canonical_items(node: dict[str, Any]) -> dict[str, tuple[str, Any]]:
#     """Map canonical key -> (original key, value) for a single evidence object."""
#     return {_canon_key(k): (k, v) for k, v in node.items() if isinstance(k, str)}


# def _is_affirmative(value: Any) -> bool:
#     """
#     True only for an explicit affirmative supplied by the backend.

#     Accepts the boolean ``True`` and the strings "true"/"yes". Integers are
#     deliberately rejected: ``1`` is too ambiguous to treat as a finding, and
#     ``isinstance(True, int)`` would otherwise let counts through.
#     """
#     if isinstance(value, bool):
#         return value
#     if isinstance(value, str):
#         return value.strip().lower() in ("true", "yes")
#     return False


# def _as_number(value: Any) -> float | None:
#     """Coerce an explicitly numeric evidence value. Booleans are not numbers here."""
#     if isinstance(value, bool):
#         return None
#     if isinstance(value, (int, float)):
#         return float(value)
#     if isinstance(value, str):
#         try:
#             return float(value.strip())
#         except ValueError:
#             return None
#     return None


# def _looks_like_hash(value: Any) -> bool:
#     """Check whether a value has the shape of a hex digest."""
#     if not isinstance(value, str):
#         return False
#     if len(value) not in _HASH_HEX_LENGTHS:
#         return False
#     return all(c in _HEX_DIGITS for c in value)


# def _find_hash(node: dict[str, Any]) -> tuple[str, Any] | None:
#     """
#     Locate a hash value in one evidence object, for provenance/context only.

#     A hash is never itself a reason to emit a signal: a SHA-256 is an identifier
#     and a fingerprint, not a reputation. This exists purely to enrich the context
#     of signals that some other explicit finding already justified, and to
#     distinguish a hash-scoped finding from a generic one.
#     """
#     items = _canonical_items(node)
#     for hint in _HASH_KEY_HINTS:
#         entry = items.get(hint)
#         if entry is not None and _looks_like_hash(entry[1]):
#             return entry
#     for key, value in node.items():
#         if isinstance(key, str) and _looks_like_hash(value):
#             return key, value
#     return None


# def _find_filename(node: dict[str, Any]) -> tuple[str, Any] | None:
#     """Locate a filename in one evidence object, most specific key first."""
#     items = _canonical_items(node)
#     for hint in _FILENAME_KEYS:
#         entry = items.get(hint)
#         if entry is not None and isinstance(entry[1], str) and entry[1].strip():
#             return entry
#     return None


# def _file_extension(filename: str) -> str:
#     """
#     Trailing extension of a filename, lowercased, without the dot.

#     Trailing dots and whitespace are trimmed first so "payload.exe." and
#     "payload.exe " resolve to "exe". A double extension such as
#     "invoice.pdf.exe" resolves to the final, effective one.
#     """
#     trimmed = filename.strip().rstrip(". ")
#     if "." not in trimmed:
#         return ""
#     return trimmed.rsplit(".", 1)[-1].strip().lower()


# def _clip(text: str) -> str:
#     """Bound a context string to a readable length."""
#     if len(text) <= _MAX_CONTEXT_LENGTH:
#         return text
#     return text[:_MAX_CONTEXT_LENGTH] + "..."


# def _describe(file_entry: tuple[str, Any] | None, hash_entry: tuple[str, Any] | None) -> str:
#     """Short factual descriptor of what an evidence object is about."""
#     parts = []
#     if file_entry is not None:
#         parts.append(f"{file_entry[0]}={file_entry[1]}")
#     if hash_entry is not None:
#         parts.append(f"{hash_entry[0]}={hash_entry[1]}")
#     return ", ".join(parts)


# def _walk_objects(node: Any, path: str, depth: int = 0):
#     """
#     Yield every ``(path, object)`` pair reachable in nested forensic evidence.

#     Traverses dicts, lists, dicts inside lists and lists inside dicts, to any
#     depth, without assuming a fixed schema. Nothing is flattened: each object is
#     reported together with the dotted/indexed path it was found at, so parent
#     and child relationships stay recoverable and a signal can point back to
#     exactly where its evidence came from. Scalars are not yielded; they are read
#     from their containing object.
#     """
#     if depth > _MAX_TRAVERSAL_DEPTH:
#         return
#     if isinstance(node, dict):
#         yield path, node
#         for key, value in node.items():
#             child = f"{path}.{key}" if path else str(key)
#             yield from _walk_objects(value, child, depth + 1)
#     elif isinstance(node, list):
#         for index, item in enumerate(node):
#             yield from _walk_objects(item, f"{path}[{index}]", depth + 1)


# def _malware_signals(path: str, items: dict[str, tuple[str, Any]], descriptor: str) -> list[Signal]:
#     """Explicit malware finding, e.g. ``{"malware_detected": true}``."""
#     for canon in _MALWARE_FLAG_KEYS:
#         entry = items.get(canon)
#         if entry is not None and _is_affirmative(entry[1]):
#             detail = f"{entry[0]}={entry[1]!r}"
#             if descriptor:
#                 detail = f"{detail} for {descriptor}"
#             return [Signal(
#                 category="forensic",
#                 indicator="malware_detected",
#                 source=f"{path}.{entry[0]}",
#                 context=_clip(f"Backend explicitly reported {detail}"),
#             )]
#     return []


# def _malicious_signals(path: str, items: dict[str, tuple[str, Any]], descriptor: str) -> list[Signal]:
#     """Explicit maliciousness finding on a file/attachment, e.g. ``{"malicious": true}``."""
#     for canon in _MALICIOUS_FLAG_KEYS:
#         entry = items.get(canon)
#         if entry is not None and _is_affirmative(entry[1]):
#             detail = f"{entry[0]}={entry[1]!r}"
#             if descriptor:
#                 detail = f"{detail} for {descriptor}"
#             return [Signal(
#                 category="forensic",
#                 indicator="malicious_attachment",
#                 source=f"{path}.{entry[0]}",
#                 context=_clip(f"Backend explicitly reported {detail}"),
#             )]
#     return []


# def _known_malicious_hash_signals(
#     path: str,
#     items: dict[str, tuple[str, Any]],
#     hash_entry: tuple[str, Any] | None,
#     descriptor: str,
# ) -> list[Signal]:
#     """
#     Explicit known-bad finding, e.g. ``{"known_malicious": true}``.

#     Reported as ``known_malicious_hash`` only when a hash is present in the same
#     object, so the signal is never named after evidence that is not there.
#     Otherwise it degrades to a generic threat-intelligence match.
#     """
#     for canon in _KNOWN_MALICIOUS_FLAG_KEYS:
#         entry = items.get(canon)
#         if entry is None or not _is_affirmative(entry[1]):
#             continue
#         detail = f"{entry[0]}={entry[1]!r}"
#         if hash_entry is not None:
#             indicator = "known_malicious_hash"
#             detail = f"{detail} for {hash_entry[0]}={hash_entry[1]}"
#         else:
#             indicator = "attachment_threat_intelligence_match"
#             if descriptor:
#                 detail = f"{detail} for {descriptor}"
#         return [Signal(
#             category="forensic",
#             indicator=indicator,
#             source=f"{path}.{entry[0]}",
#             context=_clip(f"Backend explicitly reported {detail}"),
#         )]
#     return []


# def _reputation_signals(
#     path: str,
#     items: dict[str, tuple[str, Any]],
#     hash_entry: tuple[str, Any] | None,
#     descriptor: str,
# ) -> list[Signal]:
#     """
#     Explicit reputation result, e.g. ``{"reputation": "malicious"}``.

#     Only the stated reputation is used. An unrecognised value produces nothing
#     rather than a guess.
#     """
#     for canon in _REPUTATION_KEYS:
#         entry = items.get(canon)
#         if entry is None or not isinstance(entry[1], str):
#             continue
#         value = entry[1].strip().lower()
#         if value in _MALICIOUS_REPUTATIONS:
#             indicator = "known_malicious_hash" if hash_entry is not None else "attachment_threat_intelligence_match"
#         elif value in _SUSPICIOUS_REPUTATIONS:
#             indicator = "suspicious_attachment"
#         else:
#             continue
#         detail = f"{entry[0]}={entry[1]!r}"
#         target = _describe(None, hash_entry) if indicator == "known_malicious_hash" else descriptor
#         if target:
#             detail = f"{detail} for {target}"
#         return [Signal(
#             category="forensic",
#             indicator=indicator,
#             source=f"{path}.{entry[0]}",
#             context=_clip(f"Backend explicitly reported {detail}"),
#         )]
#     return []


# def _suspicious_flag_signals(path: str, items: dict[str, tuple[str, Any]], descriptor: str) -> list[Signal]:
#     """Explicit suspicion finding, e.g. ``{"suspicious": true}``."""
#     for canon in _SUSPICIOUS_FLAG_KEYS:
#         entry = items.get(canon)
#         if entry is not None and _is_affirmative(entry[1]):
#             detail = f"{entry[0]}={entry[1]!r}"
#             if descriptor:
#                 detail = f"{detail} for {descriptor}"
#             return [Signal(
#                 category="forensic",
#                 indicator="suspicious_attachment",
#                 source=f"{path}.{entry[0]}",
#                 context=_clip(f"Backend explicitly reported {detail}"),
#             )]
#     return []


# def _threat_intel_match_signals(path: str, items: dict[str, tuple[str, Any]]) -> list[Signal]:
#     """
#     A non-empty findings/matches/detections list is an explicit intelligence result.

#     Schema-agnostic on purpose: the list may sit under ``threat_intelligence``,
#     ``ip_intelligence`` or a field the backend has not invented yet.
#     """
#     signals = []
#     for canon in _TI_MATCH_LIST_KEYS:
#         entry = items.get(canon)
#         if entry is None or not isinstance(entry[1], list) or not entry[1]:
#             continue
#         signals.append(Signal(
#             category="forensic",
#             indicator="attachment_threat_intelligence_match",
#             source=f"{path}.{entry[0]}",
#             context=_clip(f"Backend supplied {len(entry[1])} item(s) under '{entry[0]}': {entry[1]}"),
#         ))
#     return signals


# def _abuse_confidence_signals(path: str, items: dict[str, tuple[str, Any]]) -> list[Signal]:
#     """
#     High abuse-confidence score from IP intelligence.

#     Only the confidence score itself is used. Country, country code, ISP, usage
#     type, Tor status and report counts are preserved as evidence elsewhere but
#     are never treated as indicators: hosting location and provider are not
#     proof of anything.
#     """
#     for canon in _ABUSE_CONFIDENCE_KEYS:
#         entry = items.get(canon)
#         if entry is None:
#             continue
#         score = _as_number(entry[1])
#         if score is None or score < _ABUSE_CONFIDENCE_HIGH_THRESHOLD:
#             continue
#         ip_entry = items.get("ipaddress") or items.get("ip")
#         target = f" for {ip_entry[0]}={ip_entry[1]}" if ip_entry is not None else ""
#         return [Signal(
#             category="forensic",
#             indicator="high_abuse_confidence",
#             source=f"{path}.{entry[0]}",
#             context=_clip(
#                 f"Backend reported {entry[0]}={entry[1]}{target}, at or above the "
#                 f"{_ABUSE_CONFIDENCE_HIGH_THRESHOLD} high-confidence threshold"
#             ),
#         )]
#     return []


# def _suspicious_file_type_signals(path: str, file_entry: tuple[str, Any] | None) -> list[Signal]:
#     """
#     Weak observation that a filename carries an executable/script extension.

#     An extension is metadata, not analysis. This never yields
#     ``malicious_attachment`` or ``malware_detected``, and the context says so
#     explicitly so no downstream consumer mistakes it for a conclusion.
#     """
#     if file_entry is None:
#         return []
#     key, filename = file_entry
#     extension = _file_extension(filename)
#     if extension not in _SUSPICIOUS_EXTENSIONS:
#         return []
#     return [Signal(
#         category="forensic",
#         indicator="suspicious_file_type",
#         source=f"{path}.{key}",
#         context=_clip(
#             f"{key}={filename} carries the executable/script extension '.{extension}'. "
#             f"Weak observation only: a file extension is not evidence of malware."
#         ),
#     )]


# def _signals_for_object(path: str, node: dict[str, Any]) -> list[Signal]:
#     """Run every detector against a single evidence object, in a fixed order."""
#     items = _canonical_items(node)
#     hash_entry = _find_hash(node)
#     file_entry = _find_filename(node)
#     descriptor = _describe(file_entry, hash_entry)

#     signals = []
#     signals.extend(_malware_signals(path, items, descriptor))
#     signals.extend(_malicious_signals(path, items, descriptor))
#     signals.extend(_known_malicious_hash_signals(path, items, hash_entry, descriptor))
#     signals.extend(_reputation_signals(path, items, hash_entry, descriptor))
#     signals.extend(_suspicious_flag_signals(path, items, descriptor))
#     signals.extend(_threat_intel_match_signals(path, items))
#     signals.extend(_abuse_confidence_signals(path, items))
#     signals.extend(_suspicious_file_type_signals(path, file_entry))
#     return signals


# def extract_forensic_signals(
#     forensic_evidence: dict[str, Any],
#     root: str = _FORENSIC_ROOT,
# ) -> list[Signal]:
#     """
#     Extract deterministic signals from nested attachment/forensic evidence.

#     Walks the whole structure - dicts, lists, dicts in lists, lists in dicts, at
#     any depth - and emits a signal only where a field explicitly states a
#     finding. Every signal carries the evidence path that justified it.

#     What deliberately produces no signal:

#     - A ``sha256`` or other hash on its own. It is an identifier, not a verdict.
#     - A country, country code, ISP, usage type or hosting provider.
#     - An abuse-confidence score below the high-confidence threshold.
#     - A filename alone, beyond a weak ``suspicious_file_type`` observation.
#     - Any unknown field. Unrecognised evidence is skipped, never fatal.

#     Attacker-controlled text (filenames, extracted strings, nested fields) is
#     carried through as evidence in signal context. It is never executed and
#     never interpreted as an instruction to this application.

#     Returns an empty list for empty, missing or non-dict evidence.
#     """
#     if not isinstance(forensic_evidence, dict) or not forensic_evidence:
#         return []

#     signals = []
#     for path, obj in _walk_objects(forensic_evidence, root):
#         signals.extend(_signals_for_object(path, obj))
#     return signals


# def analyze_email(normalized: NormalizedEvidence) -> UnderstandingResult:
#     """
#     Analyze normalized evidence and extract observable signals.

#     This is a deterministic, rule-based extraction - no ML, no LLM calls.
#     Output is structured signals for downstream reasoning.

#     Covers the six email signal categories plus attachment/forensic
#     observations drawn from the nested forensic evidence payload. No risk score,
#     probability, verdict or final classification is produced here.
#     """
#     result = UnderstandingResult()

#     # Use normalized text for consistent matching
#     subject = normalized.email.normalized_subject
#     body = normalized.email.normalized_body
#     sender = normalized.email.sender
#     recipient = normalized.email.recipient

#     # Extract urgency signals
#     result.urgency.extend(_find_patterns(subject, _URGENCY_PATTERNS, "urgency"))
#     result.urgency.extend(_find_patterns(body, _URGENCY_PATTERNS, "urgency"))

#     # Extract credential request signals
#     result.credential_request.extend(_find_patterns(subject, _CREDENTIAL_PATTERNS, "credential"))
#     result.credential_request.extend(_find_patterns(body, _CREDENTIAL_PATTERNS, "credential"))

#     # Extract financial request signals
#     result.financial_request.extend(_find_patterns(subject, _FINANCIAL_PATTERNS, "financial"))
#     result.financial_request.extend(_find_patterns(body, _FINANCIAL_PATTERNS, "financial"))

#     # Extract social engineering signals
#     result.social_engineering.extend(_find_patterns(subject, _SOCIAL_ENGINEERING_PATTERNS, "social_engineering"))
#     result.social_engineering.extend(_find_patterns(body, _SOCIAL_ENGINEERING_PATTERNS, "social_engineering"))

#     # Extract phishing indicator signals
#     result.phishing_indicators.extend(_find_patterns(subject, _PHISHING_PATTERNS, "phishing"))
#     result.phishing_indicators.extend(_find_patterns(body, _PHISHING_PATTERNS, "phishing"))

#     # Extract BEC indicator signals
#     result.bec_indicators.extend(_find_patterns(subject, _BEC_PATTERNS, "bec"))
#     result.bec_indicators.extend(_find_patterns(body, _BEC_PATTERNS, "bec"))

#     # Add domain/structural signals from security analysis and threat intel
#     domain_signals = _extract_domain_signals(normalized)
#     for sig in domain_signals:
#         if sig.category == "phishing":
#             result.phishing_indicators.append(sig)
#         elif sig.category == "bec":
#             result.bec_indicators.append(sig)

#     # Check sender/recipient patterns
#     sender_lower = sender.lower()
#     recipient_lower = recipient.lower()

#     # Executive sender name but suspicious domain
#     exec_names = ["ceo", "cfo", "president", "director", "founder"]
#     for exec_name in exec_names:
#         if exec_name in sender_lower:
#             result.bec_indicators.append(Signal(
#                 category="bec",
#                 indicator="executive_name_in_sender",
#                 source="sender",
#                 context=f"Sender contains '{exec_name}': {sender}",
#             ))
#             result.social_engineering.append(Signal(
#                 category="social_engineering",
#                 indicator="executive_impersonation_attempt",
#                 source="sender",
#                 context=f"Sender contains executive title: {sender}",
#             ))

#     # Attachment / forensic evidence signals. Purely additive: everything above
#     # is untouched, and this reads only the forensic payload. Absent or empty
#     # forensic evidence simply yields no signals.
#     result.forensic_indicators.extend(
#         extract_forensic_signals(getattr(normalized, "normalized_forensic_evidence", {}))
#     )

#     return result

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.ai.normalization import NormalizedEvidence


@dataclass(frozen=True)
class Signal:
    """
    Represents a single observable signal with provenance.

    Each signal captures what was found, where it was found, and the category.

    ``source`` names the origin of the evidence. For email-derived signals this
    is a coarse label ("urgency", "sender", "security_analysis"). For signals
    derived from nested forensic evidence it is the full path to the field that
    justified the signal, e.g.
    ``forensic_evidence.attachments[0].analysis.embedded_files[0].malicious``.

    A signal means "this evidence was observed". It is never a verdict.
    """
    category: str
    indicator: str
    source: str
    context: str = ""


@dataclass(frozen=True)
class UnderstandingResult:
    """
    Structured understanding signals extracted from normalized evidence.

    This is intermediate data - signals for downstream reasoning, NOT final decisions.

    The six email signal categories are unchanged. ``forensic_indicators`` is an
    additive seventh bucket holding attachment/forensic-evidence observations;
    it is never populated from email text and never replaces the other six.
    """
    urgency: list[Signal] = field(default_factory=list)
    credential_request: list[Signal] = field(default_factory=list)
    financial_request: list[Signal] = field(default_factory=list)
    social_engineering: list[Signal] = field(default_factory=list)
    phishing_indicators: list[Signal] = field(default_factory=list)
    bec_indicators: list[Signal] = field(default_factory=list)
    forensic_indicators: list[Signal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "urgency": [s.__dict__ for s in self.urgency],
            "credential_request": [s.__dict__ for s in self.credential_request],
            "financial_request": [s.__dict__ for s in self.financial_request],
            "social_engineering": [s.__dict__ for s in self.social_engineering],
            "phishing_indicators": [s.__dict__ for s in self.phishing_indicators],
            "bec_indicators": [s.__dict__ for s in self.bec_indicators],
            "forensic_indicators": [s.__dict__ for s in self.forensic_indicators],
        }

    def has_signals(self) -> bool:
        """Check if any signals were detected."""
        return any([
            self.urgency,
            self.credential_request,
            self.financial_request,
            self.social_engineering,
            self.phishing_indicators,
            self.bec_indicators,
            self.forensic_indicators,
        ])


_URGENCY_PATTERNS = [
    ("urgent", "urgent"),
    ("immediately", "immediately"),
    ("asap", "asap"),
    ("right now", "right now"),
    ("within", "time-bound deadline"),
    ("deadline", "deadline"),
    ("action required", "action required"),
    ("act now", "act now"),
    ("time sensitive", "time sensitive"),
    ("expire", "expiration threat"),
    ("last chance", "last chance"),
    ("hurry", "hurry"),
    ("prompt", "prompt action"),
]

_CREDENTIAL_PATTERNS = [
    # Each pattern names the sender ASKING the recipient to supply/confirm
    # something - this is what makes it a credential request. A bare noun
    # like "password" or "login" matches equally on "here is your password"
    # (the sender disclosing something) as on "enter your password"
    # (the sender requesting something), which are opposite risk signals.
    ("enter your password", "password request"),
    ("confirm your password", "password confirmation"),
    ("verify your password", "password request"),
    ("reset your password", "password reset request"),
    ("update your password", "password update request"),
    ("provide your password", "password request"),
    ("re-enter your password", "password request"),
    ("enter your username", "username request"),
    ("provide your username", "username request"),
    ("confirm your username", "username request"),
    ("enter your credentials", "credential request"),
    ("provide your credentials", "credential request"),
    ("confirm your credentials", "credential request"),
    ("verify your credentials", "credential request"),
    ("authentication code", "auth code"),
    ("otp", "one-time password"),
    ("one-time password", "otp"),
    ("2fa", "two-factor authentication"),
    ("two-factor", "two-factor auth"),
    ("mfa", "multi-factor authentication"),
    ("verify your account", "account verification"),
    ("confirm your identity", "identity verification"),
    ("security code", "security code"),
    ("access code", "access code"),
    ("enter your pin", "pin request"),
    ("provide your pin", "pin request"),
    ("confirm your pin", "pin request"),
    ("click here to login", "login request"),
    ("log in to verify", "login request"),
    ("verify your login", "login verification request"),
]

_FINANCIAL_PATTERNS = [
    ("wire transfer", "wire transfer"),
    ("bank transfer", "bank transfer"),
    # Same direction problem as credentials: a bare "payment" matches a
    # status statement ("your payment is completed") identically to an
    # actual demand ("send payment to..."). Only the asking phrase is a
    # meaningful financial-request signal.
    ("send payment", "payment request"),
    ("make a payment", "payment request"),
    ("make the payment", "payment request"),
    ("make payment", "payment request"),
    ("payment today", "payment request"),
    ("process the payment", "payment request"),
    ("process payment", "payment request"),
    ("please pay", "payment request"),
    ("payment is overdue", "payment request"),
    ("update your payment details", "payment redirection request"),
    ("update payment information", "payment redirection request"),
    ("invoice", "invoice"),
    ("payroll", "payroll"),
    ("salary", "salary"),
    ("direct deposit", "direct deposit"),
    ("bank account", "bank account"),
    ("routing number", "routing number"),
    ("account number", "account number"),
    ("swift", "swift code"),
    ("iban", "iban"),
    ("ach", "ach transfer"),
    ("remittance", "remittance"),
    ("funds", "funds transfer"),
    ("money", "money transfer"),
    ("financial", "financial request"),
    ("transfer", "transfer request"),
    ("deposit", "deposit"),
    ("withdrawal", "withdrawal"),
]

_SOCIAL_ENGINEERING_PATTERNS = [
    ("ceo", "executive impersonation"),
    ("cfo", "executive impersonation"),
    ("president", "executive impersonation"),
    ("director", "executive impersonation"),
    ("manager", "authority impersonation"),
    ("supervisor", "authority impersonation"),
    ("confidential", "secrecy request"),
    ("secret", "secrecy request"),
    ("private", "secrecy request"),
    ("do not tell", "secrecy request"),
    ("do not share", "secrecy request"),
    ("bypass", "procedure bypass"),
    ("override", "procedure override"),
    ("exception", "exception request"),
    ("special", "special treatment"),
    ("personal favor", "personal favor"),
    ("help me", "emotional manipulation"),
    ("trust", "trust exploitation"),
    ("believe", "belief manipulation"),
]

_PHISHING_PATTERNS = [
    # Merely asking the recipient to click a link is not sufficient evidence
    # of phishing. Actual URL/domain threat intelligence is handled separately
    # by _extract_domain_signals() and remains a phishing signal when supplied.
    ("verify your account", "account verification"),
    ("update your account", "account update"),
    ("confirm your identity", "identity confirmation"),
    ("suspended", "account suspension threat"),
    ("locked", "account lock threat"),
    ("unauthorized", "unauthorized access"),
    ("security alert", "security alert"),
    ("verify now", "immediate verification"),
    ("login to", "login link"),
    ("sign in to", "sign in link"),
    ("reset your password", "password reset"),
    ("unusual activity", "unusual activity alert"),
    ("security check", "security check"),
]

_BEC_PATTERNS = [
    ("change payment", "payment change request"),
    ("update payment", "payment update request"),
    ("new account", "new account details"),
    ("new bank", "new bank details"),
    ("new vendor", "new bank details"),
    ("vendor bank", "new bank details"),
    ("vendor", "vendor payment"),
    ("supplier", "supplier payment"),
    ("outstanding", "outstanding payment"),
    ("overdue", "overdue payment"),
    ("immediate payment", "immediate payment"),
    ("reply to", "reply-to manipulation"),
    ("from my phone", "mobile excuse"),
    ("sent from my", "mobile excuse"),
]


def _find_patterns(text: str, patterns: list[tuple[str, str]], source: str) -> list[Signal]:
    """
    Find pattern matches in text and return Signal objects.

    Matches on word boundaries, not raw substrings. A plain ``pattern in
    text_lower`` check lets a short pattern fire from inside an unrelated
    word - "ach" (financial pattern for "ach transfer") matches inside
    "attached" and "achievements", "pin" matches inside "opinion" - producing
    a signal for something the text never actually said. Word-boundary
    matching keeps each pattern anchored to the real word or phrase it names.
    """
    if not text:
        return []

    text_lower = text.lower()
    signals = []

    for pattern, label in patterns:
        match = re.search(r"\b" + re.escape(pattern) + r"\b", text_lower)
        if match:
            # Find context around the match
            idx = match.start()
            start = max(0, idx - 50)
            end = min(len(text), idx + len(pattern) + 50)
            context = text[start:end].strip()

            signals.append(Signal(
                category=source,
                indicator=label,
                source=source,
                context=context,
            ))

    return signals


def _extract_domain_signals(
    normalized: NormalizedEvidence,
) -> list[Signal]:
    """
    Extract deterministic signals from the exact SecurityAnalysisModel and
    ThreatAnalysisModel structures defined by ollama_model.py.

    This function does not invent a new schema. The normalized dictionaries
    are produced from the Pydantic models, and every field accessed here
    corresponds to a field in those models.
    """

    signals: list[Signal] = []

    # ============================================================
    # SECURITY ANALYSIS
    # ============================================================

    sec = normalized.security_analysis

    if isinstance(sec, dict):

        authentication = sec.get(
            "authentication_analysis",
            {},
        )

        if isinstance(authentication, dict):

            # ----------------------------------------------------
            # SPF
            # SecurityAnalysisModel.spf is:
            # list[tuple[str, str]]
            #
            # pyspf check2() normally returns tuples such as:
            # ("fail", "...")
            # ----------------------------------------------------

            spf_results = authentication.get(
                "spf",
                [],
            )

            if isinstance(spf_results, list):

                for spf_result in spf_results:

                    if not isinstance(
                        spf_result,
                        (list, tuple),
                    ):
                        continue

                    if not spf_result:
                        continue

                    status = str(
                        spf_result[0]
                    ).strip().lower()

                    if status == "fail":

                        explanation = (
                            str(
                                spf_result[1]
                            )
                            if len(spf_result) > 1
                            else "SPF authentication failed"
                        )

                        signals.append(
                            Signal(
                                category="authentication",
                                indicator="spf_fail",
                                source=(
                                    "security_analysis."
                                    "authentication_analysis.spf"
                                ),
                             context=explanation,
                            )
                        )

                    elif status == "pass":

                        signals.append(
                            Signal(
                                category="authentication",
                                indicator="spf_pass",
                                source=(
                                    "security_analysis."
                                    "authentication_analysis.spf"
                                ),
                                context=(
                                    str(spf_result[1])
                                    if len(spf_result) > 1
                                    else "SPF authentication passed"
                                ),
                            )
                        )

            # ----------------------------------------------------
            # DKIM
            # SecurityAnalysisModel.dkim is bool
            # ----------------------------------------------------

            dkim_result = authentication.get(
                "dkim"
            )

            if dkim_result is False:

                signals.append(
                    Signal(
                        category="authentication",
                        indicator="dkim_fail",
                        source=(
                            "security_analysis."
                            "authentication_analysis.dkim"
                        ),
                    context="DKIM authentication failed",
                    )
                )
            elif dkim_result is True:

                signals.append(
                    Signal(
                        category="authentication",
                        indicator="dkim_pass",
                        source=(
                            "security_analysis."
                            "authentication_analysis.dkim"
                        ),
                        context="DKIM authentication passed",
                    )
                )

            # ----------------------------------------------------
            # DMARC
            # SecurityAnalysisModel.dmarc is Any.
            #
            # Do not assume a particular nested checkdmarc schema.
            # Preserve and inspect only explicit textual failures.
            # ----------------------------------------------------

            dmarc_result = authentication.get(
                "dmarc"
            )

            if dmarc_result is not None:

                dmarc_text = str(
                    dmarc_result
                ).lower()

                if "fail" in dmarc_text:

                   signals.append(
                        Signal(
                            category="authentication",
                            indicator="dmarc_fail",
                            source=(
                                "security_analysis."
                                "authentication_analysis.dmarc"
                            ),
                            context=(
                                f"DMARC result: "
                                f"{dmarc_result}"
                            ),
                        )
                    )

                elif "pass" in dmarc_text:

                    signals.append(
                        Signal(
                            category="authentication",
                            indicator="dmarc_pass",
                            source=(
                                "security_analysis."
                                "authentication_analysis.dmarc"
                            ),
                            context=(
                                f"DMARC result: "
                                f"{dmarc_result}"
                            ),
                        )
                    )

            # ----------------------------------------------------
            # DNS
            # SecurityAnalysisModel.dns contains:
            #
            # dns_report
            # reverse_dns_report
            #
            # Preserve these as observable signals when reports
            # actually exist.
            # ----------------------------------------------------

            dns = authentication.get(
                "dns",
                {},
            )

            if isinstance(dns, dict):

                dns_reports = dns.get(
                    "dns_report",
                    [],
                )

                if isinstance(
                    dns_reports,
                    list,
                ) and dns_reports:

                    signals.append(
                        Signal(
                            category="authentication",
                            indicator="dns_analysis_available",
                            source=(
                                "security_analysis."
                                "authentication_analysis.dns."
                                "dns_report"
                            ),
                            context=(
                                f"{len(dns_reports)} DNS "
                                f"domain report(s) supplied"
                            ),
                        )
                    )

                reverse_dns_reports = dns.get(
                    "reverse_dns_report",
                    [],
                )

                if isinstance(
                    reverse_dns_reports,
                    list,
                ) and reverse_dns_reports:

                    signals.append(
                        Signal(
                            category="authentication",
                            indicator="reverse_dns_analysis_available",
                            source=(
                                "security_analysis."
                                "authentication_analysis.dns."
                                "reverse_dns_report"
                            ),
                            context=(
                                f"{len(reverse_dns_reports)} "
                                f"reverse-DNS report(s) supplied"
                            ),
                        )
                    )

        # --------------------------------------------------------
        # Sender analysis
        # --------------------------------------------------------

        sender_analysis = sec.get(
            "sender_analysis",
            {},
        )

        if isinstance(
            sender_analysis,
            dict,
        ):

            sender_findings = sender_analysis.get(
                "findings",
                [],
            )

            if isinstance(
                sender_findings,
                list,
            ):

                for finding in sender_findings:

                    signals.append(
                        Signal(
                            category="sender",
                            indicator="sender_finding",
                            source=(
                                "security_analysis."
                                "sender_analysis.findings"
                            ),
                        context=str(finding),
                        )
                    )

        # --------------------------------------------------------
        # Header analysis
        # --------------------------------------------------------

        header_analysis = sec.get(
            "header_analysis",
            {},
        )

        if isinstance(
            header_analysis,
            dict,
        ):

            header_findings = header_analysis.get(
                "findings",
                [],
            )

            if isinstance(
                header_findings,
                list,
            ):

                for finding in header_findings:

                    signals.append(
                        Signal(
                            category="header",
                            indicator="header_finding",
                            source=(
                                "security_analysis."
                                "header_analysis.findings"
                            ),
                            context=str(finding),
                        )
                    )

        # --------------------------------------------------------
        # Phishing analysis
        # SecurityAnalysisModel.phishing_analysis is list[str]
        # --------------------------------------------------------

        phishing_analysis = sec.get(
            "phishing_analysis",
            [],
        )

        if isinstance(
            phishing_analysis,
            list,
        ):

            for finding in phishing_analysis:

                signals.append(
                    Signal(
                        category="phishing",
                        indicator="phishing_analysis",
                        source=(
                            "security_analysis."
                            "phishing_analysis"
                        ),
                        context=str(finding),
                    )
                )

    # ============================================================
    # THREAT ANALYSIS
    # ============================================================

    ti = normalized.threat_intelligence

    if isinstance(ti, dict):

        # --------------------------------------------------------
        # IP analysis
        # --------------------------------------------------------

        ip_analysis = ti.get(
            "ip_analysis",
            {},
        )

        if isinstance(
            ip_analysis,
            dict,
        ):

            originating_ip = ip_analysis.get(
                "originating_ip"
            )

            if originating_ip:

                signals.append(
                    Signal(
                        category="threat_intelligence",
                        indicator="originating_ip_analyzed",
                        source=(
                            "threat_intelligence."
                            "ip_analysis.originating_ip"
                        ),
                        context=(
                            f"Originating IP: "
                            f"{originating_ip}"
                        ),
                    )
                )

            abuse_reports = ip_analysis.get(
                "iocs_ip_abuseIPDB",
                [],
            )

            if isinstance(
                abuse_reports,
                list,
            ) and abuse_reports:

                signals.append(
                    Signal(
                        category="threat_intelligence",
                        indicator="ip_abuseipdb_report",
                        source=(
                            "threat_intelligence."
                            "ip_analysis.iocs_ip_abuseIPDB"
                        ),
                        context=(
                            f"{len(abuse_reports)} "
                            f"AbuseIPDB report(s) supplied"
                        ),
                    )
                )

            otx_reports = ip_analysis.get(
                "iocs_ip_alienvaultOTX",
                [],
            )

            if isinstance(
                otx_reports,
                list,
            ) and otx_reports:

                signals.append(
                    Signal(
                        category="threat_intelligence",
                        indicator="ip_alienvault_otx_report",
                        source=(
                            "threat_intelligence."
                            "ip_analysis.iocs_ip_alienvaultOTX"
                        ),
                        context=(
                            f"{len(otx_reports)} "
                            f"AlienVault OTX report(s) supplied"
                        ),
                    )
                )

            originating_abuse_reports = ip_analysis.get(
                "originating_ip_abuseIPDB",
                [],
            )

            if isinstance(
                originating_abuse_reports,
                list,
            ) and originating_abuse_reports:

                signals.append(
                    Signal(
                        category="threat_intelligence",
                        indicator="originating_ip_abuseipdb_report",
                        source=(
                            "threat_intelligence."
                            "ip_analysis.originating_ip_abuseIPDB"
                        ),
                        context=(
                            f"{len(originating_abuse_reports)} "
                            f"originating-IP AbuseIPDB report(s) supplied"
                        ),
                    )
                )

            originating_otx_reports = ip_analysis.get(
                "originating_ip_alienvaultOTX",
                [],
            )

            if isinstance(
                originating_otx_reports,
                list,
            ) and originating_otx_reports:

                signals.append(
                    Signal(
                        category="threat_intelligence",
                        indicator="originating_ip_alienvault_otx_report",
                        source=(
                            "threat_intelligence."
                            "ip_analysis.originating_ip_alienvaultOTX"
                        ),
                        context=(
                            f"{len(originating_otx_reports)} "
                            f"originating-IP OTX report(s) supplied"
                        ),
                    )
                )

        # --------------------------------------------------------
        # VirusTotal URL analysis
        # --------------------------------------------------------

        url_analysis = ti.get(
            "url_analysis",
            {},
        )

        if isinstance(
            url_analysis,
            dict,
        ):

            url_reports = url_analysis.get(
                "virusTotal_report",
                [],
            )

            if isinstance(
                url_reports,
                list,
            ) and url_reports:

                # Interpret VT semantics: report existence alone is not
                # malicious. Only explicit malicious/suspicious counts count
                # as phishing evidence. Clean reports produce no phishing
                # indicator; they are preserved as raw threat_intelligence
                # evidence for grounding/prompt but do not inflate phishing.
                vt_malicious = 0
                vt_suspicious = 0
                vt_harmless = 0
                for _r in url_reports:
                    if not isinstance(_r, dict):
                        continue
                    _stats = _r.get("last_analysis_stats")
                    if not isinstance(_stats, dict):
                        _stats = _r.get("analysis_stats")
                    if not isinstance(_stats, dict):
                        _stats = _r
                    try:
                        vt_malicious += max(0, int(_stats.get("malicious", 0)))
                    except (TypeError, ValueError):
                        pass
                    try:
                        vt_suspicious += max(0, int(_stats.get("suspicious", 0)))
                    except (TypeError, ValueError):
                        pass
                    try:
                        vt_harmless += max(0, int(_stats.get("harmless", 0)))
                    except (TypeError, ValueError):
                        pass
                if vt_malicious > 0:
                    signals.append(
                        Signal(
                            category="phishing",
                            indicator="url_virustotal_report",
                            source=(
                                "threat_intelligence."
                                "url_analysis.virusTotal_report"
                            ),
                            context=(
                                f"VirusTotal URL reports indicate "
                                f"{vt_malicious} malicious detection(s) "
                                f"across {len(url_reports)} report(s)"
                            ),
                        )
                    )
                elif vt_suspicious > 0:
                    signals.append(
                        Signal(
                            category="phishing",
                            indicator="url_virustotal_report",
                            source=(
                                "threat_intelligence."
                                "url_analysis.virusTotal_report"
                            ),
                            context=(
                                f"VirusTotal URL reports indicate "
                                f"{vt_suspicious} suspicious detection(s) "
                                f"across {len(url_reports)} report(s)"
                            ),
                        )
                    )
                else:
                    # Clean or undetected only: no phishing signal.
                    # Preserve as neutral evidence; do not inflate phishing.
                    # Still emit a threat-intelligence observation that is
                    # intentionally NOT in the phishing bucket so downstream
                    # calibration can treat it as counter/no evidence.
                    signals.append(
                        Signal(
                            category="threat_intelligence",
                            indicator="url_virustotal_clean",
                            source=(
                                "threat_intelligence."
                                "url_analysis.virusTotal_report"
                            ),
                            context=(
                                f"{len(url_reports)} VirusTotal URL report(s) "
                                f"supplied with no malicious/suspicious "
                                f"detections (harmless={vt_harmless})"
                            ),
                        )
                    )

        # --------------------------------------------------------
        # VirusTotal domain analysis
        # --------------------------------------------------------

        domain_analysis = ti.get(
            "domain_analysis",
            {},
        )

        if isinstance(
            domain_analysis,
            dict,
        ):

            domain_reports = domain_analysis.get(
                "virusTotal_report",
                [],
            )

            if isinstance(
                domain_reports,
                list,
            ) and domain_reports:

                vt_malicious = 0
                vt_suspicious = 0
                vt_harmless = 0
                for _r in domain_reports:
                    if not isinstance(_r, dict):
                        continue
                    _stats = _r.get("last_analysis_stats")
                    if not isinstance(_stats, dict):
                        _stats = _r.get("analysis_stats")
                    if not isinstance(_stats, dict):
                        _stats = _r
                    try:
                        vt_malicious += max(0, int(_stats.get("malicious", 0)))
                    except (TypeError, ValueError):
                        pass
                    try:
                        vt_suspicious += max(0, int(_stats.get("suspicious", 0)))
                    except (TypeError, ValueError):
                        pass
                    try:
                        vt_harmless += max(0, int(_stats.get("harmless", 0)))
                    except (TypeError, ValueError):
                        pass
                if vt_malicious > 0:
                    signals.append(
                        Signal(
                            category="phishing",
                            indicator="domain_virustotal_report",
                            source=(
                                "threat_intelligence."
                                "domain_analysis.virusTotal_report"
                            ),
                            context=(
                                f"VirusTotal domain reports indicate "
                                f"{vt_malicious} malicious detection(s) "
                                f"across {len(domain_reports)} report(s)"
                            ),
                        )
                    )
                elif vt_suspicious > 0:
                    signals.append(
                        Signal(
                            category="phishing",
                            indicator="domain_virustotal_report",
                            source=(
                                "threat_intelligence."
                                "domain_analysis.virusTotal_report"
                            ),
                            context=(
                                f"VirusTotal domain reports indicate "
                                f"{vt_suspicious} suspicious detection(s) "
                                f"across {len(domain_reports)} report(s)"
                            ),
                        )
                    )
                else:
                    signals.append(
                        Signal(
                            category="threat_intelligence",
                            indicator="domain_virustotal_clean",
                            source=(
                                "threat_intelligence."
                                "domain_analysis.virusTotal_report"
                            ),
                            context=(
                                f"{len(domain_reports)} VirusTotal domain report(s) "
                                f"supplied with no malicious/suspicious "
                                f"detections (harmless={vt_harmless})"
                            ),
                        )
                    )

        # --------------------------------------------------------
        # VirusTotal attachment analysis
        # --------------------------------------------------------

        attachment_analysis = ti.get(
            "attachment_analysis",
            {},
        )

        if isinstance(
            attachment_analysis,
            dict,
        ):

            attachment_reports = attachment_analysis.get(
                "virusTotal_report",
                [],
            )

            if isinstance(
                attachment_reports,
                list,
            ) and attachment_reports:

                signals.append(
                    Signal(
                        category="threat_intelligence",
                        indicator="attachment_virustotal_report",
                        source=(
                            "threat_intelligence."
                            "attachment_analysis."
                            "virusTotal_report"
                        ),
                        context=(
                            f"{len(attachment_reports)} "
                            f"VirusTotal attachment report(s) supplied"
                        ),
                    )
                )

    return signals


# ---------------------------------------------------------------------------
# Attachment / forensic evidence understanding
#
# The backend supplies arbitrarily nested forensic JSON whose schema is not
# fixed and may gain fields at any time. Everything below is deterministic
# evidence extraction: a signal is emitted only when a supplied field
# explicitly states the finding. Nothing is looked up externally, nothing is
# inferred from weak context, and no score, probability or verdict is produced.
# ---------------------------------------------------------------------------

# Path prefix used when reporting where forensic evidence was found.
_FORENSIC_ROOT = "forensic_evidence"

# Recursion backstop only. The input guard already caps nesting at 15 levels;
# this exists purely so a hand-built pathological structure cannot exhaust the
# stack. It is far above any depth real evidence can reach.
_MAX_TRAVERSAL_DEPTH = 200

# Context strings are bounded so one huge evidence value cannot dominate output.
_MAX_CONTEXT_LENGTH = 300

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Hex digest lengths for the hash algorithms a forensic backend may report:
# MD5 (32), SHA-1 (40), SHA-224 (56), SHA-256 (64), SHA-384 (96), SHA-512 (128).
_HASH_HEX_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})

# Accepted spellings for explicit backend findings, in canonical form (see
# _canon_key). Tuples rather than sets so iteration order is stable across
# processes and the extracted signals are reproducible.
_MALWARE_FLAG_KEYS = ("malwaredetected", "malwarefound", "ismalware", "containsmalware")
_MALICIOUS_FLAG_KEYS = ("malicious", "ismalicious")
_KNOWN_MALICIOUS_FLAG_KEYS = ("knownmalicious", "knownbad", "hashknownmalicious", "blacklisted")
_SUSPICIOUS_FLAG_KEYS = ("suspicious", "issuspicious")

_REPUTATION_KEYS = ("reputation", "hashreputation", "filereputation", "threatreputation")
_MALICIOUS_REPUTATIONS = frozenset({"malicious", "known_malicious", "known malicious", "bad", "known_bad", "known bad"})
_SUSPICIOUS_REPUTATIONS = frozenset({"suspicious", "poor"})

# A non-empty list under one of these keys is an explicit threat-intelligence
# result, whatever the surrounding schema looks like.
_TI_MATCH_LIST_KEYS = ("findings", "matches", "detections", "hits", "threatmatches", "iocmatches")

_ABUSE_CONFIDENCE_KEYS = ("abuseconfidencescore", "abuseconfidence")

# AbuseIPDB reports 0-100, where 100 is maximum confidence of abuse. 75 is the
# conventional "high confidence" cutoff. Below it, no signal is emitted at all:
# a mid-range score is not a finding.
_ABUSE_CONFIDENCE_HIGH_THRESHOLD = 75

_FILENAME_KEYS = ("filename", "originalfilename", "originalname", "displayname", "name")

_HASH_KEY_HINTS = ("sha256", "sha512", "sha384", "sha1", "md5", "filehash", "hash", "digest")

# Directly executable / script file types. Used only for a weak
# suspicious_file_type observation, never for a maliciousness claim. Archive
# formats (.zip, .rar, .7z) are deliberately absent: they are far too common to
# be worth observing, and a malicious payload inside one is caught by walking
# into the embedded-file evidence instead.
_SUSPICIOUS_EXTENSIONS = frozenset({
    "application", "bat", "cmd", "com", "cpl", "dll", "exe", "gadget", "hta",
    "inf", "jar", "js", "jse", "lnk", "msi", "msp", "mst", "pif", "ps1",
    "psm1", "reg", "scf", "scr", "sct", "shb", "shs", "vbe", "vbs", "ws",
    "wsf", "wsh",
})


def _canon_key(key: Any) -> str:
    """
    Canonical form of an evidence key, so camelCase and snake_case agree.

    ``abuseConfidenceScore`` and ``abuse_confidence_score`` both canonicalize to
    ``abuseconfidencescore``. Only used for lookups; the original key spelling
    is always what gets reported in a signal's provenance.
    """
    if not isinstance(key, str):
        return ""
    return key.lower().replace("_", "").replace("-", "").replace(" ", "")


def _canonical_items(node: dict[str, Any]) -> dict[str, tuple[str, Any]]:
    """Map canonical key -> (original key, value) for a single evidence object."""
    return {_canon_key(k): (k, v) for k, v in node.items() if isinstance(k, str)}


def _is_affirmative(value: Any) -> bool:
    """
    True only for an explicit affirmative supplied by the backend.

    Accepts the boolean ``True`` and the strings "true"/"yes". Integers are
    deliberately rejected: ``1`` is too ambiguous to treat as a finding, and
    ``isinstance(True, int)`` would otherwise let counts through.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes")
    return False


def _as_number(value: Any) -> float | None:
    """Coerce an explicitly numeric evidence value. Booleans are not numbers here."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _looks_like_hash(value: Any) -> bool:
    """Check whether a value has the shape of a hex digest."""
    if not isinstance(value, str):
        return False
    if len(value) not in _HASH_HEX_LENGTHS:
        return False
    return all(c in _HEX_DIGITS for c in value)


def _find_hash(node: dict[str, Any]) -> tuple[str, Any] | None:
    """
    Locate a hash value in one evidence object, for provenance/context only.

    A hash is never itself a reason to emit a signal: a SHA-256 is an identifier
    and a fingerprint, not a reputation. This exists purely to enrich the context
    of signals that some other explicit finding already justified, and to
    distinguish a hash-scoped finding from a generic one.
    """
    items = _canonical_items(node)
    for hint in _HASH_KEY_HINTS:
        entry = items.get(hint)
        if entry is not None and _looks_like_hash(entry[1]):
            return entry
    for key, value in node.items():
        if isinstance(key, str) and _looks_like_hash(value):
            return key, value
    return None


def _find_filename(node: dict[str, Any]) -> tuple[str, Any] | None:
    """Locate a filename in one evidence object, most specific key first."""
    items = _canonical_items(node)
    for hint in _FILENAME_KEYS:
        entry = items.get(hint)
        if entry is not None and isinstance(entry[1], str) and entry[1].strip():
            return entry
    return None


def _file_extension(filename: str) -> str:
    """
    Trailing extension of a filename, lowercased, without the dot.

    Trailing dots and whitespace are trimmed first so "payload.exe." and
    "payload.exe " resolve to "exe". A double extension such as
    "invoice.pdf.exe" resolves to the final, effective one.
    """
    trimmed = filename.strip().rstrip(". ")
    if "." not in trimmed:
        return ""
    return trimmed.rsplit(".", 1)[-1].strip().lower()


def _clip(text: str) -> str:
    """Bound a context string to a readable length."""
    if len(text) <= _MAX_CONTEXT_LENGTH:
        return text
    return text[:_MAX_CONTEXT_LENGTH] + "..."


def _describe(file_entry: tuple[str, Any] | None, hash_entry: tuple[str, Any] | None) -> str:
    """Short factual descriptor of what an evidence object is about."""
    parts = []
    if file_entry is not None:
        parts.append(f"{file_entry[0]}={file_entry[1]}")
    if hash_entry is not None:
        parts.append(f"{hash_entry[0]}={hash_entry[1]}")
    return ", ".join(parts)


def _walk_objects(node: Any, path: str, depth: int = 0):
    """
    Yield every ``(path, object)`` pair reachable in nested forensic evidence.

    Traverses dicts, lists, dicts inside lists and lists inside dicts, to any
    depth, without assuming a fixed schema. Nothing is flattened: each object is
    reported together with the dotted/indexed path it was found at, so parent
    and child relationships stay recoverable and a signal can point back to
    exactly where its evidence came from. Scalars are not yielded; they are read
    from their containing object.
    """
    if depth > _MAX_TRAVERSAL_DEPTH:
        return
    if isinstance(node, dict):
        yield path, node
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _walk_objects(value, child, depth + 1)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _walk_objects(item, f"{path}[{index}]", depth + 1)


def _malware_signals(path: str, items: dict[str, tuple[str, Any]], descriptor: str) -> list[Signal]:
    """Explicit malware finding, e.g. ``{"malware_detected": true}``."""
    for canon in _MALWARE_FLAG_KEYS:
        entry = items.get(canon)
        if entry is not None and _is_affirmative(entry[1]):
            detail = f"{entry[0]}={entry[1]!r}"
            if descriptor:
                detail = f"{detail} for {descriptor}"
            return [Signal(
                category="forensic",
                indicator="malware_detected",
                source=f"{path}.{entry[0]}",
                context=_clip(f"Backend explicitly reported {detail}"),
            )]
    return []


def _malicious_signals(path: str, items: dict[str, tuple[str, Any]], descriptor: str) -> list[Signal]:
    """Explicit maliciousness finding on a file/attachment, e.g. ``{"malicious": true}``."""
    for canon in _MALICIOUS_FLAG_KEYS:
        entry = items.get(canon)
        if entry is not None and _is_affirmative(entry[1]):
            detail = f"{entry[0]}={entry[1]!r}"
            if descriptor:
                detail = f"{detail} for {descriptor}"
            return [Signal(
                category="forensic",
                indicator="malicious_attachment",
                source=f"{path}.{entry[0]}",
                context=_clip(f"Backend explicitly reported {detail}"),
            )]
    return []


def _known_malicious_hash_signals(
    path: str,
    items: dict[str, tuple[str, Any]],
    hash_entry: tuple[str, Any] | None,
    descriptor: str,
) -> list[Signal]:
    """
    Explicit known-bad finding, e.g. ``{"known_malicious": true}``.

    Reported as ``known_malicious_hash`` only when a hash is present in the same
    object, so the signal is never named after evidence that is not there.
    Otherwise it degrades to a generic threat-intelligence match.
    """
    for canon in _KNOWN_MALICIOUS_FLAG_KEYS:
        entry = items.get(canon)
        if entry is None or not _is_affirmative(entry[1]):
            continue
        detail = f"{entry[0]}={entry[1]!r}"
        if hash_entry is not None:
            indicator = "known_malicious_hash"
            detail = f"{detail} for {hash_entry[0]}={hash_entry[1]}"
        else:
            indicator = "attachment_threat_intelligence_match"
            if descriptor:
                detail = f"{detail} for {descriptor}"
        return [Signal(
            category="forensic",
            indicator=indicator,
            source=f"{path}.{entry[0]}",
            context=_clip(f"Backend explicitly reported {detail}"),
        )]
    return []


def _reputation_signals(
    path: str,
    items: dict[str, tuple[str, Any]],
    hash_entry: tuple[str, Any] | None,
    descriptor: str,
) -> list[Signal]:
    """
    Explicit reputation result, e.g. ``{"reputation": "malicious"}``.

    Only the stated reputation is used. An unrecognised value produces nothing
    rather than a guess.
    """
    for canon in _REPUTATION_KEYS:
        entry = items.get(canon)
        if entry is None or not isinstance(entry[1], str):
            continue
        value = entry[1].strip().lower()
        if value in _MALICIOUS_REPUTATIONS:
            indicator = "known_malicious_hash" if hash_entry is not None else "attachment_threat_intelligence_match"
        elif value in _SUSPICIOUS_REPUTATIONS:
            indicator = "suspicious_attachment"
        else:
            continue
        detail = f"{entry[0]}={entry[1]!r}"
        target = _describe(None, hash_entry) if indicator == "known_malicious_hash" else descriptor
        if target:
            detail = f"{detail} for {target}"
        return [Signal(
            category="forensic",
            indicator=indicator,
            source=f"{path}.{entry[0]}",
            context=_clip(f"Backend explicitly reported {detail}"),
        )]
    return []


def _suspicious_flag_signals(path: str, items: dict[str, tuple[str, Any]], descriptor: str) -> list[Signal]:
    """Explicit suspicion finding, e.g. ``{"suspicious": true}``."""
    for canon in _SUSPICIOUS_FLAG_KEYS:
        entry = items.get(canon)
        if entry is not None and _is_affirmative(entry[1]):
            detail = f"{entry[0]}={entry[1]!r}"
            if descriptor:
                detail = f"{detail} for {descriptor}"
            return [Signal(
                category="forensic",
                indicator="suspicious_attachment",
                source=f"{path}.{entry[0]}",
                context=_clip(f"Backend explicitly reported {detail}"),
            )]
    return []


def _threat_intel_match_signals(path: str, items: dict[str, tuple[str, Any]]) -> list[Signal]:
    """
    A non-empty findings/matches/detections list is an explicit intelligence result.

    Schema-agnostic on purpose: the list may sit under ``threat_intelligence``,
    ``ip_intelligence`` or a field the backend has not invented yet.
    """
    signals = []
    for canon in _TI_MATCH_LIST_KEYS:
        entry = items.get(canon)
        if entry is None or not isinstance(entry[1], list) or not entry[1]:
            continue
        signals.append(Signal(
            category="forensic",
            indicator="attachment_threat_intelligence_match",
            source=f"{path}.{entry[0]}",
            context=_clip(f"Backend supplied {len(entry[1])} item(s) under '{entry[0]}': {entry[1]}"),
        ))
    return signals


def _abuse_confidence_signals(path: str, items: dict[str, tuple[str, Any]]) -> list[Signal]:
    """
    High abuse-confidence score from IP intelligence.

    Only the confidence score itself is used. Country, country code, ISP, usage
    type, Tor status and report counts are preserved as evidence elsewhere but
    are never treated as indicators: hosting location and provider are not
    proof of anything.
    """
    for canon in _ABUSE_CONFIDENCE_KEYS:
        entry = items.get(canon)
        if entry is None:
            continue
        score = _as_number(entry[1])
        if score is None or score < _ABUSE_CONFIDENCE_HIGH_THRESHOLD:
            continue
        ip_entry = items.get("ipaddress") or items.get("ip")
        target = f" for {ip_entry[0]}={ip_entry[1]}" if ip_entry is not None else ""
        return [Signal(
            category="forensic",
            indicator="high_abuse_confidence",
            source=f"{path}.{entry[0]}",
            context=_clip(
                f"Backend reported {entry[0]}={entry[1]}{target}, at or above the "
                f"{_ABUSE_CONFIDENCE_HIGH_THRESHOLD} high-confidence threshold"
            ),
        )]
    return []


def _suspicious_file_type_signals(path: str, file_entry: tuple[str, Any] | None) -> list[Signal]:
    """
    Weak observation that a filename carries an executable/script extension.

    An extension is metadata, not analysis. This never yields
    ``malicious_attachment`` or ``malware_detected``, and the context says so
    explicitly so no downstream consumer mistakes it for a conclusion.
    """
    if file_entry is None:
        return []
    key, filename = file_entry
    extension = _file_extension(filename)
    if extension not in _SUSPICIOUS_EXTENSIONS:
        return []
    return [Signal(
        category="forensic",
        indicator="suspicious_file_type",
        source=f"{path}.{key}",
        context=_clip(
            f"{key}={filename} carries the executable/script extension '.{extension}'. "
            f"Weak observation only: a file extension is not evidence of malware."
        ),
    )]


def _signals_for_object(path: str, node: dict[str, Any]) -> list[Signal]:
    """Run every detector against a single evidence object, in a fixed order."""
    items = _canonical_items(node)
    hash_entry = _find_hash(node)
    file_entry = _find_filename(node)
    descriptor = _describe(file_entry, hash_entry)

    signals = []
    signals.extend(_malware_signals(path, items, descriptor))
    signals.extend(_malicious_signals(path, items, descriptor))
    signals.extend(_known_malicious_hash_signals(path, items, hash_entry, descriptor))
    signals.extend(_reputation_signals(path, items, hash_entry, descriptor))
    signals.extend(_suspicious_flag_signals(path, items, descriptor))
    signals.extend(_threat_intel_match_signals(path, items))
    signals.extend(_abuse_confidence_signals(path, items))
    signals.extend(_suspicious_file_type_signals(path, file_entry))
    return signals


def extract_forensic_signals(
    forensic_evidence: dict[str, Any],
    root: str = _FORENSIC_ROOT,
) -> list[Signal]:
    """
    Extract deterministic signals from nested attachment/forensic evidence.

    Walks the whole structure - dicts, lists, dicts in lists, lists in dicts, at
    any depth - and emits a signal only where a field explicitly states a
    finding. Every signal carries the evidence path that justified it.

    What deliberately produces no signal:

    - A ``sha256`` or other hash on its own. It is an identifier, not a verdict.
    - A country, country code, ISP, usage type or hosting provider.
    - An abuse-confidence score below the high-confidence threshold.
    - A filename alone, beyond a weak ``suspicious_file_type`` observation.
    - Any unknown field. Unrecognised evidence is skipped, never fatal.

    Attacker-controlled text (filenames, extracted strings, nested fields) is
    carried through as evidence in signal context. It is never executed and
    never interpreted as an instruction to this application.

    Returns an empty list for empty, missing or non-dict evidence.
    """
    if not isinstance(forensic_evidence, dict) or not forensic_evidence:
        return []

    signals = []
    for path, obj in _walk_objects(forensic_evidence, root):
        signals.extend(_signals_for_object(path, obj))
    return signals


def analyze_email(normalized: NormalizedEvidence) -> UnderstandingResult:
    """
    Analyze normalized evidence and extract observable signals.

    This is a deterministic, rule-based extraction - no ML, no LLM calls.
    Output is structured signals for downstream reasoning.

    Covers the six email signal categories plus attachment/forensic
    observations drawn from the nested forensic evidence payload. No risk score,
    probability, verdict or final classification is produced here.
    """
    result = UnderstandingResult()

    # Use normalized text for consistent matching
    subject = normalized.email.normalized_subject
    body = normalized.email.normalized_body
    sender = normalized.email.sender
    recipient = normalized.email.recipient

    # Extract urgency signals
    result.urgency.extend(_find_patterns(subject, _URGENCY_PATTERNS, "urgency"))
    result.urgency.extend(_find_patterns(body, _URGENCY_PATTERNS, "urgency"))

    # Extract credential request signals
    result.credential_request.extend(_find_patterns(subject, _CREDENTIAL_PATTERNS, "credential"))
    result.credential_request.extend(_find_patterns(body, _CREDENTIAL_PATTERNS, "credential"))

    # Extract financial request signals
    result.financial_request.extend(_find_patterns(subject, _FINANCIAL_PATTERNS, "financial"))
    result.financial_request.extend(_find_patterns(body, _FINANCIAL_PATTERNS, "financial"))

    # Extract social engineering signals
    result.social_engineering.extend(_find_patterns(subject, _SOCIAL_ENGINEERING_PATTERNS, "social_engineering"))
    result.social_engineering.extend(_find_patterns(body, _SOCIAL_ENGINEERING_PATTERNS, "social_engineering"))

    # Extract phishing indicator signals
    result.phishing_indicators.extend(_find_patterns(subject, _PHISHING_PATTERNS, "phishing"))
    result.phishing_indicators.extend(_find_patterns(body, _PHISHING_PATTERNS, "phishing"))

    # Extract BEC indicator signals
    result.bec_indicators.extend(_find_patterns(subject, _BEC_PATTERNS, "bec"))
    result.bec_indicators.extend(_find_patterns(body, _BEC_PATTERNS, "bec"))

    # Add domain/structural signals from security analysis and threat intel
    domain_signals = _extract_domain_signals(normalized)
    for sig in domain_signals:
        if sig.category == "phishing":
            result.phishing_indicators.append(sig)
        elif sig.category == "bec":
            result.bec_indicators.append(sig)

    # Check sender/recipient patterns
    sender_lower = sender.lower()
    recipient_lower = recipient.lower()

    # Executive sender name but suspicious domain
    exec_names = ["ceo", "cfo", "president", "director", "founder"]
    for exec_name in exec_names:
        if exec_name in sender_lower:
            result.bec_indicators.append(Signal(
                category="bec",
                indicator="executive_name_in_sender",
                source="sender",
                context=f"Sender contains '{exec_name}': {sender}",
            ))
            result.social_engineering.append(Signal(
                category="social_engineering",
                indicator="executive_impersonation_attempt",
                source="sender",
                context=f"Sender contains executive title: {sender}",
            ))

    # Attachment / forensic evidence signals. Purely additive: everything above
    # is untouched, and this reads only the forensic payload. Absent or empty
    # forensic evidence simply yields no signals.
    result.forensic_indicators.extend(
        extract_forensic_signals(getattr(normalized, "normalized_forensic_evidence", {}))
    )

    return result