"""
Adapter layer — Subhom+Saikat FINAL payload -> internal Logic Engine models.

Architecture:
    HTTP Request (Subhom aggregated JSON)
        ↓
    API Model (LogicRequest)  — case_id, email, security_analysis, threat_intelligence, forensic_evidence, ai_assessment, grounding...
        ↓
    adapters.py  (this file) — the ONLY place that understands Subhom's raw JSON
        ↓
    AnalysisInput (internal): case_id, email, iocs, security_analysis, threat_intelligence, ai_assessment
        ↓
    LogicEngine

This file is the boundary. Rules/scoring/correlation/verdict never parse external payloads.

Final Subhom structure (ACTUAL):
    security_analysis:
        authentication_analysis: { spf: LIST, dkim: BOOLEAN, dmarc: OBJECT, dns: OBJECT }
        sender_analysis: { from: OBJECT, reply_to: OBJECT, return_path: OBJECT, findings: LIST }
        header_analysis: { received: LIST, authentication_results: LIST, dkim_signature: STRING, findings: LIST }
        phishing_analysis: LIST[ {indicator, evidence, severity} ]

    threat_intelligence:
        ip_analysis: { abuseIPDB_report: LIST, alienvaultOTX_report: LIST }
        url_analysis: { virusTotal_report: LIST }
        domain_analysis: { virusTotal_report: LIST }
        attachment_analysis: { virusTotal_report: LIST }

    email:
        sender, recipient, subject, date, message_id, iocs: {ips, domains, urls, hashes}

    ai_assessment: { phishing_probability, bec_probability, ... }
    grounding, forensic_evidence, processing_time_seconds, model_info

Backward compatibility:
    Also handles prior simplified schemas (spf as object, threat_analysis as flat lists, etc.)
    so unit tests remain deterministic without file I/O.
"""

from __future__ import annotations

from typing import Any

from logic.models import (
    AIAssessment,
    DMARCResult,
    DKIMResult,
    EmailMetadata,
    HeaderAnalysis,
    IOCData,
    SecurityAnalysis,
    SenderIdentity,
    SPFResult,
    ThreatIntelligence,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _extract_domain(email_str: str | None) -> str | None:
    if not email_str or "@" not in email_str:
        return None
    return email_str.rsplit("@", 1)[-1].lower().strip(">").strip()


def _extract_url_domain(url: str | None) -> str | None:
    if not isinstance(url, str) or not url:
        return None
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if '://' in url else f'http://{url}')
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SecurityAnalysis adapter — FINAL payload
# ---------------------------------------------------------------------------

def adapt_security_analysis(raw: dict[str, Any] | None) -> SecurityAnalysis:
    """
    Convert the authoritative backend security_analysis payload into the
    existing internal SecurityAnalysis model.

    External field names are taken directly from logic_models.py.
    No legacy/alternate field names are used here.
    """
    if not raw or not isinstance(raw, dict):
        return SecurityAnalysis()

    auth = _safe_dict(raw.get("authentication_analysis"))
    sender = _safe_dict(raw.get("sender_analysis"))
    header = _safe_dict(raw.get("header_analysis"))
    phishing = _safe_list(raw.get("phishing_analysis"))

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    dns_obj = _safe_dict(auth.get("dns"))
    dns_reports = _safe_list(dns_obj.get("dns_report"))

    dns_domain: str | None = None
    dns_spf_record: str | None = None

    for report in dns_reports:
        if not isinstance(report, dict):
            continue

        domain = report.get("domain")
        if not dns_domain and isinstance(domain, str):
            dns_domain = domain

        records = report.get("records")
        if not isinstance(records, dict):
            continue

        txt_records = _safe_list(records.get("TXT"))

        if not dns_spf_record:
            for txt in txt_records:
                if isinstance(txt, str) and "v=spf1" in txt.lower():
                    dns_spf_record = txt
                    break

    # ------------------------------------------------------------------
    # SPF
    #
    # Authoritative type from logic_models.py:
    #     list[tuple[str, str]]
    # ------------------------------------------------------------------

    spf_list = _safe_list(auth.get("spf"))

    spf_result = "unknown"
    spf_domain = dns_domain
    spf_record = dns_spf_record

    if spf_list:
        chosen: tuple[Any, ...] | None = None

        valid_results = {
            "pass",
            "fail",
            "softfail",
            "neutral",
            "none",
        }

        for entry in spf_list:
            if not isinstance(entry, (tuple, list)):
                continue

            if not entry:
                continue

            result_value = str(entry[0]).lower()

            if result_value in valid_results:
                chosen = tuple(entry)
                break

        if chosen is None:
            for entry in spf_list:
                if isinstance(entry, (tuple, list)) and entry:
                    chosen = tuple(entry)
                    break

        if chosen:
            raw_result = str(chosen[0]).lower()

            if raw_result in valid_results:
                spf_result = raw_result
            elif "fail" in raw_result:
                spf_result = "fail"
            elif "pass" in raw_result:
                spf_result = "pass"

            if len(chosen) >= 2 and chosen[1] is not None:
                spf_record = str(chosen[1])

    spf = SPFResult(
        result=spf_result,
        domain=spf_domain,
        record=spf_record,
    )

    # ------------------------------------------------------------------
    # DKIM
    #
    # Authoritative type from logic_models.py:
    #     bool
    # ------------------------------------------------------------------

    dkim_raw = auth.get("dkim")

    if isinstance(dkim_raw, bool):
        dkim_result = "pass" if dkim_raw else "fail"
    else:
        dkim_result = "unknown"

    dkim_domain = None
    dkim_selector = None

    header_dkim_sig = header.get("dkim_signature")

    if isinstance(header_dkim_sig, str) and header_dkim_sig:
        import re

        domain_match = re.search(
            r"d\s*=\s*([^;\s]+)",
            header_dkim_sig,
        )

        if domain_match:
            dkim_domain = domain_match.group(1).strip()

        selector_match = re.search(
            r"s\s*=\s*([^;\s]+)",
            header_dkim_sig,
        )

        if selector_match:
            dkim_selector = selector_match.group(1).strip()

    if not dkim_domain:
        dkim_domain = dns_domain

    dkim = DKIMResult(
        result=dkim_result,
        domain=dkim_domain,
        selector=dkim_selector,
    )

    # ------------------------------------------------------------------
    # DMARC
    #
    # Authentication result and DNS policy are separate concepts. A DNS
    # policy of p=none does NOT mean DMARC authentication failed.
    # ------------------------------------------------------------------

    import re

    dmarc_raw = auth.get("dmarc")
    dmarc_result = "unknown"
    dmarc_domain = dns_domain
    dmarc_policy = None
    dmarc_alignment = None

    if isinstance(dmarc_raw, dict):
        raw_result = dmarc_raw.get("result")
        if isinstance(raw_result, str) and raw_result.strip():
            dmarc_result = raw_result.strip().lower()

        if isinstance(dmarc_raw.get("domain"), str):
            dmarc_domain = dmarc_raw.get("domain")

        raw_policy = dmarc_raw.get("policy")
        if isinstance(raw_policy, str) and raw_policy.strip():
            dmarc_policy = raw_policy.strip()

        dmarc_alignment = (
            dmarc_raw.get("alignment")
            or dmarc_raw.get("explanation")
        )

        nested = dmarc_raw.get("dmarc")
        if isinstance(nested, dict):
            valid = nested.get("valid")
            if valid is True:
                dmarc_result = "pass"
            elif valid is False:
                dmarc_result = "fail"

            record = nested.get("record")
            if isinstance(record, str):
                policy_match = re.search(
                    r"(?:^|[;\s])p\s*=\s*([^;\s]+)",
                    record,
                    re.IGNORECASE,
                )
                if policy_match:
                    dmarc_policy = f"p={policy_match.group(1).lower()}"

    if dmarc_result == "unknown":
        for item in _safe_list(header.get("authentication_results")):
            if not isinstance(item, str):
                continue
            match = re.search(
                r"\bdmarc\s*=\s*(pass|fail|none|neutral)\b",
                item,
                re.IGNORECASE,
            )
            if match:
                dmarc_result = match.group(1).lower()
                break

    if dmarc_result not in {
        "pass",
        "fail",
        "none",
        "unknown",
    }:
        if "fail" in dmarc_result:
            dmarc_result = "fail"
        elif "pass" in dmarc_result:
            dmarc_result = "pass"
        else:
            dmarc_result = "unknown"

    dmarc = DMARCResult(
        result=dmarc_result,
        domain=dmarc_domain,
        policy=dmarc_policy,
        alignment=dmarc_alignment,
    )

    # ------------------------------------------------------------------
    # Sender
    #
    # Authoritative fields:
    #     from
    #     reply_to
    #     return_path
    #     findings
    # ------------------------------------------------------------------

    def _extract_email_address(
        obj: Any,
    ) -> str | None:
        if isinstance(obj, dict):
            value = obj.get("email_address")

            if isinstance(value, str) and value:
                return value

        elif isinstance(obj, str):
            return obj

        return None

    from_addr = (
        _extract_email_address(sender.get("from"))
        or "unknown@unknown"
    )

    reply_addr = _extract_email_address(
        sender.get("reply_to")
    )

    return_addr = _extract_email_address(
        sender.get("return_path")
    )

    findings_sender = _safe_list(
        sender.get("findings")
    )

    header_findings = _safe_list(
        header.get("findings")
    )

    explicit_mismatch = any(
        "mismatch" in str(f).lower()
        or "spoof" in str(f).lower()
        for f in findings_sender
    )

    explicit_header_mismatch = any(
        "mismatch" in str(f).lower()
        or "spoof" in str(f).lower()
        for f in header_findings
    )

    from_domain = _extract_domain(from_addr)

    reply_domain = (
        _extract_domain(reply_addr)
        if reply_addr
        else None
    )

    return_domain = (
        _extract_domain(return_addr)
        if return_addr
        else None
    )

    domains_present = [
        domain
        for domain in (
            from_domain,
            reply_domain,
            return_domain,
        )
        if domain
    ]

    domain_consistent = True

    if len(domains_present) >= 2:
        domain_consistent = len(set(domains_present)) == 1

    if (
        explicit_mismatch
        or explicit_header_mismatch
    ):
        domain_consistent = False

    sender_identity = None

    try:
        sender_identity = SenderIdentity(
            **{
                "from": from_addr,
                "return_path": return_addr,
                "reply_to": reply_addr,
                "domain_consistent": domain_consistent,
            }
        )
    except Exception:
        sender_identity = None

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    received = _safe_list(
        header.get("received")
    )

    ip_hops = len(received)

    relay_anomaly = False

    all_findings_text = " ".join(
        str(item)
        for item in (
            findings_sender + header_findings
        )
    ).lower()

    if any(
        keyword in all_findings_text
        for keyword in (
            "anomaly",
            "mismatch",
            "suspicious",
            "spoof",
        )
    ):
        relay_anomaly = True

    authentication_results = _safe_list(
        header.get("authentication_results")
    )

    for entry in authentication_results:
        if (
            isinstance(entry, str)
            and "fail" in entry.lower()
        ):
            relay_anomaly = True

    if ip_hops > 3:
        relay_anomaly = True

    suspicious_headers: list[str] = []

    for finding in header_findings:
        if isinstance(finding, str) and finding:
            suspicious_headers.append(finding)

    for auth_result in authentication_results:
        if isinstance(auth_result, str) and auth_result:
            suspicious_headers.append(auth_result[:200])

    for received_header in received[:5]:
        if isinstance(received_header, str) and received_header:
            suspicious_headers.append(received_header[:200])

    header_analysis = HeaderAnalysis(
        relay_anomaly=relay_anomaly,
        ip_hops=ip_hops,
        suspicious_headers=suspicious_headers[:10],
    )

    # ------------------------------------------------------------------
    # Phishing
    # ------------------------------------------------------------------

    suspicious_indicators: list[str] = []

    for item in phishing:
        if isinstance(item, str):
            suspicious_indicators.append(item)

        elif isinstance(item, dict):
            indicator = str(
                item.get("indicator", "")
            ).strip()

            evidence = str(
                item.get("evidence", "")
            ).strip()

            if indicator:
                suspicious_indicators.append(
                    indicator
                )

            elif evidence:
                suspicious_indicators.append(
                    evidence[:100]
                )

    if any(
        "spoof" in str(f).lower()
        for f in (
            findings_sender + header_findings
        )
    ):
        if "spoofing" not in suspicious_indicators:
            suspicious_indicators.append("spoofing")

    if any(
        "mismatch" in str(f).lower()
        for f in findings_sender
    ):
        if "sender_mismatch" not in suspicious_indicators:
            suspicious_indicators.append("sender_mismatch")

    return SecurityAnalysis(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        sender_identity=sender_identity,
        header_analysis=header_analysis,
        suspicious_indicators=suspicious_indicators,
    )

# ---------------------------------------------------------------------------
# ThreatIntelligence adapter — FINAL provider reports
# ---------------------------------------------------------------------------

_UNKNOWN_REPUTATION_CATEGORY = "reputation_unknown"

def adapt_threat_intelligence(
    raw: dict[str, Any] | None,
    extracted_iocs: IOCData | None = None,
) -> ThreatIntelligence:
    """
    Convert the authoritative backend threat_intelligence payload into the
    existing internal ThreatIntelligence model.

    Only the current field names from logic_models.py are used.
    No legacy provider-report aliases are consulted.
    """
    if not raw or not isinstance(raw, dict):
        return ThreatIntelligence()

    ips: list[dict] = []
    domains: list[dict] = []
    urls: list[dict] = []
    hashes: list[dict] = []

    # ------------------------------------------------------------------
    # IP analysis
    # ------------------------------------------------------------------

    ip_obj = raw.get("ip_analysis")

    if isinstance(ip_obj, dict):

        originating_ip = ip_obj.get("originating_ip")

        # --------------------------------------------------------------
        # AbuseIPDB IOC reports
        # --------------------------------------------------------------

        abuse_reports = _safe_list(
            ip_obj.get("iocs_ip_abuseIPDB")
        )

        def _upsert_ip(
            ip: str,
            reputation_score: int,
            country: Any,
            asn: Any,
            isp: Any,
            threat_history: bool,
            categories: list[str],
        ) -> None:
            existing = next(
                (
                    item
                    for item in ips
                    if item.get("ip") == ip
                ),
                None,
            )

            if existing is None:
                ips.append(
                    {
                        "ip": ip,
                        "reputation_score": reputation_score,
                        "country": country,
                        "asn": asn,
                        "isp": isp,
                        "threat_history": threat_history,
                        "categories": list(
                            dict.fromkeys(categories)
                        ),
                    }
                )
                return

            existing["reputation_score"] = max(
                int(existing.get("reputation_score", 0)),
                reputation_score,
            )

            if not existing.get("country"):
                existing["country"] = country

            if not existing.get("asn"):
                existing["asn"] = asn

            if not existing.get("isp"):
                existing["isp"] = isp

            existing["threat_history"] = bool(
                existing.get("threat_history")
                or threat_history
            )

            existing["categories"] = list(
                dict.fromkeys(
                    _safe_list(
                        existing.get("categories")
                    )
                    + categories
                )
            )

        def _consume_abuse_report(
            entry: Any,
            default_ip: str | None = None,
        ) -> None:
            if not isinstance(entry, dict):
                return

            ip = (
                entry.get("ip")
                or entry.get("ipAddress")
                or default_ip
            )

            if not isinstance(ip, str) or not ip:
                return

            raw_score = (
                entry.get("abuseConfidenceScore")
                or entry.get("abuseConfidence")
                or entry.get("confidence")
                or 0
            )

            try:
                score = max(
                    0,
                    min(100, int(raw_score)),
                )
            except Exception:
                score = 0

            categories: list[str] = []

            if score >= 70:
                categories.append("phishing")

            if (
                entry.get("isWhitelisted") is False
                and score > 0
            ):
                categories.append("blacklisted")

            raw_categories = entry.get("categories")

            if isinstance(raw_categories, list):
                categories.extend(
                    str(category)
                    for category in raw_categories
                    if isinstance(category, str)
                )

            total_reports = entry.get(
                "totalReports",
                0,
            )

            try:
                has_history = (
                    int(total_reports) > 0
                    or score >= 50
                )
            except Exception:
                has_history = score >= 50

            _upsert_ip(
                ip=ip,
                reputation_score=score,
                country=(
                    entry.get("countryCode")
                    or entry.get("country")
                ),
                asn=entry.get("asn"),
                isp=entry.get("isp"),
                threat_history=has_history,
                categories=categories,
            )

        for entry in abuse_reports:
            _consume_abuse_report(entry)

        # --------------------------------------------------------------
        # AbuseIPDB originating-IP reports
        # --------------------------------------------------------------

        originating_abuse_reports = _safe_list(
            ip_obj.get(
                "originating_ip_abuseIPDB"
            )
        )

        for entry in originating_abuse_reports:
            _consume_abuse_report(
                entry,
                originating_ip,
            )

        # --------------------------------------------------------------
        # AlienVault OTX IOC reports
        # --------------------------------------------------------------

        otx_reports = _safe_list(
            ip_obj.get(
                "iocs_ip_alienvaultOTX"
            )
        )

        def _consume_otx_report(
            entry: Any,
            default_ip: str | None = None,
        ) -> None:
            if not isinstance(entry, dict):
                return

            ip = (
                entry.get("ip")
                or entry.get("indicator")
                or entry.get("ipAddress")
                or default_ip
            )

            if not isinstance(ip, str) or not ip:
                return

            raw_reputation = entry.get(
                "reputation"
            )

            if raw_reputation is None:
                pulse_info = entry.get(
                    "pulse_info"
                )

                if isinstance(
                    pulse_info,
                    dict,
                ):
                    pulses = pulse_info.get(
                        "pulses"
                    )

                    if isinstance(pulses, list):
                        raw_reputation = min(
                            100,
                            len(pulses) * 20,
                        )

            if raw_reputation is None:
                raw_reputation = 0

            try:
                reputation = max(
                    0,
                    min(100, int(raw_reputation)),
                )
            except Exception:
                reputation = 0

            categories: list[str] = []

            raw_categories = entry.get(
                "categories"
            )

            if isinstance(raw_categories, list):
                categories.extend(
                    str(category)
                    for category in raw_categories
                    if isinstance(category, str)
                )

            _upsert_ip(
                ip=ip,
                reputation_score=reputation,
                country=(
                    entry.get("country")
                    or entry.get("countryCode")
                ),
                asn=entry.get("asn"),
                isp=entry.get("isp"),
                threat_history=(
                    reputation >= 50
                    or bool(entry.get("pulse_info"))
                ),
                categories=categories,
            )

        for entry in otx_reports:
            _consume_otx_report(entry)

        # --------------------------------------------------------------
        # AlienVault OTX originating-IP reports
        # --------------------------------------------------------------

        originating_otx_reports = _safe_list(
            ip_obj.get(
                "originating_ip_alienvaultOTX"
            )
        )

        for entry in originating_otx_reports:
            _consume_otx_report(
                entry,
                originating_ip,
            )

        # --------------------------------------------------------------
        # Preserve originating_ip even when no provider report exists.
        # --------------------------------------------------------------

        if (
            isinstance(originating_ip, str)
            and originating_ip
            and not any(
                item.get("ip") == originating_ip
                for item in ips
            )
        ):
            ips.append(
                {
                    "ip": originating_ip,
                    "reputation_score": 0,
                    "country": None,
                    "asn": None,
                    "isp": None,
                    "threat_history": False,
                    "categories": [_UNKNOWN_REPUTATION_CATEGORY],
                }
            )

    # ------------------------------------------------------------------
    # URL analysis
    # ------------------------------------------------------------------

    url_obj = raw.get("url_analysis")

    if isinstance(url_obj, dict):
        vt_reports = _safe_list(
            url_obj.get("virusTotal_report")
        )

        for entry in vt_reports:
            if not isinstance(entry, dict):
                continue

            url = entry.get("url")

            if not isinstance(url, str) or not url:
                continue

            positives = entry.get("positives", 0)
            total = entry.get("total", 0)

            try:
                positives = int(positives)
            except Exception:
                positives = 0

            try:
                total = int(total)
            except Exception:
                total = 0

            reputation = (
                int(
                    positives / total * 100
                )
                if total > 0
                else 0
            )

            categories = [
                str(category)
                for category in _safe_list(
                    entry.get("categories")
                )
                if isinstance(category, str)
            ]

            if total <= 0:
                categories.append(_UNKNOWN_REPUTATION_CATEGORY)
            elif positives > 0 and not categories:
                categories.append("suspicious")

            urls.append(
                {
                    "url": url,
                    "reputation_score": reputation,
                    "domain": _extract_url_domain(url),
                    "threat_history": positives > 0,
                    "categories": categories,
                }
            )

    # ------------------------------------------------------------------
    # Domain analysis
    # ------------------------------------------------------------------

    domain_obj = raw.get(
        "domain_analysis"
    )

    if isinstance(domain_obj, dict):
        vt_reports = _safe_list(
            domain_obj.get("virusTotal_report")
        )

        for entry in vt_reports:
            if not isinstance(entry, dict):
                continue

            domain = entry.get("domain")

            if not isinstance(domain, str) or not domain:
                continue

            positives = entry.get("positives", 0)
            total = entry.get("total", 0)

            try:
                positives = int(positives)
            except Exception:
                positives = 0

            try:
                total = int(total)
            except Exception:
                total = 0

            reputation = (
                int(
                    positives / total * 100
                )
                if total > 0
                else 0
            )

            categories = [
                str(category)
                for category in _safe_list(
                    entry.get("categories")
                )
                if isinstance(category, str)
            ]

            if total <= 0:
                categories.append(_UNKNOWN_REPUTATION_CATEGORY)
            elif positives > 0 and not categories:
                categories.append("suspicious")

            domains.append(
                {
                    "domain": domain,
                    "reputation_score": reputation,
                    "country": entry.get("country"),
                    "registrar": entry.get("registrar"),
                    "creation_date": entry.get(
                        "creation_date"
                    ),
                    "threat_history": positives > 0,
                    "categories": categories,
                }
            )

    # ------------------------------------------------------------------
    # Attachment analysis
    # ------------------------------------------------------------------

    attachment_obj = raw.get(
        "attachment_analysis"
    )

    if isinstance(
        attachment_obj,
        dict,
    ):
        vt_reports = _safe_list(
            attachment_obj.get(
                "virusTotal_report"
            )
        )

        for entry in vt_reports:
            if not isinstance(entry, dict):
                continue

            file_hash = (
                entry.get("sha256")
                or entry.get("hash")
                or entry.get("resource")
            )

            if (
                not isinstance(file_hash, str)
                or not file_hash
            ):
                continue

            hash_type = "sha256"

            if len(file_hash) == 32:
                hash_type = "md5"
            elif len(file_hash) == 40:
                hash_type = "sha1"
            elif len(file_hash) == 128:
                hash_type = "sha512"

            positives = entry.get(
                "positives",
                0,
            )
            total = entry.get(
                "total",
                0,
            )

            try:
                positives = int(
                    positives
                )
            except Exception:
                positives = 0

            try:
                total = int(total)
            except Exception:
                total = 0

            reputation = (
                int(
                    positives / total * 100
                )
                if total > 0
                else 0
            )

            categories = [
                str(category)
                for category in _safe_list(
                    entry.get(
                        "categories"
                    )
                )
                if isinstance(category, str)
            ]

            if total <= 0:
                categories.append(_UNKNOWN_REPUTATION_CATEGORY)
            elif positives > 0 and not categories:
                categories.append("malware")

            hashes.append(
                {
                    "hash": file_hash,
                    "hash_type": hash_type,
                    "reputation_score": reputation,
                    "threat_history": positives > 0,
                    "categories": categories,
                }
            )

    # Preserve every IOC extracted from the email, even if no provider report
    # exists. The explicit marker keeps UNKNOWN distinct from a real score of 0.
    if extracted_iocs is not None:
        for ip in extracted_iocs.ips:
            if not any(item.get("ip") == ip for item in ips):
                ips.append({"ip": ip, "reputation_score": 0, "country": None, "asn": None, "isp": None, "threat_history": False, "categories": [_UNKNOWN_REPUTATION_CATEGORY]})
        for domain in extracted_iocs.domains:
            if not any(item.get("domain") == domain for item in domains):
                domains.append({"domain": domain, "reputation_score": 0, "country": None, "registrar": None, "creation_date": None, "threat_history": False, "categories": [_UNKNOWN_REPUTATION_CATEGORY]})
        for url in extracted_iocs.urls:
            if not any(item.get("url") == url for item in urls):
                urls.append({"url": url, "reputation_score": 0, "domain": _extract_url_domain(url), "threat_history": False, "categories": [_UNKNOWN_REPUTATION_CATEGORY]})
        for file_hash in extracted_iocs.hashes:
            if not any(item.get("hash") == file_hash for item in hashes):
                hash_type = "sha256" if len(file_hash) == 64 else "md5" if len(file_hash) == 32 else "sha1" if len(file_hash) == 40 else "sha512" if len(file_hash) == 128 else "sha256"
                hashes.append({"hash": file_hash, "hash_type": hash_type, "reputation_score": 0, "threat_history": False, "categories": [_UNKNOWN_REPUTATION_CATEGORY]})

    return ThreatIntelligence(
        ips=ips,
        domains=domains,
        urls=urls,
        hashes=hashes,
    )

# ---------------------------------------------------------------------------
# Email adapter
# ---------------------------------------------------------------------------

def adapt_email(raw: dict[str, Any] | None) -> EmailMetadata | None:
    """
    Convert email dict into EmailMetadata.

    Expected:
        {
          "sender": "a@b.com" or {"email_address":"a@b.com"},
          "recipient": "c@d.com",
          "subject": "...",
          "date": "2024-...",
          "message_id": "<...>"
        }
    Supports nested objects and alternative keys.
    """
    if not raw or not isinstance(raw, dict):
        return None

    def _extract_addr(value: Any) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for k in ("email_address", "address", "email", "value"):
                if isinstance(value.get(k), str):
                    return value.get(k)
            # Sometimes sender is {"sender":"a@b.com"}
            if isinstance(value.get("sender"), str):
                return value.get("sender")
        return None

    sender = _extract_addr(raw.get("sender")) or _extract_addr(raw.get("from")) or "unknown@unknown"
    recipient = _extract_addr(raw.get("recipient")) or _extract_addr(raw.get("to")) or "unknown@unknown"
    subject = raw.get("subject") or raw.get("Subject") or ""
    if not isinstance(subject, str):
        subject = str(subject)
    date_val = raw.get("date") or raw.get("Date")
    # date may be string; EmailMetadata expects datetime or None — let pydantic parse
    message_id = raw.get("message_id") or raw.get("messageId") or raw.get("Message-ID") or raw.get("messageID")

    try:
        return EmailMetadata(sender=sender, recipient=recipient, subject=subject, date=date_val, message_id=message_id)
    except Exception:
        # Fallback minimal
        try:
            return EmailMetadata(sender=sender, recipient=recipient, subject=subject)
        except Exception:
            return None


def adapt_iocs(email_raw: dict[str, Any] | None, threat_intel: ThreatIntelligence) -> IOCData:
    """
    Build IOCData — prefer email.iocs when present, otherwise derive from ThreatIntelligence.

    FINAL Subhom format:
        email.iocs: { ip_addresses: [...], domains: [...], urls: [...], hashes: [...] }
        Legacy/alt: { ips: [...], domains: [...], urls: [...], hashes: [...] }
    Supports BOTH:
        ips / ip_addresses (prefer ip_addresses when ips is absent)
        domains, urls, hashes (same name in both schemas)
    Each list contains strings.
    """
    if isinstance(email_raw, dict):
        iocs_raw = email_raw.get("iocs") or email_raw.get("ioc") or email_raw.get("indicators")
        if isinstance(iocs_raw, dict):
            # Handle ips / ip_addresses — prefer ip_addresses when ips is absent
            ips_raw = iocs_raw.get("ips")
            if not isinstance(ips_raw, list):
                ips_raw = iocs_raw.get("ip_addresses")
            # If both present, merge (robust); prefer ip_addresses content when ips empty
            if isinstance(iocs_raw.get("ips"), list) and isinstance(iocs_raw.get("ip_addresses"), list):
                # merge deduplicated
                ips_raw = list(dict.fromkeys([str(x) for x in iocs_raw.get("ips", []) + iocs_raw.get("ip_addresses", []) if isinstance(x, str)]))
                return IOCData(
                    ips=[str(x) for x in ips_raw if isinstance(x, str)],
                    domains=[str(x) for x in _safe_list(iocs_raw.get("domains")) if isinstance(x, str)],
                    urls=[str(x) for x in _safe_list(iocs_raw.get("urls")) if isinstance(x, str)],
                    hashes=[str(x) for x in _safe_list(iocs_raw.get("hashes")) if isinstance(x, str)],
                )
            return IOCData(
                ips=[str(x) for x in _safe_list(ips_raw) if isinstance(x, str)],
                domains=[str(x) for x in _safe_list(iocs_raw.get("domains")) if isinstance(x, str)],
                urls=[str(x) for x in _safe_list(iocs_raw.get("urls")) if isinstance(x, str)],
                hashes=[str(x) for x in _safe_list(iocs_raw.get("hashes")) if isinstance(x, str)],
            )
        # Also handle case where email itself contains iocs at top level
        if any(k in email_raw for k in ("ips", "ip_addresses", "domains", "urls", "hashes")) and (
            isinstance(email_raw.get("ips"), list) or isinstance(email_raw.get("ip_addresses"), list)
        ):
            ips_top = email_raw.get("ips") if isinstance(email_raw.get("ips"), list) else email_raw.get("ip_addresses")
            # merge if both present at top level
            if isinstance(email_raw.get("ips"), list) and isinstance(email_raw.get("ip_addresses"), list):
                ips_top = list(dict.fromkeys([str(x) for x in email_raw.get("ips", []) + email_raw.get("ip_addresses", []) if isinstance(x, str)]))
            return IOCData(
                ips=[str(x) for x in _safe_list(ips_top) if isinstance(x, str)],
                domains=[str(x) for x in _safe_list(email_raw.get("domains")) if isinstance(x, str)],
                urls=[str(x) for x in _safe_list(email_raw.get("urls")) if isinstance(x, str)],
                hashes=[str(x) for x in _safe_list(email_raw.get("hashes")) if isinstance(x, str)],
            )

    # Derive from threat intel
    return IOCData(
        ips=[ip.ip for ip in threat_intel.ips],
        domains=[d.domain for d in threat_intel.domains],
        urls=[u.url for u in threat_intel.urls],
        hashes=[h.hash for h in threat_intel.hashes],
    )


# ---------------------------------------------------------------------------
# AI adapter — REAL data, no fabrication
# ---------------------------------------------------------------------------

def adapt_ai_assessment(raw: dict[str, Any] | None) -> AIAssessment:
    """
    Convert the current Ollama ai_assessment object into the existing
    internal AIAssessment model.

    Authoritative Ollama fields:

        phishing_probability
        bec_probability
        social_engineering_probability
        urgency_detected
        credential_request_detected
        financial_request_detected
        suspicious_language
        detected_patterns
        explanation
        model_info
        attachment_risk_detected
        malicious_attachment_detected
        attachment_findings

    The current internal AIAssessment model does not define dedicated fields
    for grounding, processing_time_seconds, processing model metadata, or
    attachment-specific fields. Those values therefore remain preserved inside
    the existing model_info dictionary without modifying logic/models.py.

    No legacy Ollama field names are used.
    """
    if not raw or not isinstance(raw, dict):
        return AIAssessment()

    # ------------------------------------------------------------------
    # Probability fields
    # ------------------------------------------------------------------

    def _probability(key: str) -> float:
        value = raw.get(key)

        if value is None:
            return 0.0

        try:
            probability = float(value)
        except (TypeError, ValueError):
            return 0.0

        return max(
            0.0,
            min(1.0, probability),
        )

    # ------------------------------------------------------------------
    # String-list fields
    # ------------------------------------------------------------------

    suspicious_language = _safe_list(
        raw.get("suspicious_language")
    )

    suspicious_language = [
        str(value)
        for value in suspicious_language
        if isinstance(
            value,
            (str, int, float),
        )
    ]

    detected_patterns = _safe_list(
        raw.get("detected_patterns")
    )

    detected_patterns = [
        str(value)
        for value in detected_patterns
        if isinstance(
            value,
            (str, int, float),
        )
    ]

    # ------------------------------------------------------------------
    # Attachment fields
    #
    # Authoritative attachment finding structure:
    #
    # {
    #     "finding_type": str,
    #     "evidence_path": str,
    #     "explanation": str,
    #     "evidence_strength": str
    # }
    # ------------------------------------------------------------------

    attachment_findings = _safe_list(
        raw.get("attachment_findings")
    )

    preserved_attachment_findings: list[dict[str, Any]] = []

    for finding in attachment_findings:
        if not isinstance(finding, dict):
            continue

        normalized_finding = {
            "finding_type": finding.get(
                "finding_type"
            ),
            "evidence_path": finding.get(
                "evidence_path"
            ),
            "explanation": finding.get(
                "explanation"
            ),
            "evidence_strength": finding.get(
                "evidence_strength"
            ),
        }

        preserved_attachment_findings.append(
            normalized_finding
        )

        # Keep attachment findings visible to the existing internal model
        # without changing the internal model schema.
        finding_type = finding.get(
            "finding_type"
        )

        explanation = finding.get(
            "explanation"
        )

        evidence_path = finding.get(
            "evidence_path"
        )

        finding_text_parts = [
            str(value).strip()
            for value in (
                finding_type,
                evidence_path,
                explanation,
            )
            if isinstance(value, str)
            and value.strip()
        ]

        finding_text = " — ".join(
            finding_text_parts
        )

        if (
            finding_text
            and finding_text not in suspicious_language
        ):
            suspicious_language.append(
                finding_text[:200]
            )

        if (
            isinstance(finding_type, str)
            and finding_type.strip()
            and finding_type not in detected_patterns
        ):
            detected_patterns.append(
                finding_type.strip()
            )

    # ------------------------------------------------------------------
    # Preserve the complete current attachment fields inside model_info.
    # ------------------------------------------------------------------

    extra_ai: dict[str, Any] = {}

    if "attachment_risk_detected" in raw:
        extra_ai[
            "attachment_risk_detected"
        ] = raw[
            "attachment_risk_detected"
        ]

    if "malicious_attachment_detected" in raw:
        extra_ai[
            "malicious_attachment_detected"
        ] = raw[
            "malicious_attachment_detected"
        ]

    if "attachment_findings" in raw:
        extra_ai[
            "attachment_findings"
        ] = preserved_attachment_findings

    # ------------------------------------------------------------------
    # Preserve Ollama model_info exactly.
    # ------------------------------------------------------------------

    base_model_info = raw.get(
        "model_info"
    )

    if isinstance(
        base_model_info,
        dict,
    ):
        merged_model_info = {
            **base_model_info,
            **extra_ai,
        }

    elif extra_ai:
        merged_model_info = extra_ai

    else:
        merged_model_info = None

    # ------------------------------------------------------------------
    # Construct the unchanged internal AIAssessment model.
    # ------------------------------------------------------------------

    try:
        return AIAssessment(
            phishing_probability=_probability(
                "phishing_probability"
            ),
            bec_probability=_probability(
                "bec_probability"
            ),
            social_engineering_probability=_probability(
                "social_engineering_probability"
            ),
            urgency_detected=bool(
                raw.get(
                    "urgency_detected",
                    False,
                )
            ),
            credential_request_detected=bool(
                raw.get(
                    "credential_request_detected",
                    False,
                )
            ),
            financial_request_detected=bool(
                raw.get(
                    "financial_request_detected",
                    False,
                )
            ),
            suspicious_language=suspicious_language,
            detected_patterns=detected_patterns,
            explanation=str(
                raw.get(
                    "explanation",
                    "",
                )
            ),
            model_info=merged_model_info,
        )

    except Exception:
        return AIAssessment()