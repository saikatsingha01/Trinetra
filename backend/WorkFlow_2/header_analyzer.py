def header_analysis(validated_email):
    findings = []
    findings.extend(check_missing_headers(validated_email))
    return {
        "received": get_received_headers(validated_email),
        "authentication_results": get_authentication_results(validated_email),
        "dkim_signature": get_dkim_signature(validated_email),
        "findings": findings
    }

def get_received_headers(validated_email):
    return validated_email.received

def get_authentication_results(validated_email):
    return validated_email.authentication_results

def get_dkim_signature(validated_email):
    return validated_email.dkim_signature

def check_missing_headers(validated_email):
    findings = []
    if not validated_email.from_:
        findings.append("Missing From header")
    if not validated_email.to:
        findings.append("Missing To header")
    if not validated_email.date:
        findings.append("Missing Date header")
    if not validated_email.message_id:
        findings.append("Missing Message-ID header")
    return findings