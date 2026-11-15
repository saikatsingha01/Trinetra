import asyncio, spf, dkim, checkdmarc, re

from email.utils import parseaddr
from WorkFlow_2 import dns_analyzer as dnanl


async def authentication_analysis(validated_email, email_data):
    ips = validated_email.iocs.ip_address
    originating_ip = validated_email.originating_ip
    domains = validated_email.iocs.domain

    from_address = validated_email.from_
    return_path = validated_email.return_path
    auth_results = validated_email.authentication_results

    from_domain = get_from_domain(from_address)

    dns_result, spf_result, dkim_result, dmarc_result = await asyncio.gather(
        dnanl.dns_analysis(domains, ips),
        asyncio.to_thread(check_spf, originating_ip, return_path),
        asyncio.to_thread(check_dkim, email_data, auth_results),
        asyncio.to_thread(check_dmarc, from_domain)
    )

    return {
        "dns": dns_result,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result
    }


def get_from_domain(mail_from):
    try:
        _, email_address = parseaddr(mail_from or "")
        if not email_address or "@" not in email_address:
            return None
        return email_address.rsplit("@", 1)[1].lower()
    except Exception:
        return None


def check_spf(originating_ip, mail_from):
    if not originating_ip or not mail_from:
        return []
    try:
        _, email_address = parseaddr(mail_from)
        if not email_address or "@" not in email_address:
            return []
        result, explanation = spf.check2(
            i=originating_ip,
            s=email_address,
            h=None
        )
        print(
        spf.check2(
                i="209.85.220.41",
                s="rishimatall@gmail.com",
                h=None
            )
        )

        print(
        spf.check2(
                i="209.85.220.41",
                s="rishimatall@gmail.com",
                h="mail-sor-f41.google.com"
            )
        )
        return [(result, explanation)]
    except Exception as e:
        return [("error", str(e))]


def check_dkim(email_data, auth_results):
    try:
        local_result = dkim.verify(email_data)
        header_result = None
        for header in auth_results or []:
            match = re.search(
                r'\bdkim=(pass|fail|neutral|none|temperror|permerror)\b',
                header,
                re.IGNORECASE
            )
            if match:
                header_result = match.group(1).lower()
                break

        if local_result is True:
            return True
        
        if local_result is False and header_result == "pass":
            print(
                "DKIM discrepancy: Authentication-Results = Pass, "
                "but CypherX/dkimpy verification = Fail"
            )
        return False
    
    except Exception as e:
        print(
            f"DKIM verification exception: "
            f"{type(e).__name__}: {e}"
        )
        return False


def check_dmarc(domain):
    if not domain:
        return None
    try:
        results = checkdmarc.check_domains([domain], skip_tls=True)
        return results if results else None
    except Exception as e:
        return {"error": str(e)}