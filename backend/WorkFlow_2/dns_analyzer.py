import asyncio, dns.resolver

async def dns_analysis(domains, ips):
    dns_report, rdns_report = await asyncio.gather(
        asyncio.to_thread(check_dns, domains),
        asyncio.to_thread(check_rdns, ips)
    )
    return{
        "dns_report": dns_report,
        "reverse_dns_report": rdns_report
    }

def check_dns(domains):
    result = []
    for domain in domains:
        domain_report = {}

        # TXT
        txt_report = []
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for answer in answers:
                txt_report.append(str(answer))
        except Exception as e:
            txt_report.append(str(e))
        domain_report["TXT"] = txt_report

        # MX
        mx_report = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for answer in answers:
                mx_report.append(str(answer))
        except Exception as e:
            mx_report.append(str(e))
        domain_report["MX"] = mx_report

        # A
        a_report = []
        try:
            answers = dns.resolver.resolve(domain, "A")
            for answer in answers:
                a_report.append(str(answer))
        except Exception as e:
            a_report.append(str(e))
        domain_report["A"] = a_report

        # AAAA
        aaaa_report = []
        try:
            answers = dns.resolver.resolve(domain, "AAAA")
            for answer in answers:
                aaaa_report.append(str(answer))
        except Exception as e:
            aaaa_report.append(str(e))
        domain_report["AAAA"] = aaaa_report

        result.append({
            "domain": domain,
            "records": domain_report
        })
    return result

def check_rdns(ips):
    results = []
    for ip in ips:
        hosts = []
        try:
            answer = dns.resolver.resolve_address(ip)
            for host in answer:
                hosts.append(str(host))
        except Exception as e:
            hosts.append(str(e))
        results.append({
            "ip": ip,
            "hosts": hosts
        })
    return results