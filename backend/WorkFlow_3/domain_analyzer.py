import asyncio

from WorkFlow_3.api_engine import api_request

async def domain_intelligence(domains, vt_api, vt_baseUrl, vt_domain_end):
    unique_domains = list(dict.fromkeys(domains))
    tasks = [
        asyncio.to_thread(
            check_domain_virusTotal,
            domain,
            vt_api,
            vt_baseUrl,
            vt_domain_end
        )
        for domain in unique_domains
    ]
    results = await asyncio.gather(*tasks)
    return {
        "virusTotal_report": [result for result in results if result is not None]
    }


def check_domain_virusTotal(domain, vt_api, vt_baseUrl, vt_domain_end):
    response = api_request(
        "GET",
        f"{vt_baseUrl}/{vt_domain_end}/{domain}",
        headers={
            "x-apikey": vt_api
        }
    )
    if response is not None:
        return response["data"]
    return None