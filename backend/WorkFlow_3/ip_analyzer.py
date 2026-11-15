import asyncio, ipaddress

from WorkFlow_3.api_engine import api_request

async def ip_intelligence(ips, originating_ip, abip_api, av_api, abip_end, av_baseUrl):
    unique_ips = list(dict.fromkeys(ips))

    abuse_tasks = [
        asyncio.to_thread(check_abuseIPDB, ip, abip_api, abip_end)
        for ip in unique_ips
    ]

    otx_tasks = [
        check_otx(ip, av_api, av_baseUrl, ("general", "reputation"))
        for ip in unique_ips
    ]

    abuse_results, otx_results = await asyncio.gather(
        asyncio.gather(*abuse_tasks),
        asyncio.gather(*otx_tasks)
    )

    abuse_map = {
        ip: result
        for ip, result in zip(unique_ips, abuse_results)
        if result is not None
    }

    otx_map = {
        ip: result
        for ip, result in zip(unique_ips, otx_results)
    }

    originating_abuse = []
    originating_otx = []

    if originating_ip:
        if originating_ip in abuse_map:
            originating_abuse = [abuse_map[originating_ip]]
        else:
            originating_abuse_task = asyncio.to_thread(check_abuseIPDB, originating_ip, abip_api, abip_end)
            originating_abuse_result = await originating_abuse_task

            if originating_abuse_result is not None:
                originating_abuse = [originating_abuse_result]

        if originating_ip in otx_map:
            originating_otx = list(otx_map[originating_ip])

            geo_result = await asyncio.to_thread(check_otx_section, originating_ip, "geo", av_api, av_baseUrl)

            if geo_result is not None:
                originating_otx.append(geo_result)

        else:
            originating_otx = await check_otx(originating_ip, av_api, av_baseUrl, ("general", "reputation", "geo"))

    iocs_abuse = [abuse_map[ip] for ip in unique_ips if ip in abuse_map]

    iocs_otx = []

    for ip in unique_ips:
        if ip in otx_map:
            iocs_otx.extend(otx_map[ip])
            
    return {
        "iocs_ip_abuseIPDB": iocs_abuse,
        "iocs_ip_alienvaultOTX": iocs_otx,
        "originating_ip": originating_ip,
        "originating_ip_abuseIPDB": originating_abuse,
        "originating_ip_alienvaultOTX": originating_otx
    }


def check_abuseIPDB(ip, abip_api, abip_end):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_global:
            return None
        response = api_request(
            "GET",
            abip_end,
            params={"ipAddress": ip},
            headers={
                "Key": abip_api,
                "Accept": "application/json"
            }
        )
        if response is not None:
            return response["data"]
    except ValueError:
        return None
    return None


def check_otx_section(ip, section, av_api, av_baseUrl):
    try:
        ip_obj = ipaddress.ip_address(ip)
        version = (
            "IPv4"
            if ip_obj.version == 4
            else "IPv6"
        )
        url = f"{av_baseUrl}/{version}/{ip}/{section}"
        response = api_request(
            "GET",
            url,
            headers={
                "X-OTX-API-KEY": av_api
            }
        )
        if response is not None:
            return {
                "ip": ip,
                "section": section,
                "data": response
            }
    except ValueError:
        return None
    return None


async def check_otx(ip, av_api, av_baseUrl, sections):
    tasks = [
        asyncio.to_thread(check_otx_section,ip,section,av_api,av_baseUrl
)
        for section in sections
    ]
    results = await asyncio.gather(*tasks)
    return [result for result in results if result is not None]