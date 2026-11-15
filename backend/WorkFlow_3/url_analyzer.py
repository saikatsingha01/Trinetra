import asyncio, base64

from WorkFlow_3.api_engine import api_request


async def url_intelligence(urls, vt_api, vt_baseUrl, vt_url_end):
    unique_urls = list(dict.fromkeys(urls))
    tasks = [
        asyncio.to_thread(
            check_url_virusTotal,
            url,
            vt_api,
            vt_baseUrl,
            vt_url_end
        )
        for url in unique_urls
    ]
    results = await asyncio.gather(*tasks)
    return {
        "virusTotal_report": [result for result in results if result is not None]
    }


def check_url_virusTotal(url, vt_api, vt_baseUrl, vt_url_end):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = api_request(
        "GET",
        f"{vt_baseUrl}/{vt_url_end}/{url_id}",
        headers={
            "x-apikey": vt_api
        }
    )
    if response is not None:
        return response["data"]
    return None