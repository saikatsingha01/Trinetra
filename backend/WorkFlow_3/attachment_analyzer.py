import asyncio

from WorkFlow_3.api_engine import api_request

async def attachment_intelligence( hashes, vt_api, vt_baseUrl, vt_hashes_end):
    unique_hashes = list(dict.fromkeys(hashes))
    tasks = [
        asyncio.to_thread(
            check_attachment_virusTotal,
            sha256,
            vt_api,
            vt_baseUrl,
            vt_hashes_end
        )
        for sha256 in unique_hashes
    ]
    results = await asyncio.gather(*tasks)
    return {
        "virusTotal_report": [result for result in results if result is not None]
    }


def check_attachment_virusTotal(sha256, vt_api, vt_baseUrl, vt_hashes_end):
    response = api_request(
        "GET",
        f"{vt_baseUrl}/{vt_hashes_end}/{sha256}",
        headers={
            "x-apikey": vt_api
        }
    )
    if response is not None:
        return response["data"]
    return None