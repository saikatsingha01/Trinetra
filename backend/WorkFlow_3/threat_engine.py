import asyncio, os
from WorkFlow_3 import domain_analyzer as danl, ip_analyzer as ianl, url_analyzer as uanl, attachment_analyzer as aanl
from dotenv import load_dotenv
load_dotenv()

async def analyze_threat(validated_email):
    ips = validated_email.iocs.ip_address
    originating_ip = validated_email.originating_ip
    urls = validated_email.iocs.url
    domains = validated_email.iocs.domain
    hashes = [sha256 for sha256 in validated_email.attachments.sha256 if sha256]

    abip_api = os.getenv('ABUSE_IPDB_API_KEY')
    av_api = os.getenv('ALIEN_VAULT_OTX_API_KEY')
    vt_api = os.getenv('VIRUS_TOTAL_API_KEY')

    abip_end = os.getenv('ABUSE_IPDB_ENDPOINT')
    av_baseUrl = os.getenv('ALIEN_VAULT_OTX_BASE_URL')
    vt_baseUrl = os.getenv('VIRUS_TOTAL_BASE_URL')
    vt_url_end = os.getenv('VIRUS_TOTAL_URL_ENDPOINT')
    vt_domain_end = os.getenv('VIRUS_TOTAL_DOMAIN_ENDPOINT')
    vt_hashes_end = os.getenv('VIRUS_TOTAL_HASHES_ENDPOINT')

    ip_intel, url_intel, domain_intel, attachment_intel = await asyncio.gather(
        ianl.ip_intelligence(ips, originating_ip, abip_api, av_api, abip_end, av_baseUrl),
        uanl.url_intelligence(urls, vt_api, vt_baseUrl, vt_url_end),
        danl.domain_intelligence(domains, vt_api, vt_baseUrl, vt_domain_end),
        aanl.attachment_intelligence(hashes, vt_api, vt_baseUrl, vt_hashes_end)
    )

    return{
        "ip_analysis": ip_intel,
        "url_analysis": url_intel,
        "domain_analysis": domain_intel,
        "attachment_analysis": attachment_intel
    }