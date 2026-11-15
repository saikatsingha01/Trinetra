import asyncio, re, ipaddress
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()

async def extract_iocs(content):
    IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    URL_PATTERN = r'https?://[^\s<>"\']+'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    ipAddress, url, domain = await asyncio.gather(
        asyncio.to_thread(get_ip, content, IP_PATTERN),
        asyncio.to_thread(get_url, content, URL_PATTERN),
        asyncio.to_thread(get_domain, content, DOMAIN_PATTERN, EMAIL_PATTERN)
    )

    return{
        "ip_address": ipAddress,
        "url": url,
        "domain": domain
    }

def get_originating_ip(received_headers):
    for received in reversed(received_headers):
        ips = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            received
        )
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_global:
                    return ip
            except ValueError:
                pass
    return None

def get_ip(content, ipPattern):
    valid_ips = []
    ips = re.findall(ipPattern, content)
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    return list(dict.fromkeys(valid_ips))

def get_url(content, urlPattern):
    valid_urls = []
    urls = re.findall(urlPattern, content)
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            valid_urls.append(url)
    return list(dict.fromkeys(valid_urls))

def get_domain(content, domainPattern, email_pattern):
    content_without_emails = re.sub(email_pattern, '', content)
    domains = re.findall(domainPattern, content_without_emails)
    return list(dict.fromkeys(domains))