import asyncio
from email.utils import parseaddr

async def sender_analysis(validated_email):
    from_data, reply_to_data, return_path_data = await asyncio.gather(
        asyncio.to_thread(parse_sender, validated_email.from_),
        asyncio.to_thread(parse_sender, validated_email.reply_to),
        asyncio.to_thread(parse_sender, validated_email.return_path),
    )

    findings = []

    from_domain, reply_to_domain, return_path_domain = await asyncio.gather(
        asyncio.to_thread(extract_sender_domain, from_data['email_address']),
        asyncio.to_thread(extract_sender_domain, reply_to_data['email_address']),
        asyncio.to_thread(extract_sender_domain, return_path_data['email_address']),
    )

    if (from_domain and reply_to_domain and from_domain != reply_to_domain):
        findings.append("From and Reply-To domains differ")
    if (from_domain and return_path_domain and from_domain != return_path_domain):
        findings.append("From and Return-Path domains differ")

    return {
        "from": from_data,
        "reply_to": reply_to_data,
        "return_path": return_path_data,
        "findings": findings
    }

def parse_sender(address):
    name, email_address = parseaddr(address or "")
    return{
        "name": name,
        "email_address": email_address
    }

def extract_sender_domain(address):
    if not address or "@" not in address:
        return None
    return address.split("@", 1)[1]