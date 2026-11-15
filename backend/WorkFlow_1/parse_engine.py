import hashlib
from email  import policy
from email.parser import BytesParser
from WorkFlow_1 import ioc_extractor as iocext

async def parse_email(email_data):
    ctx = BytesParser(policy=policy.default).parsebytes(email_data)
    contents, ctx_content_types, ctx_file_names, ctx_attachments = [], [], [], {}
    filename, content_type, size, sha256 = [], [], [], []

    ctx_from = ctx.get("From")
    ctx_to = ctx.get("To")
    ctx_subject = ctx.get("Subject")
    ctx_date = ctx.get("Date")
    ctx_replyTo = ctx.get("Reply-To")
    ctx_returnPath = ctx.get("Return-Path")
    ctx_messageId = ctx.get("Message-ID")
    ctx_received = ctx.get_all("Received", [])
    ctx_auth_results = ctx.get_all("Authentication-Results", [])
    ctx_dkim_sign = ctx.get("DKIM-Signature")

    for part in ctx.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            contents.append(part.get_content())

        ctx_content_types.append(part.get_content_type())

        if part.get_filename():
            ctx_file_names.append(part.get_filename())

            payload = part.get_payload(decode=True)

            filename.append(part.get_filename())
            content_type.append(part.get_content_type())
            size.append(len(payload) if payload else 0)
            sha256.append(hashlib.sha256(payload).hexdigest() if payload else None)

    ctx_attachments["filename"] = filename
    ctx_attachments["content_type"] = content_type
    ctx_attachments["size"] = size
    ctx_attachments["sha256"] = sha256

    ctx_content = "\n".join(contents)

    ioc_content = "\n".join([
        str(ctx_from or ""),
        str(ctx_to or ""),
        str(ctx_subject or ""),
        str(ctx_date or ""),
        str(ctx_received or ""),
        str(ctx_replyTo or ""),
        str(ctx_returnPath or ""),
        str(ctx_messageId or ""),
        ctx_content
    ])

    ctx_iocs = await iocext.extract_iocs(ioc_content)
    ctx_originating_ip = iocext.get_originating_ip(ctx_received)

    parsed_email = {
        "from": ctx_from,
        "to": ctx_to,
        "subject": ctx_subject,
        "date": ctx_date,
        "received": ctx_received,
        "originating_ip": ctx_originating_ip,
        "reply_to": ctx_replyTo,
        "return_path": ctx_returnPath,
        "message_id": ctx_messageId,
        "content": ctx_content,
        "content_type": ctx_content_types,
        "file_name": ctx_file_names,
        "attachments": ctx_attachments,
        "iocs": ctx_iocs,
        "dkim_signature": ctx_dkim_sign,
        "authentication_results": ctx_auth_results,
    }
    return parsed_email