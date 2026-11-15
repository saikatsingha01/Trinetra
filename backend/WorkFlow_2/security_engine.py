import asyncio
from WorkFlow_2 import authentication_analyzer as authanl, sender_analyzer as sanl, header_analyzer as hanl
from WorkFlow_2 import phishing_analyzer as panl

async def analyze_security(validated_email, email_data):
    authentication_intel, sender_intel, header_intel, phishing_intel = await asyncio.gather(
        authanl.authentication_analysis(validated_email, email_data),
        sanl.sender_analysis(validated_email),
        asyncio.to_thread(hanl.header_analysis, validated_email),
        asyncio.to_thread(panl.phishing_analysis, validated_email)
    )
    return{
        "authentication_analysis": authentication_intel,
        "sender_analysis": sender_intel,
        "header_analysis": header_intel,
        "phishing_analysis": phishing_intel,
    }