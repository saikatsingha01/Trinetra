import re
from WorkFlow_2.phishing_patterns import PHISHING_PATTERNS

def phishing_analysis(validated_email):
    text = validated_email.content
    findings = []
    for category, pattern in PHISHING_PATTERNS.items():
        if check_pattern(text, pattern):
            findings.append(category)
    return findings

def check_pattern(text, pattern):
    result = re.search(pattern, text, re.IGNORECASE)
    return result is not None