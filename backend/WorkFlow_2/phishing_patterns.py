PHISHING_PATTERNS = {

    # 1. URGENCY / PRESSURE
    "urgent_action":
        r"\b(urgent|urgently|immediate|immediately|asap|right away|act now)\b",
    "urgent_response":
        r"\b(urgent|immediate)\s+(response|reply|action|attention)\b",
    "limited_time":
        r"\b(limited time|time sensitive|expires? soon|deadline|within\s+\d+\s+(hour|hours|minute|minutes))\b",
    "failure_to_act":
        r"\b(failure|failing)\s+to\s+(act|respond|verify|confirm|comply)\b",
    "last_warning":
        r"\b(last warning|final warning|final notice|last notice)\b",
    "immediate_consequence":
        r"\b(immediately|right away).{0,50}\b(suspend|block|disable|terminate|close)\b",
    "pressure_language":
        r"\b(do not delay|don't delay|do not ignore|don't ignore|respond immediately)\b",

    # 2. ACCOUNT / IDENTITY VERIFICATION
    "verify_account":
        r"\b(verify|confirm|validate|authenticate).{0,50}\b(account|profile)\b",
    "verify_identity":
        r"\b(verify|confirm|validate).{0,50}\b(identity|identification)\b",
    "verify_email":
        r"\b(verify|confirm|validate).{0,50}\b(email|e-mail|email address)\b",
    "account_confirmation":
        r"\b(account|profile).{0,40}\b(verification|confirmation|validation)\b",
    "identity_confirmation":
        r"\b(identity|identification).{0,40}\b(verification|confirmation)\b",
    "security_verification":
        r"\b(security|security check).{0,40}\b(verification|confirmation|validation)\b",

    # 3. CREDENTIAL / PASSWORD REQUESTS
    "password_expired":
        r"\b(password|passcode).{0,40}\b(expir(ed|ing)|expired|expires?)\b",
    "password_reset":
        r"\b(password|credential).{0,40}\b(reset|renew|change|update)\b",
    "credential_request":
        r"\b(provide|submit|confirm|verify|enter).{0,40}\b(password|credential|login details)\b",
    "username_request":
        r"\b(enter|provide|confirm|verify).{0,40}\b(username|user name)\b",
    "login_request":
        r"\b(enter|confirm|verify|provide).{0,40}\b(login|login details|credentials)\b",
    "credential_verification":
        r"\b(verify|confirm|validate).{0,40}\b(credentials|password|login)\b",

    # 4. LOGIN / SIGN-IN
    "sign_in_request":
        r"\b(sign\s+in|log\s+in|login).{0,50}\b(verify|confirm|secure|account)\b",
    "unusual_login":
        r"\b(unusual|suspicious|unrecognized|unknown).{0,40}\b(login|sign[- ]?in|activity)\b",
    "new_login":
        r"\b(new|recent|unknown|unrecognized).{0,30}\b(login|sign[- ]?in|device|location)\b",
    "login_alert":
        r"\b(login|sign[- ]?in).{0,30}\b(alert|alerted|notification|detected)\b",

    # 5. ACCOUNT SUSPENSION / LOCKING
    "account_suspended":
        r"\b(account|profile).{0,40}\b(suspend(ed)?|disabled|blocked|locked)\b",
    "account_terminated":
        r"\b(account|profile).{0,40}\b(terminate(d)?|closed|deactivated)\b",
    "account_lock":
        r"\b(account|profile).{0,40}\b(lock(ed)?|locked|freeze|frozen)\b",
    "access_revoked":
        r"\b(access|account privileges).{0,40}\b(revoked|removed|disabled)\b",
    "prevent_suspension":
        r"\b(verify|confirm|update).{0,40}\b(to prevent|avoid).{0,30}\b(suspension|closure|blocking)\b",

    # 6. LINK / CLICK ACTIONS
    "click_link":
        r"\b(click|tap|follow).{0,40}\b(link|here|button|below)\b",
    "click_to_verify":
        r"\b(click|tap).{0,40}\b(verify|confirm|validate|authenticate)\b",
    "click_to_login":
        r"\b(click|tap).{0,40}\b(login|log in|sign in)\b",
    "click_to_update":
        r"\b(click|tap).{0,40}\b(update|change|modify).{0,30}\b(account|information|details)\b",
    "link_expiration":
        r"\b(link|URL|verification link).{0,40}\b(expir(es|ed|ing)|valid for)\b",
    "use_link":
        r"\b(use|visit|open).{0,30}\b(link|URL|portal|website)\b",

    # 7. PAYMENT / FINANCIAL
    "payment_request":
        r"\b(payment|pay|transfer|transaction).{0,50}\b(required|requested|needed|pending)\b",
    "invoice_request":
        r"\b(invoice|bill|payment request).{0,50}\b(attached|attached file|included)\b",
    "bank_account":
        r"\b(bank account|account number|bank details|banking details)\b",
    "bank_transfer":
        r"\b(bank transfer|wire transfer|fund transfer|money transfer)\b",
    "payment_confirmation":
        r"\b(confirm|verify|validate).{0,40}\b(payment|transaction|transfer)\b",
    "payment_failure":
        r"\b(payment|transaction).{0,40}\b(failed|declined|rejected|unsuccessful)\b",
    "refund":
        r"\b(refund|reimbursement|money back).{0,50}\b(claim|request|verify|confirm)\b",
    "financial_information":
        r"\b(provide|submit|confirm|verify).{0,40}\b(bank|financial|payment)\s+(information|details)\b",

    # 8. PERSONAL / SENSITIVE INFORMATION
    "personal_information":
        r"\b(provide|submit|confirm|verify).{0,40}\b(personal information|personal details)\b",
    "identity_information":
        r"\b(provide|submit|upload|confirm).{0,40}\b(identity|identification)\s+(document|details|information)\b",
    "card_information":
        r"\b(credit card|debit card|card number|CVV|CVC)\b",
    "security_code":
        r"\b(security code|verification code|one[- ]time code|OTP|2FA code)\b",
    "otp_request":
        r"\b(enter|provide|share|confirm).{0,30}\b(OTP|one[- ]time password|verification code)\b",

    # 9. BEC / BUSINESS IMPERSONATION
    "ceo_request":
        r"\b(CEO|chief executive|executive|director|manager|boss).{0,80}\b(send|transfer|pay|purchase|buy|urgent)\b",
    "executive_impersonation":
        r"\b(CEO|director|manager|executive).{0,50}\b(confidential|private|urgent|immediate)\b",

    "confidential_request":
        r"\b(confidential|strictly confidential|private matter|keep this confidential)\b",
    "secret_transaction":
        r"\b(confidential|private).{0,60}\b(payment|transfer|transaction|purchase)\b",
    "gift_card_request":
        r"\b(gift card|gift cards|voucher).{0,50}\b(buy|purchase|send|code)\b",
    "wire_transfer_request":
        r"\b(send|make|initiate|process).{0,50}\b(wire|bank|fund).{0,30}\b(transfer|payment)\b",
    "invoice_change":
        r"\b(update|change|modify).{0,40}\b(invoice|bank details|payment details)\b",
    "vendor_payment":
        r"\b(vendor|supplier|invoice).{0,50}\b(payment|transfer|bank details)\b",

    # 10. AUTHORITY / TRUST IMPERSONATION
    "security_team_impersonation":
        r"\b(security team|security department|IT department|IT support).{0,60}\b(verify|confirm|update|login)\b",
    "support_impersonation":
        r"\b(customer support|customer service|technical support|IT support).{0,60}\b(verify|confirm|update|account)\b",
    "administrator_impersonation":
        r"\b(administrator|admin|system administrator).{0,60}\b(verify|confirm|update|password|account)\b",
    "official_notice":
        r"\b(official notice|security notice|important notice|service notification)\b",

    # 11. THREAT / CONSEQUENCE LANGUAGE
    "threat_account":
        r"\b(account|access).{0,50}\b(will be suspended|will be blocked|will be disabled)\b",
    "threat_closure":
        r"\b(account|service).{0,50}\b(will be closed|will be terminated|will be deactivated)\b",
    "security_breach_claim":
        r"\b(security breach|security incident|compromised account|unauthorized access)\b",
    "suspicious_activity":
        r"\b(suspicious activity|unusual activity|unauthorized activity|unrecognized activity)\b",
    "fraud_alert":
        r"\b(fraud alert|fraudulent activity|fraud detected|fraud prevention)\b",

    # 12. DELIVERY / ATTACHMENT LURES
    "open_attachment":
        r"\b(open|download|view|review).{0,30}\b(attachment|attached file|document)\b",
    "download_document":
        r"\b(download|open).{0,40}\b(document|file|attachment)\b",
    "important_document":
        r"\b(important|confidential|secure).{0,30}\b(document|attachment|file)\b",
    "invoice_attachment":
        r"\b(invoice|bill|receipt).{0,30}\b(attachment|attached|document)\b",
    "secure_document":
        r"\b(secure document|protected document|encrypted document)\b",

    # 13. DELIVERY / ACCOUNT NOTIFICATION
    "delivery_notification":
        r"\b(delivery|shipment|package|parcel).{0,50}\b(notification|update|confirmation)\b",
    "delivery_problem":
        r"\b(delivery|shipment|package|parcel).{0,50}\b(failed|delayed|problem|issue|unable)\b",
    "address_confirmation":
        r"\b(confirm|verify|update).{0,40}\b(address|delivery address|shipping address)\b",

    # 14. MFA / SECURITY DEVICE
    "mfa_request":
        r"\b(MFA|multi[- ]factor authentication|two[- ]factor authentication|2FA)\b",
    "authentication_code":
        r"\b(authentication code|verification code|security code|login code)\b",
    "mfa_verification":
        r"\b(verify|confirm|enter).{0,40}\b(MFA|2FA|authentication code|verification code)\b",
    "security_key":
        r"\b(security key|authentication key|verification key)\b",

    # 15. SOCIAL ENGINEERING / EMOTIONAL MANIPULATION
    "keep_secret":
        r"\b(do not tell|don't tell|keep secret|keep this private|keep confidential)\b",
    "trust_request":
        r"\b(trust me|please trust|between us|just between you and me)\b",
    "emergency_request":
        r"\b(emergency|urgent situation|critical situation|emergency situation)\b",
    "help_request":
        r"\b(I need your help|need your assistance|please help me).{0,60}\b(send|pay|transfer|purchase)\b",
    "emotional_pressure":
        r"\b(please help|desperate|critical|important).{0,50}\b(immediately|urgently|asap)\b",

    # 16. PASSWORD / SECURITY POLICY
    "password_policy":
        r"\b(password policy|password requirement|password security)\b",
    "password_update":
        r"\b(update|change|renew).{0,40}\b(password|passcode)\b",
    "credential_expiration":
        r"\b(credentials?|login).{0,40}\b(expir(ed|ing)|expires?)\b",

    # 17. GENERAL PHISHING LANGUAGE
    "verify_information":
        r"\b(verify|confirm|validate).{0,40}\b(information|details|data)\b",
    "update_information":
        r"\b(update|confirm|verify).{0,40}\b(information|details|profile)\b",
    "security_check":
        r"\b(security check|security verification|security confirmation)\b",
    "account_security":
        r"\b(account security|security of your account|protect your account)\b",
    "unusual_activity_action":
        r"\b(unusual activity|suspicious activity).{0,60}\b(verify|confirm|secure|login)\b",
    "protect_account":
        r"\b(protect|secure).{0,40}\b(account|profile|identity)\b",

    # 18. URL / WEBSITE LURE
    "secure_portal":
        r"\b(secure portal|security portal|verification portal|account portal)\b",
    "online_verification":
        r"\b(online verification|online authentication|online confirmation)\b",
    "visit_website":
        r"\b(visit|access|open).{0,40}\b(website|portal|web page|URL)\b",
    "website_verification":
        r"\b(verify|confirm|validate).{0,40}\b(through|via|on).{0,20}\b(website|portal|link)\b",

    # 19. TAX / GOVERNMENT / OFFICIAL-LIKE LURES
    "tax_notice":
        r"\b(tax notice|tax refund|tax payment|tax verification)\b",
    "government_notice":
        r"\b(government notice|official notice|legal notice|regulatory notice)\b",
    "legal_action":
        r"\b(legal action|legal proceedings|court action).{0,60}\b(payment|response|verification)\b",


    # 20. JOB / HR / CORPORATE LURES
    "hr_verification":
        r"\b(HR|human resources).{0,50}\b(verify|confirm|update|account|information)\b",
    "payroll_request":
        r"\b(payroll|salary|salary account).{0,50}\b(verify|confirm|update|bank)\b",
    "employee_information":
        r"\b(employee|staff).{0,50}\b(verify|confirm|update).{0,30}\b(information|details)\b",
    "benefits_notification":
        r"\b(benefits|employee benefits).{0,50}\b(verify|confirm|update)\b",

    # 21. DOWNLOAD / SOFTWARE LURES
    "software_update":
        r"\b(software|application|app|browser).{0,50}\b(update|upgrade|install)\b",
    "security_update":
        r"\b(security update|critical security update|important security update)\b",
    "download_update":
        r"\b(download|install).{0,40}\b(update|security update|patch|software)\b",


    # 22. REWARD / PRIZE / FREE OFFER
    "prize_claim":
        r"\b(congratulations|winner|won|prize|reward).{0,60}\b(claim|collect|verify)\b",
    "free_offer":
        r"\b(free|complimentary).{0,40}\b(offer|gift|reward|prize)\b",
    "reward_expiration":
        r"\b(reward|prize|offer).{0,40}\b(expires?|expired|claim before)\b",


    # 23. COMMON PHISHING SUBJECT / MESSAGE TERMS
    "action_required":
        r"\b(action required|action needed|response required|attention required)\b",
    "important_action":
        r"\b(important action|important update|important information)\b",
    "account_alert":
        r"\b(account alert|security alert|account notification)\b",
    "verification_required":
        r"\b(verification required|confirmation required|authentication required)\b",
    "update_required":
        r"\b(update required|confirmation needed|verification needed)\b",
}