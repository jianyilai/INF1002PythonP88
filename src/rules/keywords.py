
PHISHING_KEYWORDS_DATASET = {
    # Urgency and pressure tactics
    "urgency_keywords": [
        "urgent", "immediate", "expires today", "expires soon", "limited time",
        "act now", "don't delay", "hurry", "last chance", "final notice",
        "time sensitive", "expires in", "deadline", "asap", "quickly",
        "immediate action required", "respond immediately", "time is running out", 
        "immediately", "expired"
    ],

    # Financial and account security threats
    "security_threats": [
        "account suspended", "account locked", "account compromised",
        "security alert", "suspicious activity", "unauthorized access",
        "verify account", "confirm identity", "update payment",
        "payment failed", "card declined", "billing problem",
        "account will be closed", "suspended account", "frozen account",
        "security breach", "unauthorized login", "suspicious login", 
        "unusual activity"
    ],

    # Money and financial incentives
    "financial_incentives": [
        "free money", "cash prize", "you've won", "congratulations",
        "lottery winner", "inheritance", "tax refund", "compensation",
        "claim your", "collect your", "million dollars", "prize money",
        "windfall", "beneficiary", "transfer funds", "wire transfer",
        "deposit", "refund available", "bonus", "reward", "payment required", 
        "past due", 
    ],

    # Credential harvesting phrases
    "credential_harvesting": [
        "verify your password", "confirm your login", "update credentials",
        "verify identity", "confirm account details", "login verification",
        "password expires", "update security", "verify information",
        "confirm personal information", "account verification required",
        "click here to verify", "sign in to confirm", "validate account", 
        "reset password", 
    ],

    # Generic suspicious phrases
    "suspicious_phrases": [
        "click here", "click below", "click now", "download attachment",
        "open attachment", "confirm now", "verify now", "update now",
        "act immediately", "respond within", "failure to respond",
        "avoid account closure", "prevent suspension", "maintain access"
    ],

    # Fake authority/legitimacy claims
    "fake_authority": [
        "government agency", "tax authority", "bank security",
        "fraud department", "security team", "customer service",
        "account manager", "billing department", "technical support",
        "official notice", "legal department", "compliance team",
        "authorized by", "certified", "official communication"
    ],

    # Personal information requests
    "info_requests": [
        "provide ssn", "social security", "date of birth", "mother's maiden name",
        "full name", "address confirmation", "phone verification",
        "personal details", "sensitive information", "confidential data",
        "account number", "routing number", "pin number", "security code",
        "cvv", "expiration date", "credit card"
    ],

    # Spelling and grammar red flags (common misspellings)
    "misspellings": [
        "recieve", "paypal", "amazom", "microsooft", "googel",
        "bnak", "accont", "pasword", "secuirty", "verificaton",
        "suspeneded", "immeditaly", "importnat", "urgnet"
    ],

    # Technical/malware related
    "malware_indicators": [
        "install software", "download now", "system update required",
        "security patch", "antivirus", "system scan", "computer infected",
        "virus detected", "malware found", "system compromised",
        "clean your computer", "speed up pc", "fix errors", 
    ],

    # Romance/dating scam indicators
    "romance_scam": [
        "lonely", "widowed", "military deployed", "traveling abroad",
        "true love", "soulmate", "destiny", "meant to be",
        "emergency funds", "stuck abroad", "customs fee",
        "hospital bills", "travel money", "sex", "horny",
        "penis", "pussy", "vagina", "prostitute", "handjob", 
        "blowjob", "disease free", "drug", "drugs", "enlargement", 
        "viagra", "performance"
    ],

    # Business email compromise indicators
    "bec_indicators": [
        "ceo", "cfo", "president", "executive", "board member",
        "confidential transaction", "wire transfer", "vendor payment",
        "invoice attached", "payment request", "urgent payment",
        "change bank details", "new account information"
    ]
}

# Phishing domains and suspicious TLDs commonly used
SUSPICIOUS_DOMAINS = {
    "suspicious_tlds": [
        ".tk", ".ml", ".ga", ".cf", ".click", ".download", ".loan",
        ".win", ".bid", ".accountant", ".date", ".review", ".faith",
        ".cricket", ".science", ".work", ".party", ".gq"
    ],

    "domain_patterns": [
        "secure-", "verify-", "update-", "account-", "service-",
        "support-", "help-", "billing-", "security-", "login-",
        "-secure", "-verify", "-update", "-account", "-service"
    ]
}

# Email header red flags
EMAIL_HEADER_FLAGS = {
    "suspicious_subjects": [
        "re:", "fwd:", "urgent:", "important:", "confidential:",
        "security alert", "account notice", "payment confirmation",
        "delivery failure", "undelivered mail", "returned mail"
    ],

    "sender_spoofing_indicators": [
        "noreply", "no-reply", "donotreply", "admin", "support",
        "security", "service", "notification", "alert", "info"
    ]
}

# Function to check email content against phishing indicators
def analyze_phishing_indicators(email_text, email_subject="", sender_email=""):
    """
    Analyze email content for phishing indicators
    Returns a dictionary with risk scores and flagged keywords
    """
    email_text_lower = email_text.lower()
    email_subject_lower = email_subject.lower()
    sender_lower = sender_email.lower()

    results = {
        "risk_score": 0,
        "flagged_categories": [],
        "flagged_keywords": [],
        "recommendations": []
    }

    # Check each category of keywords
    for category, keywords in PHISHING_KEYWORDS_DATASET.items():
        flagged_in_category = []
        for keyword in keywords:
            if keyword.lower() in email_text_lower or keyword.lower() in email_subject_lower:
                flagged_in_category.append(keyword)
                results["flagged_keywords"].append(keyword)

        if flagged_in_category:
            results["flagged_categories"].append(category)
            # Weight different categories differently
            category_weights = {
                "urgency_keywords": 2,
                "security_threats": 3,
                "credential_harvesting": 4,
                "info_requests": 4,
                "financial_incentives": 2,
                "malware_indicators": 3
            }
            results["risk_score"] += len(flagged_in_category) * \
                category_weights.get(category, 1)

    # Check domain indicators
    for tld in SUSPICIOUS_DOMAINS["suspicious_tlds"]:
        if tld in sender_lower:
            results["risk_score"] += 2
            results["flagged_keywords"].append(f"Suspicious TLD: {tld}")

    # Generate risk assessment
    if results["risk_score"] >= 10:
        results["recommendations"].append("HIGH RISK: Likely phishing attempt")
    elif results["risk_score"] >= 5:
        results["recommendations"].append("MEDIUM RISK: Exercise caution")
    elif results["risk_score"] >= 2:
        results["recommendations"].append(
            "LOW RISK: Some suspicious indicators present")
    else:
        results["recommendations"].append(
            "MINIMAL RISK: Few or no indicators found")

    return results

# Example usage function
def example_usage():
    # Example of how to use the phishing detection system  
    sample_email = """
    URGENT: Your account has been suspended due to suspicious activity.
    Click here to verify your account immediately to avoid permanent closure.
    Please confirm your login credentials and social security number.
    """

    sample_subject = "Account Suspended - Immediate Action Required"
    sample_sender = "security@paypal-verification.tk"

    analysis = analyze_phishing_indicators(
        sample_email, sample_subject, sample_sender)

    print("Phishing Analysis Results:")
    print(f"Risk Score: {analysis['risk_score']}")
    print(f"Flagged Categories: {analysis['flagged_categories']}")
    print(f"Flagged Keywords: {analysis['flagged_keywords']}")
    print(f"Recommendation: {analysis['recommendations'][0]}")


if __name__ == "__main__":
    example_usage()
