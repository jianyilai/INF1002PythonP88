'''# url_check.py
# ---------------------------------------------------
# Detects suspicious URLs in email content:
# - Flags URLs with IP addresses instead of domains
# - Flags URLs with suspicious TLDs or domain patterns (from keywords.py)
# - Compares URL domains against a whitelist (using edit distance)
#
# Returns (score, details)


import re
from urllib.parse import urlparse
from .keywords import SUSPICIOUS_DOMAINS
from .whitelist import load_whitelist
from .distance_domain_check import Levenshtein

whitelist = load_whitelist()

def extract_urls(text: str):
    """Extract all URLs from a string using regex."""
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text or "")


def is_ip_address(domain: str):
    """Check if a domain is an IP address."""
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None


def domain_suspicion_score(domain: str, threshold: int = 2):
    """
    Check if domain is suspicious:
    - Contains bad TLDs/patterns
    - Too close to whitelist domains (edit distance)
    """
    score = 0
    reasons = []

    # Suspicious TLD check
    for tld in SUSPICIOUS_DOMAINS.get("suspicious_tlds", []):
        if domain.endswith(tld):
            score += 2
            reasons.append(f"Suspicious TLD: {tld}")

    # Suspicious pattern check
    for pat in SUSPICIOUS_DOMAINS.get("domain_patterns", []):
        if pat in domain:
            score += 1
            reasons.append(f"Suspicious pattern: {pat}")

    # Edit distance check against whitelist
    for safe in whitelist:
        distance = Levenshtein.distance(domain, safe)
        if 0 < distance <= threshold:
            score += 3
            reasons.append(f"Similar to safe domain: {safe} (distance {distance})")

    return score, reasons


def url_check(text: str):
    """
    Main function to check URLs inside email content.
    Returns (score, details).
    """
    urls = extract_urls(text)
    score = 0
    details = {"urls": [], "flags": []}

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # If domain includes port, remove it
        domain = domain.split(":")[0]

        # IP address detection
        if is_ip_address(domain):
            score += 3
            details["flags"].append(f"IP address used: {domain}")

        # Domain suspicion
        d_score, reasons = domain_suspicion_score(domain)
        score += d_score
        details["flags"].extend(reasons)

        details["urls"].append(domain)

    return score, details


# --- Example usage
if __name__ == "__main__":
    body = """
    Please verify your account here: http://192.168.1.10/login
    Or visit https://secure-paypal.tk/verify
    """
    score, info = url_check(body)
    print("Score:", score)
    print("Details:", info)
'''