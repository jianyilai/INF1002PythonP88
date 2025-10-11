import re                
from rapidfuzz.distance import Levenshtein      
import requests         

# known valid emails (whitelist) — to detect typo variants of legitimate emails
known_emails = set(["johndoe@gmail.com", "user@domain.com", "admin@company.com"])

# whitelist of trusted domains — to validate domain trustworthiness
known_domains = set([
    "paypal.com",
        # Public email providers
        "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "icloud.com",
        "aol.com", "protonmail.com", "zoho.com", "gmx.com",
        "yandex.com", "qq.com", "163.com", "126.com", "sina.com",
        # Major companies
        "microsoft.com", "apple.com", "amazon.com", "facebook.com", "google.com",
        "twitter.com", "linkedin.com", "netflix.com", "adobe.com", "ibm.com",
        # Education (examples)
        "edu.com", "edu.sg.com", "harvard.edu", "ox.ac.uk", "mit.edu", "stanford.edu",
        # Government (examples)
        "gov.uk", "usa.gov", "gov.au", "gov.in", "gov.ca", "gov.sg",
        # Popular regional providers
        "web.de", "wanadoo.fr", "orange.fr", "libero.it", "virgilio.it",
        "naver.com", "daum.net", "hanmail.net", "rediffmail.com",
        # Other common domains
        "me.com", "live.com", "msn.com", "rocketmail.com",
        "fastmail.com", "tutanota.com", "inbox.com", "mail.ru", "bk.ru",
        "list.ru", "rambler.ru", "outlook.co.uk", "outlook.fr", "outlook.de",
        "hotmail.co.uk", "hotmail.fr", "hotmail.de",
        # Singapore related domains
        "singnet.com.sg", "pacific.net.sg", "starhub.com.sg", "singtel.com",
        "gov.sg", "moe.edu.sg", "nus.edu.sg", "ntu.edu.sg", "smu.edu.sg",
        "sp.edu.sg", "suss.edu.sg", "sims.edu.sg", "sgh.com.sg", "changi.com",
        "stb.gov.sg", "iras.gov.sg", "hdb.gov.sg", "cpf.gov.sg", "moh.gov.sg", 
        "nea.gov.sg", "nparks.gov.sg", "dbs.com.sg", "ocbc.com.sg", "uob.com.sg",
        "singlife.com", "axa.com.sg", "prudential.com.sg", "fairprice.com.sg",
        "coldstorage.com.sg", "giant.com.sg", "shengsiong.com.sg", "ntuc.com.sg",
        "carousell.com", "lazada.sg", "qoo10.sg", "shopee.sg", "zalora.sg",
        "grab.com", "gojek.com", "foodpanda.sg", "deliveroo.com.sg"
    ])

# Homoglyph mapping for common phishing tricks (similar looking characters)
HOMOGLYPHS = {
    'I': 'l',  # Uppercase i for lowercase L
    'i': 'l',  # Lowercase i for lowercase L
    'l': 'I',  # Lowercase L for uppercase i
}

# Detect if a domain uses suspicious homoglyphs compared to known domains
def is_homoglyph_domain(input_domain, known_domains):
    # For each known domain, check if changing any single homoglyph in input_domain matches the legit domain
    for legit_domain in known_domains:
        if len(input_domain) != len(legit_domain):
            continue
        for i, (c1, c2) in enumerate(zip(input_domain, legit_domain)):
            if c1 != c2 and c1 in HOMOGLYPHS and HOMOGLYPHS[c1] == c2:
                # Try replacing just this character and see if it matches
                candidate = input_domain[:i] + HOMOGLYPHS[c1] + input_domain[i+1:]
                if candidate == legit_domain:
                    return True, legit_domain
    return False, None

# VirusTotal API key  — for querying domain reputation
VT_API_KEY = "a7a108d529dd49e079c6bc09d4695a06075d68d427c679b2c925d4548b499984"

# Validate email format with regex
def is_valid_email(email):
    pattern = r'^(?!.*\.\.)(?!\.)(?!.*\.$)[a-zA-Z0-9._%+-]+@(?!(?:.*\.\.)|\.)([a-zA-Z-]+\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_similar_email(input_email, known_emails, max_distance=2):
    for correct_email in known_emails:
        distance = Levenshtein.distance(input_email, correct_email)
        if distance <= max_distance:
            return True, correct_email, distance
    return False, None, None
# Detect close typos against known domains using Levenshtein distance
def is_similar_domain(input_domain, known_domains, max_distance=1):
    for domain in known_domains:
        distance = Levenshtein.distance(input_domain, domain)
        if distance <= max_distance:
            return True, domain, distance
    return False, None, None
# Check domain reputation via VirusTotal API
domain_cache = {}

def check_domain_reputation_virustotal(domain, api_key):
    cache_status = None
    if domain in domain_cache:
        cache_status = f"Cache hit for {domain}"
        result = domain_cache[domain]
    else:
        cache_status = f"API call for {domain}"
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                if malicious_count == 0:
                    result = (True, "Domain reputation is clean.")
                else:
                    result = (False, f"Domain flagged with {malicious_count} malicious reports.")
            elif response.status_code == 401:
                result = (False, "Unauthorized - invalid API key.")
            else:
                result = (False, f"VirusTotal API error: HTTP {response.status_code}")
        except Exception as e:
            result = (False, f"Error querying VirusTotal API: {e}")
        domain_cache[domain] = result
    # Attach cache status to the result as a tuple (result, message, cache_status)
    return result + (cache_status,)
# Unified email checker with weighted scoring system
def check_email(input_email):
    WEIGHT_HOMOGLYPH = 0.2  # Homoglyph suspicion is significant
    output = []
    output.append(f"\nChecking: {input_email}")

    # If email is in known_emails, skip all checks and auto flag as safe
    if input_email in known_emails:
        output.append("✔️ Email is whitelisted. All checks skipped.")
        output.append("\nFinal phishing score: 0.00 / 1.00")
        output.append("✔️ Email is very likely legitimate.")
        return '\n'.join(output)

    score = 0.0

    # Inverted weight constants (higher score = more suspicious)
    WEIGHT_FORMAT = 0.4                # Invalid format is suspicious
    WEIGHT_DOMAIN_REPUTATION = 0.25    # Bad reputation is suspicious
    WEIGHT_FULL_EMAIL_TYPO = 0.2       # Typo is suspicious
    WEIGHT_DOMAIN_TYPO = 0.15          # Domain typo or unknown is suspicious
    WEIGHT_ALIAS_SUSPICION = 0.1       # '+' alias is suspicious

    # Extract local part and domain once here
    try:
        local_part, domain = input_email.split('@')
    except ValueError:
        local_part = None
        domain = None

    # 1) Validate email format
    if not is_valid_email(input_email):
        score += WEIGHT_FORMAT
        output.append("❌    Invalid email format.")
        format_valid = False
    else:
        format_valid = True

    if not domain:
        output.append("❌ Unable to extract domain from email.")
        reputation_ok = False
        rep_message = "No domain extracted, skipping domain reputation."
        domain_typo = False
    else:
        # Homoglyph detection (before lowercasing)
        homoglyph_found, legit_domain = is_homoglyph_domain(domain, known_domains)
        if homoglyph_found:
            # If homoglyph detected, force score to at least 0.8 (suspicious)
            score = max(score, 0.8)
            output.append(f"❌ Domain uses suspicious homoglyphs (e.g., 'I' or 'i' instead of 'l'). Did you mean: {legit_domain}?")
        # Lowercase for all other checks
        domain = domain.lower()
        # 2.5) Detect '+' aliasing in local part
        if '+' in local_part:
            score += WEIGHT_ALIAS_SUSPICION
            output.append("⚠️ '+' alias detected in email. This can be used for phishing or evasion.")

        # Check if domain is NOT in known_domains (unknown domain is suspicious)
        if domain not in known_domains:
            score += WEIGHT_DOMAIN_TYPO
            output.append("⚠️ Unknown domain, not listed under one of our known domains.")

        # 3) Check domain reputation
        reputation_ok, rep_message, cache_status = check_domain_reputation_virustotal(domain, VT_API_KEY)
        if not reputation_ok:
            score += WEIGHT_DOMAIN_REPUTATION
            output.append(f"❌ {rep_message}")
        else:
            output.append(f"✅ {rep_message}")
        #Output cache_status for debugging or display:
            output.append(f"[Cache status: {cache_status}]")

        # 4) Check domain typos
        domain_typo, correct_domain, domain_distance = is_similar_domain(domain, known_domains)
        if domain_typo and domain_distance > 0:
            score += WEIGHT_DOMAIN_TYPO
            output.append(f"⚠️ Domain suspicious — possible typo (edit distance: {domain_distance}). Did you mean: {correct_domain}?")

    # 5) Check for full email typos (only if format is valid)
    if format_valid:
        similar, match, distance = is_similar_email(input_email, known_emails)
        if similar:
            score += WEIGHT_FULL_EMAIL_TYPO
            output.append(f"⚠️ Suspicious — possible typo (edit distance: {distance}). Did you mean: {match}?")
        else:
            output.append("✅ Email format is valid and doesn't match known typo patterns.")
    else:
        output.append("⚠️ Skipping full email typo check due to invalid email format.")

    # Clamp score to [0, 1]
    score = min(max(score, 0.0), 1.0)

    # 6) Final decision (inverted)
    output.append(f"\nFinal phishing score: {score:.2f} / 1.00")

    if score >= 0.8:
        output.append("❌ Email address is very likely phishing or malicious.")
    elif 0.5 <= score < 0.8:
        output.append("⚠️ Email address is somewhat suspicious, review recommended.")
    else:
        output.append("✔️ Email address is likely legitimate.")

    return '\n'.join(output)

# Terminal input entrypoint
if __name__ == "__main__":
    while True:
        email_input = input("Enter an email address: ").strip()
        if is_valid_email(email_input):
            check_email(email_input)
            break
        else:
            print("Please enter a valid email address.")


