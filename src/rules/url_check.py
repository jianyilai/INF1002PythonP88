from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urlparse
import tldextract  # for registrable domain (eTLD+1)

from .keywords import SUSPICIOUS_DOMAINS
from .whitelist import load_whitelist
from .distance_domain_check import (
    is_similar_domain,
    check_domain_reputation_virustotal,
)

# Load whitelist once
WHITELIST: List[str] = load_whitelist()
WHITELIST_SET = set(WHITELIST)

# Regexes
URL_RE  = re.compile(r"(https?://[^\s)>'\"\]]+)", re.IGNORECASE)
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Subdomain tokens that often show up in phish infrastructure
RISKY_SUBDOMAIN_TOKENS = {
    "login", "signin", "verify", "verification", "account", "accounts",
    "secure", "security", "update", "billing", "auth", "password",
    "id", "support", "helpdesk"
}

def extract_urls(text: str) -> List[str]:
    return URL_RE.findall(text or "")

def is_ip_address(host: str) -> bool:
    return bool(IPV4_RE.match(host))

def _normalize_host(netloc: str) -> str:
    host = (netloc or "").split(":")[0].lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host

def _parts(host: str) -> tuple[str, str, str]:
    """
    Return (subdomain, registrable_domain, suffix)
    e.g., login.mail.lycos.com -> ('login.mail', 'lycos.com', 'com')
    """
    ext = tldextract.extract(host)
    sub = ext.subdomain or ""
    reg = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    return sub, reg, ext.suffix or ""

def domain_suspicion_score(domain: str, threshold: int = 2, use_reputation: bool = True) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    sub, registrable, suffix = _parts(domain)

    # Unknown registrable domain (tiny nudge)
    if registrable and registrable not in WHITELIST_SET:
        score += 1
        reasons.append(f"{domain}: registrable domain '{registrable}' not in whitelist")

    # Suspicious TLDs
    for tld in SUSPICIOUS_DOMAINS.get("suspicious_tlds", []):
        if registrable.endswith(tld) or domain.endswith(tld):
            score += 2
            reasons.append(f"{domain}: suspicious TLD '{tld}'")

    # Suspicious patterns anywhere in the host
    for pat in SUSPICIOUS_DOMAINS.get("domain_patterns", []):
        if pat in domain:
            score += 1
            reasons.append(f"{domain}: suspicious pattern '{pat}'")

    # Risky subdomain tokens (e.g., 'login', 'verify')
    if sub:
        tokens = {tok for tok in sub.split(".") if tok}
        hits = sorted(tokens & RISKY_SUBDOMAIN_TOKENS)
        if hits:
            # Cap at 2 to avoid inflation
            add = min(len(hits), 2)
            score += add
            reasons.append(f"{domain}: risky subdomain token(s) {hits}")

    # Near-whitelist similarity (use registrable vs whitelist)
    if registrable:
        similar, correct, dist = is_similar_domain(registrable, WHITELIST_SET, max_distance=threshold)
        if similar and dist and dist > 0:
            score += 3
            reasons.append(f"{domain}: '{registrable}' similar to whitelisted '{correct}' (distance {dist})")

    # VirusTotal reputation
    if use_reputation:
        ok, msg = check_domain_reputation_virustotal(registrable or domain)
        if ok:
            reasons.append(f"{domain}: reputation OK (VT) — {msg}")
        else:
            score += 4
            reasons.append(f"{domain}: reputation flagged (VT) — {msg}")

    return score, reasons

def url_check(text: str, threshold: int = 2, use_reputation: bool = False) -> Tuple[int, dict]:
    urls = extract_urls(text)
    score = 0
    details = {"urls": [], "flags": []}

    for url in urls:
        parsed = urlparse(url)
        host = _normalize_host(parsed.netloc)
        if not host:
            continue

        details["urls"].append(host)

        if is_ip_address(host):
            score += 3
            details["flags"].append(f"{host}: URL uses raw IP")

        d_score, reasons = domain_suspicion_score(host, threshold=threshold, use_reputation=use_reputation)
        score += d_score
        details["flags"].extend(reasons)

    return score, details
