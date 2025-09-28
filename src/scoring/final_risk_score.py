# risk_scoring.py
# ---------------------------------------------------
# Combines multiple rules into a single phishing risk score:
# - Whitelist (exact / subdomain) check
# - Sender domain edit-distance similarity to safe domains
# - Keyword position scoring (subject + early body)
# - Suspicious URL detection (IPs, bad TLDs/patterns, lookalikes)
#
# Outputs a total score, per-rule breakdown, and a final classification.

from dataclasses import dataclass, asdict
from typing import Dict, Any, Tuple
import re

from src.rules.whitelist import load_whitelist
from src.rules.edit_distance import levenshtein_distance
from src.rules.keyword_position_score import keyword_position_score
from src.rules.keywords import analyze_phishing_indicators  # optional bonus signal
from src.rules.url_check import url_check

# ---------------------------
DEFAULT_WEIGHTS = {
    "whitelist_exact_bonus": -6,    # strong negative score (safer) if exact safe domain
    "whitelist_subdomain_bonus": -4, # *.safe.com gets a bonus too
    "edit_distance_near_match": 3,   # suspicious: looks like a safe domain
    "edit_distance_threshold": 2,    # distance <= 2 counts as "near"
    "sender_missing_or_bad": 2,      # malformed/no sender domain
    "min_keyword_subject_weight": 3, # keyword_position_score defaults (exposed to tune)
    "min_keyword_early_weight": 2,
    # URL check is scored inside url_check; we just sum it
}

# Classification thresholds (tune to your dataset)
THRESHOLDS = {
    "SAFE_MAX": 0,         # total score <= 0  => SAFE
    "SUSPICIOUS_MAX": 6,   # 1..6              => SUSPICIOUS
    # >6                   => PHISHING
}

EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

@dataclass
class RiskResult:
    total_score: int
    classification: str
    breakdown: Dict[str, Any]

def _extract_sender_domain(sender: str) -> str | None:
    if not sender:
        return None
    m = EMAIL_REGEX.search(sender)
    if not m:
        return None
    domain = m.group(1).lower().strip()
    # strip port if present (rare in emails)
    return domain.split(":")[0]

def _is_exact_whitelist(domain: str, whitelist: list[str]) -> bool:
    return domain in whitelist

def _is_subdomain_of_whitelist(domain: str, whitelist: list[str]) -> str | None:
    # returns the matched parent if domain endswith '.' + safe or equals safe
    for safe in whitelist:
        if domain == safe or domain.endswith("." + safe):
            return safe
    return None

def _sender_domain_score(domain: str | None, whitelist: list[str], cfg: dict) -> Tuple[int, Dict[str, Any]]:
    score = 0
    info = {"sender_domain": domain, "flags": []}

    if not domain:
        score += cfg["sender_missing_or_bad"]
        info["flags"].append("Missing or invalid sender domain")
        return score, info

    # Whitelist bonuses (reduce risk)
    if _is_exact_whitelist(domain, whitelist):
        score += cfg["whitelist_exact_bonus"]
        info["flags"].append(f"Exact whitelist match: {domain}")
        return score, info  # early exit; very strong signal

    parent = _is_subdomain_of_whitelist(domain, whitelist)
    if parent:
        score += cfg["whitelist_subdomain_bonus"]
        info["flags"].append(f"Subdomain of whitelisted: {parent}")

    # Edit-distance: close lookalikes to known safe domains = risky
    thr = cfg["edit_distance_threshold"]
    near_hits = []
    for safe in whitelist:
        d = levenshtein_distance(domain, safe)
        if 0 < d <= thr:
            score += cfg["edit_distance_near_match"]
            near_hits.append((safe, d))
    if near_hits:
        info["flags"].append({"near_safe_domains": near_hits, "distance<=thr": thr})

    return score, info

def classify(total: int) -> str:
    if total <= THRESHOLDS["SAFE_MAX"]:
        return "SAFE"
    if total <= THRESHOLDS["SUSPICIOUS_MAX"]:
        return "SUSPICIOUS"
    return "PHISHING"

def compute_email_risk(
    sender: str,
    subject: str,
    body: str,
    weights: Dict[str, int] | None = None,
    keyword_params: Dict[str, Any] | None = None,
) -> RiskResult:
    """
    Combine all checks into one risk score and label.

    Parameters
    ----------
    sender : str
        Raw "From" header (e.g., 'Support <help@paypaI.com>').
    subject : str
        Email subject.
    body : str
        Email body text (plain string).
    weights : dict | None
        Optional override of DEFAULT_WEIGHTS.
    keyword_params : dict | None
        Optional overrides for keyword_position_score parameters
        (e.g., {"subject_weight": 4, "early_weight": 2, "early_ratio": 0.2}).

    Returns
    -------
    RiskResult
        total_score, classification, breakdown
    """
    cfg = {**DEFAULT_WEIGHTS, **(weights or {})}
    whitelist = load_whitelist()

    breakdown: Dict[str, Any] = {}

    # 1) Sender domain based checks (whitelist + lookalikes)
    sender_domain = _extract_sender_domain(sender or "")
    s_score, s_info = _sender_domain_score(sender_domain, whitelist, cfg)
    breakdown["sender_checks"] = {"score": s_score, **s_info}

    # 2) Keyword position score (subject & early body)
    kp_kwargs = {
        "subject_weight": keyword_params.get("subject_weight", cfg["min_keyword_subject_weight"]) if keyword_params else cfg["min_keyword_subject_weight"],
        "early_weight": keyword_params.get("early_weight", cfg["min_keyword_early_weight"]) if keyword_params else cfg["min_keyword_early_weight"],
        "early_ratio": keyword_params.get("early_ratio", 0.20) if keyword_params else 0.20,
    }
    kw_score, kw_details = keyword_position_score(subject, body, **kp_kwargs)
    breakdown["keyword_position"] = {"score": kw_score, **kw_details}

    # 3) Suspicious URL checks (IPs, TLDs, patterns, near lookalikes)
    url_score, url_details = url_check(body or "")
    breakdown["url_checks"] = {"score": url_score, **url_details}

    # 4) (Optional) Dictionary-based keyword categories (coarse signal)
    #    This gives a lightweight corroborative score & flags.
    dict_result = analyze_phishing_indicators(body or "", subject or "", sender or "")
    dict_score = dict_result.get("risk_score", 0)
    breakdown["dictionary_indicators"] = {
        "score": dict_score,
        "flagged_categories": dict_result.get("flagged_categories", []),
        "flagged_keywords": dict_result.get("flagged_keywords", []),
        "recommendation": dict_result.get("recommendations", [""])[0],
    }

    # Sum scores
    total = s_score + kw_score + url_score + dict_score
    label = classify(total)

    return RiskResult(total_score=total, classification=label, breakdown=breakdown)

# ---------------------------
# Tiny demo
# ---------------------------
if __name__ == "__main__":
    demo_sender = 'Security Team <support@paypaI.com>'  # note the capital i "I" lookalike
    demo_subject = "URGENT: Verify Account Now"
    demo_body = """
    Please verify your account immediately to avoid suspension.
    Click here: http://192.168.1.50/login
    Or use https://secure-paypal.tk/verify
    """

    result = compute_email_risk(demo_sender, demo_subject, demo_body)
    print("TOTAL SCORE:", result.total_score)
    print("CLASSIFICATION:", result.classification)
    print("BREAKDOWN:", asdict(result)["breakdown"])
