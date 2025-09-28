# src/__init__.py
# ---------------------------------------------------
# Root package initializer for phishing detector
# Makes imports like:
#   from src import compute_email_risk, url_check

from .rules import (
    url_check,
    keyword_position_score,
    load_whitelist,
    levenshtein_distance,
    PHISHING_KEYWORDS_DATASET,
    SUSPICIOUS_DOMAINS,
)
from .scoring.final_risk_score import compute_email_risk

__all__ = [
    # scoring
    "compute_email_risk",
    # rules
    "url_check",
    "keyword_position_score",
    "load_whitelist",
    "levenshtein_distance",
    "PHISHING_KEYWORDS_DATASET",
    "SUSPICIOUS_DOMAINS",
]
