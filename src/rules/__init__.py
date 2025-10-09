# src/rules/__init__.py
# ---------------------------------------------------
# Expose common rule functions so callers can just:
#   from src.rules import url_check

from .url_check import url_check
from .keyword_position_score import keyword_position_score
from .whitelist import load_whitelist
from .keywords import (
    PHISHING_KEYWORDS_DATASET,
    SUSPICIOUS_DOMAINS,
)

__all__ = [
    "url_check",
    "keyword_position_score",
    "load_whitelist",
    "PHISHING_KEYWORDS_DATASET",
    "SUSPICIOUS_DOMAINS",
]
