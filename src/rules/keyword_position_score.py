# keyword_position_score.py
# ---------------------------------------------
# - Higher weight if a suspicious phrase appears in the SUBJECT
# - Medium weight if it appears early in the BODY (first X%)
# - Returns (score, details)

from typing import Iterable, Tuple, Dict, Any
#from .keywords import PHISHING_KEYWORDS_DATASET
import re

# uses keywords.py, 

def _flatten_keywords():
    # Turn the keywords.py dataset into a flat list of phrases.
    from .keywords import PHISHING_KEYWORDS_DATASET  
    flat = []
    for _, phrases in PHISHING_KEYWORDS_DATASET.items():
        flat.extend(phrases)
    return flat



def _compile_patterns(phrases):
    """
    Compile case-insensitive regex patterns with word-boundaries where sensible.
    Keeps it simple so phrases like 'verify account' still match.
    """
    patterns = []
    for p in phrases:
        p = p.strip()
        if not p:
            continue
        # Escape special chars; allow spaces as-is so multi-word phrases match naturally.
        escaped = re.escape(p).replace(r"\ ", r"\s+")
        # Add word boundaries at ends if the phrase looks like words (not URLs).
        pattern = rf"(?i)\b{escaped}\b"
        patterns.append(re.compile(pattern))
    return patterns


def keyword_position_score(
    subject: str,
    body: str,
    phrases: Iterable[str] | None = None,
    subject_weight: int = 3,
    early_weight: int = 2,
    early_ratio: float = 0.20,
):
    """
    Parameters
    ----------
    subject : str
        Email subject (raw string).
    body : str
        Email body (raw string).
    phrases : iterable[str] | None
        Suspicious phrases to check. If None, tries to load from keywords.py,
        else uses a small fallback list.
    subject_weight : int
        Score added per unique phrase hit in the subject.
    early_weight : int
        Score added per unique phrase hit in the early section of the body.
    early_ratio : float
        Fraction of the body considered "early" (0.20 = first 20%).

    Returns
    -------
    (score, details)
        score  : int total
        details: dict with hits and configuration (nice for demo/prints)
    """
    subject = (subject or "")
    body = (body or "")

    if phrases is None:
        phrases = _flatten_keywords()

    patterns = _compile_patterns(phrases)

    # Define early section of the body (first X%)
    cutoff = max(0, min(len(body), int(len(body) * early_ratio)))
    early_body = body[:cutoff]

    # Collect unique hits so we don't double-count the same phrase
    subject_hits = set()
    early_hits = set()

    for pat in patterns:
        if pat.search(subject):
            subject_hits.add(pat.pattern)
        if early_body and pat.search(early_body):
            early_hits.add(pat.pattern)

    # Score = (#unique subject hits)*subject_weight + (#unique early-body hits)*early_weight
    score = subject_weight * len(subject_hits) + early_weight * len(early_hits)

    details = {
        "subject_hits_count": len(subject_hits),
        "early_hits_count": len(early_hits),
        "subject_hits_patterns": sorted(subject_hits),
        "early_hits_patterns": sorted(early_hits),
        "params": {
            "subject_weight": subject_weight,
            "early_weight": early_weight,
            "early_ratio": early_ratio,
        },
    }
    return score, details