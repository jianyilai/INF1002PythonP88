# src/scoring/__init__.py
# ---------------------------------------------------
# Expose scoring logic
# Usage:
#   from src.scoring import compute_email_risk

from .final_risk_score import compute_email_risk

__all__ = ["compute_email_risk"]
