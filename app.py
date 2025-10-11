import src.rules.distance_domain_check as distance_domain_check
import io
import sys
# app.py
# ---------------------------------------------------
# Minimal Flask UI to test your phishing detector.
# - Paste sender, subject, body
# - See total score, classification, and breakdown
from flask import Flask, request, redirect, url_for, render_template, jsonify
import re
from src.scoring.final_risk_score import compute_email_risk
from dataclasses import asdict
from types import SimpleNamespace
app = Flask(__name__)

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():

    action = request.form.get("action", "analyze")
    
    # If user clicked "Clear", just render blank form
    if action == "clear":
        return render_template(
            "index.html",
            sender="",
            subject="",
            body="",
            result=None,
            raw=None,
            check_output=None,
            error=None
        )

    sender  = request.form.get("sender", "")
    subject = request.form.get("subject", "")
    body    = request.form.get("body", "")

    # Only show the output from check_email (output.append)
    format_valid = distance_domain_check.is_valid_email(sender)
    if not format_valid:
        error = "Please enter a valid sender email address."
        return render_template("index.html", result=None, error=error, check_output=None)

    check_output = distance_domain_check.check_email(sender)

    result_obj = compute_email_risk(sender, subject, body)  # dataclass
    data = asdict(result_obj)                                # plain dict

    return render_template("index.html", sender=sender, subject=subject, body=body, result=data, raw=data, check_output=check_output)

@app.post("/api/analyze")
def api_analyze():
    payload = request.get_json(force=True, silent=True) or {}
    result_obj = compute_email_risk(
        payload.get("sender", ""),
        payload.get("subject", ""),
        payload.get("body", ""),
    )
    # API does not use check_output, but for consistency, return as part of JSON if needed
    return jsonify({"result": asdict(result_obj), "check_output": None}), 200

if __name__ == "__main__":
    # Run: python app.py
    app.run(host="127.0.0.1", port=5000, debug=True)
