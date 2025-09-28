# app.py
# ---------------------------------------------------
# Minimal Flask UI to test your phishing detector.
# - Paste sender, subject, body
# - See total score, classification, and breakdown

from flask import Flask, request, redirect, url_for, render_template_string, jsonify
import re
from src.scoring.final_risk_score import compute_email_risk
from dataclasses import asdict
from types import SimpleNamespace
app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Phishing Risk Checker</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
    .container { max-width: 900px; margin: 0 auto; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.05); }
    h1 { margin-top: 0; }
    label { display:block; margin: 8px 0 4px; font-weight: 600; }
    input[type=text], textarea { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 8px; }
    textarea { height: 160px; }
    .btn-row { display:flex; gap:12px; margin-top: 12px; }
    button { padding: 10px 16px; border: 0; border-radius: 8px; cursor:pointer; }
    .primary { background: #1f6feb; color: white; }
    .secondary { background: #eaeef2; }
    .kvd { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size: 13px; white-space: pre-wrap; }
    .badge { display:inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
    .SAFE { background:#e7f7ed; color:#146c2e; }
    .SUSPICIOUS { background:#fff7e6; color:#8a4b00; }
    .PHISHING { background:#ffe9e9; color:#8a0000; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align:left; padding: 8px; border-bottom:1px solid #eee; vertical-align: top; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    .muted { color:#666; }
    .pill { padding:2px 6px; border-radius:5px; background:#f5f5f5; display:inline-block; margin-right:6px; margin-bottom:6px; }
  </style>
</head>
<body>
<div class="container">
  <div class="card">
    <h1>Phishing Risk Checker</h1>
    {% if error %}
      <div style="color: red; margin-bottom: 10px;">{{ error }}</div>
    {% endif %}
    <form method="post" action="{{ url_for('analyze') }}">
      <label>Sender (From)</label>
      <input type="text" name="sender" placeholder="Security Team &lt;support@paypaI.com&gt;" required>

      <label>Subject</label>
      <input type="text" name="subject" placeholder="URGENT: Verify Account Now" required>

      <label>Body</label>
      <textarea name="body" placeholder="Paste email body here..." required></textarea>

      <div class="btn-row">
        <button class="primary" type="submit">Analyze</button>
        <button class="secondary" type="reset">Clear</button>
      </div>
    </form>
  </div>


# Email validation function (Python, not inside PAGE string)
def is_valid_email(email):
  pattern = r'^(?!.*\..)(?!\.)(?!.*\.$)[a-zA-Z0-9._%+-]+@(?!(?:.*\..)|\.)([a-zA-Z-]+\.)+[a-zA-Z]{2,}$'
  return re.match(pattern, email) is not None

  {% if result %}
  <div class="card">
    <h2>Result</h2>
    <p><strong>Total Score:</strong> {{ result.total_score }}</p>
    <p><strong>Classification:</strong> <span class="badge {{ result.classification }}">{{ result.classification }}</span></p>

    <h3>Breakdown</h3>
    <table>
      <tr>
        <th>Component</th>
        <th>Details</th>
      </tr>
      <tr>
        <td><strong>Sender Checks</strong></td>
        <td>
          <div><strong>Score:</strong> {{ result.breakdown.sender_checks.score }}</div>
          <div><strong>Sender Domain:</strong> <span class="mono">{{ result.breakdown.sender_checks.sender_domain or '—' }}</span></div>
          {% if result.breakdown.sender_checks.flags %}
            <div class="muted">Flags:</div>
            <div>

              from flask import Flask, request, redirect, url_for, render_template_string, jsonify
              from src.scoring.final_risk_score import compute_email_risk
              from dataclasses import asdict
              from types import SimpleNamespace
              import re
              app = Flask(__name__)

              # Email validation function (global scope)
              def is_valid_email(email):
                  pattern = r'^(?!.*\..)(?!\.)(?!.*\.$)[a-zA-Z0-9._%+-]+@(?!(?:.*\..)|\.)([a-zA-Z-]+\.)+[a-zA-Z]{2,}$'
                  return re.match(pattern, email) is not None

              {% endfor %}
            </div>
          {% endif %}
        </td>
      </tr>
      <tr>
        <td><strong>Keyword Position</strong></td>
        <td>
          <div><strong>Score:</strong> {{ result.breakdown.keyword_position.score }}</div>
          <div class="muted">Subject hits: {{ result.breakdown.keyword_position.subject_hits_count }}, Early hits: {{ result.breakdown.keyword_position.early_hits_count }}</div>
        </td>
      </tr>
      <tr>
        <td><strong>URL Checks</strong></td>
        <td>
          <div><strong>Score:</strong> {{ result.breakdown.url_checks.score }}</div>
          {% if result.breakdown.url_checks.urls %}
            <div class="muted">Found domains:</div>
            <div>
              {% for d in result.breakdown.url_checks.urls %}
                <span class="pill mono">{{ d }}</span>
              {% endfor %}
            </div>
          {% endif %}
          {% if result.breakdown.url_checks.flags %}
            <div class="muted" style="margin-top:6px;">Flags:</div>
            <div>
              {% for f in result.breakdown.url_checks.flags %}
                <span class="pill">{{ f }}</span>
              {% endfor %}
            </div>
          {% endif %}
        </td>
      </tr>
      <tr>
        <td><strong>Dictionary Indicators</strong></td>
        <td>
          <div><strong>Score:</strong> {{ result.breakdown.dictionary_indicators.score }}</div>
          {% if result.breakdown.dictionary_indicators.flagged_categories %}
            <div class="muted">Categories:</div>
            <div>
              {% for c in result.breakdown.dictionary_indicators.flagged_categories %}
                <span class="pill">{{ c }}</span>
              {% endfor %}
            </div>
          {% endif %}
          {% if result.breakdown.dictionary_indicators.flagged_keywords %}
            <div class="muted" style="margin-top:6px;">Keywords:</div>
            <div class="mono kvd">{{ result.breakdown.dictionary_indicators.flagged_keywords | tojson(indent=2) }}</div>
          {% endif %}
          <div class="muted" style="margin-top:6px;">Heuristic note: {{ result.breakdown.dictionary_indicators.recommendation }}</div>
        </td>
      </tr>
    </table>

    <h3>Raw JSON</h3>
    <pre class="kvd">{{ result | tojson(indent=2) }}</pre>
  </div>
  {% endif %}
</div>
</body>
</html>
"""

@app.get("/")
def index():
    return render_template_string(PAGE, result=None)

@app.post("/analyze")
def analyze():
  sender  = request.form.get("sender", "")
  subject = request.form.get("subject", "")
  body    = request.form.get("body", "")

  if not is_valid_email(sender):
    error = "Please enter a valid sender email address."
    return render_template_string(PAGE, result=None, error=error)

  result_obj = compute_email_risk(sender, subject, body)  # dataclass
  data = asdict(result_obj)                                # plain dict

  return render_template_string(PAGE, result=data, raw=data)

@app.post("/api/analyze")
def api_analyze():
    payload = request.get_json(force=True, silent=True) or {}
    result_obj = compute_email_risk(
        payload.get("sender", ""),
        payload.get("subject", ""),
        payload.get("body", ""),
    )
    return jsonify(asdict(result_obj)), 200

if __name__ == "__main__":
    # Run: python app.py
    app.run(host="127.0.0.1", port=5000, debug=True)
