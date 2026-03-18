"""
Hook — local Flask server.

Serves the dashboard UI and exposes:
  POST /analyze      — analyze a raw email for phishing
  GET  /examples     — return curated sample emails for the dashboard
  GET  /health       — liveness check

Usage:
    python server.py          # http://localhost:5000
    PORT=8080 python server.py
"""

from __future__ import annotations

import os
import sys

from flask import Flask, jsonify, request, send_from_directory

from hook import HookDetector, HookError

# ---------------------------------------------------------------------------
# Startup check — fail fast if the API key is missing
# ---------------------------------------------------------------------------

if not os.environ.get("ANTHROPIC_API_KEY"):
    print(
        "ERROR: ANTHROPIC_API_KEY is not set.\n"
        "Export it before running:\n"
        "  export ANTHROPIC_API_KEY=sk-ant-...",
        file=sys.stderr,
    )
    sys.exit(1)

app = Flask(__name__, static_folder=".")
detector = HookDetector()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Max email body accepted by /analyze (32 KB)
MAX_EMAIL_BYTES = 32_768

# ---------------------------------------------------------------------------
# Sample emails (shown via the dashboard "Try an example" buttons)
# ---------------------------------------------------------------------------

EXAMPLES = [
    {
        "label": "Legitimate Newsletter",
        "expected": "safe",
        "text": """\
Subject: Your June Digest from Hacker News Weekly
From: digest@hackernewsweekly.com
To: reader@example.com

Hi there,

Here are this week's top stories curated for you:

1. How Cloudflare Uses Rust in Production
   https://hackernewsweekly.com/articles/cloudflare-rust

2. Understanding LLM Tokenization From First Principles
   https://hackernewsweekly.com/articles/llm-tokenization

3. The Art of Unix Plumbing (2024 Edition)
   https://hackernewsweekly.com/articles/unix-plumbing

You're receiving this because you subscribed at hackernewsweekly.com.
Unsubscribe: https://hackernewsweekly.com/unsubscribe?token=u_abc123xyz

— The HN Weekly Team
""",
    },
    {
        "label": "Bank Credential Harvesting",
        "expected": "phishing",
        "text": """\
Subject: ⚠️ URGENT: Your Chase Bank account will be suspended in 24 hours
From: security-alert@chas3-bank.com
Reply-To: verify@chas3-bank.com

Dear Valued Customer,

Our fraud detection system has flagged SUSPICIOUS ACTIVITY on your Chase
checking account ending in ****1234. Your account will be PERMANENTLY
CLOSED IN 24 HOURS unless you verify your identity immediately:

    http://chase-secure-verify.ru/login?session=9A3K7

You will need to confirm:
  • Online banking username and password
  • Social Security Number (last 4 digits)
  • Credit card CVV

Chase Online Security Team
""",
    },
    {
        "label": "IRS Tax Refund Scam",
        "expected": "phishing",
        "text": """\
Subject: IRS: You are owed a tax refund of $3,847.00 — Claim within 48 hours
From: irs-refunds@irs-gov-portal.com

INTERNAL REVENUE SERVICE — OFFICIAL NOTIFICATION

After a routine audit of 2023 filings, the IRS has determined you are
eligible for a REFUND of $3,847.00. To receive your refund you must
complete the secure refund form within 48 HOURS or it will be FORFEITED.

Complete your refund form here:
  https://irs-refund-portal.biz/claim?id=TX78230

Required information:
  - Social Security Number
  - Bank routing + account number for direct deposit

Department of the Treasury — Internal Revenue Service
""",
    },
    {
        "label": "Fake Package Delivery",
        "expected": "phishing",
        "text": """\
Subject: Your FedEx package #FX992817364 could not be delivered
From: noreply@fedex-delivery-update.info

FedEx Delivery Notification

We attempted to deliver your package on June 3. Your package will be
returned to sender in 3 DAYS unless you reschedule.

To reschedule, a $1.99 redelivery fee is required:

    http://fedex-redeliver.net/pay?pkg=FX992817364

If you do not act within 72 hours, your package will be destroyed.

FedEx Customer Support
""",
    },
    {
        "label": "CEO Fraud / Wire Transfer",
        "expected": "phishing",
        "text": """\
Subject: Confidential — Wire transfer needed today
From: ceo.michael.hartwell@company-corp.net
To: finance@company.com

Hi Sarah,

I'm in back-to-back board meetings all day and can't take calls. I need
you to process an urgent wire transfer before 3 PM EST today.

Amount: $47,500.00
Beneficiary: Meridian Consulting LLC
Routing: 082902282
Account: 4019287364

Please treat this as CONFIDENTIAL — do not discuss with anyone until I
give the go-ahead. Confirm by reply when it's done.

Thanks,
Michael Hartwell, CEO
Sent from my iPhone
""",
    },
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "dashboard.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Hook"})


@app.route("/examples")
def examples():
    return jsonify(EXAMPLES)


@app.route("/analyze", methods=["POST"])
def analyze():
    # Enforce request size limit
    if request.content_length and request.content_length > MAX_EMAIL_BYTES:
        return jsonify({"error": "Request too large (32 KB max)."}), 413

    data = request.get_json(silent=True) or {}
    email_text: str = data.get("email", "").strip()

    if not email_text:
        return jsonify({"error": "No email content provided."}), 400

    if len(email_text.encode()) > MAX_EMAIL_BYTES:
        return jsonify({"error": "Email too large (32 KB max)."}), 413

    try:
        result = detector.analyze(email_text)
        payload = result.model_dump()
        payload["tactics"] = result.tactics.model_dump()
        return jsonify(payload)

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except HookError as exc:
        return jsonify({"error": f"Analysis failed: {exc}"}), 502
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Unexpected error: {exc}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Hook dashboard → http://localhost:{port}")
    app.run(debug=True, port=port)
