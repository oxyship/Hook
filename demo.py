"""
Hook demo — runs five sample emails through the detector and prints
formatted results to the terminal.

Usage:
    python demo.py

Requires ANTHROPIC_API_KEY to be set in your environment.
"""

from __future__ import annotations

import os
import sys
import textwrap
from dataclasses import dataclass

from hook import AnalysisResult, HookDetector

# ---------------------------------------------------------------------------
# ANSI colour helpers (graceful fallback when not a TTY)
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def green(t: str) -> str:
    return _c("32;1", t)


def yellow(t: str) -> str:
    return _c("33;1", t)


def red(t: str) -> str:
    return _c("31;1", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


# ---------------------------------------------------------------------------
# Sample emails
# ---------------------------------------------------------------------------

@dataclass
class SampleEmail:
    label: str
    expected: str  # "safe" | "suspicious" | "phishing"
    text: str


SAMPLES: list[SampleEmail] = [
    # ── 1. Legitimate marketing newsletter ──────────────────────────────────
    SampleEmail(
        label="Legitimate Newsletter",
        expected="safe",
        text="""\
Subject: Your June Digest from Hacker News Weekly
From: digest@hackernewsweekly.com
To: reader@example.com

Hi there,

Here are this week's top stories curated for you:

1. How Cloudflare Uses Rust in Production — bit.ly/hn-1234  ← NOTE: this
   shortener goes to hackernewsweekly.com/articles/cloudflare-rust

2. Understanding LLM Tokenization From First Principles
   https://hackernewsweekly.com/articles/llm-tokenization

3. The Art of Unix Plumbing (2024 Edition)
   https://hackernewsweekly.com/articles/unix-plumbing

You're receiving this because you subscribed at hackernewsweekly.com.
Unsubscribe: https://hackernewsweekly.com/unsubscribe?token=u_abc123xyz

— The HN Weekly Team
""",
    ),

    # ── 2. Bank credential-harvesting Hook ─────────────────────────────────
    SampleEmail(
        label="Bank Credential Harvesting",
        expected="phishing",
        text="""\
Subject: ⚠️ URGENT: Your Chase Bank account will be suspended in 24 hours
From: security-alert@chas3-bank.com
Reply-To: verify@chas3-bank.com

Dear Valued Customer,

Our fraud detection system has flagged SUSPICIOUS ACTIVITY on your Chase
checking account ending in ****1234. To protect your funds, we have
temporarily LIMITED access.

YOUR ACCOUNT WILL BE PERMANENTLY CLOSED IN 24 HOURS unless you verify
your identity immediately by clicking the link below:

    http://chase-secure-verify.ru/login?session=9A3K7

You will need to confirm:
  • Online banking username and password
  • Social Security Number (last 4 digits)
  • Credit card CVV
  • One-time verification code from your phone

Do NOT share this email. This is a confidential security communication.

Chase Online Security Team
""",
    ),

    # ── 3. IRS tax-refund government impersonation ───────────────────────────
    SampleEmail(
        label="IRS Tax Refund Scam",
        expected="phishing",
        text="""\
Subject: IRS: You are owed a tax refund of $3,847.00 — Claim within 48 hours
From: irs-refunds@irs-gov-portal.com

INTERNAL REVENUE SERVICE — OFFICIAL NOTIFICATION

Taxpayer ID: ***-**-7823

After a routine audit of 2023 filings, the IRS has determined you are
eligible for a REFUND of $3,847.00.

To receive your refund via direct deposit you must complete the secure
refund form within 48 HOURS or the refund will be FORFEITED and returned
to the U.S. Treasury.

Complete your refund form here:
  https://irs-refund-portal.biz/claim?id=TX78230

Required information:
  - Full legal name and date of birth
  - Social Security Number
  - Bank routing + account number for direct deposit

NOTE: Failure to claim within the deadline will result in the funds being
reassigned. The IRS will not re-issue expired refunds.

Department of the Treasury — Internal Revenue Service
""",
    ),

    # ── 4. Package-delivery smishing-style Hook ────────────────────────────
    SampleEmail(
        label="Fake Package Delivery",
        expected="phishing",
        text="""\
Subject: Your FedEx package #FX992817364 could not be delivered — action required
From: noreply@fedex-delivery-update.info
To: customer@example.com

FedEx Delivery Notification

We attempted to deliver your package (Tracking: FX992817364) on June 3.
The driver could not access your address.

Your package will be returned to sender in 3 DAYS unless you reschedule.

To reschedule delivery and confirm your address, a $1.99 redelivery fee
is required:

    Click here to pay & reschedule: http://fedex-redeliver.net/pay?pkg=FX992817364

Payment accepted: Visa, Mastercard, PayPal

If you do not act within 72 hours, your package will be destroyed.

FedEx Customer Support
DO NOT REPLY to this email. Visit our portal above.
""",
    ),

    # ── 5. CEO fraud / Business Email Compromise (BEC) ──────────────────────
    SampleEmail(
        label="CEO Fraud / BEC",
        expected="phishing",
        text="""\
Subject: Confidential — Wire transfer needed today
From: ceo.michael.hartwell@company-corp.net
To: finance@company.com

Hi Sarah,

I'm in back-to-back board meetings all day and can't take calls. I need
you to process an urgent wire transfer — this is time-sensitive and
must be completed before 3 PM EST today.

Amount: $47,500.00
Beneficiary: Meridian Consulting LLC
Bank: First National Bank
Routing: 082902282
Account: 4019287364

This is for a new vendor contract I signed this morning. Please treat
this as CONFIDENTIAL — do not discuss with other team members until
I give the go-ahead. Legal reasons.

I'll explain everything once I'm out of meetings. Just confirm by
reply when it's done.

Thanks,
Michael Hartwell
CEO, Company Corp
Sent from my iPhone
""",
    ),
]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _verdict_badge(verdict: str) -> str:
    if verdict == "safe":
        return green(f"✅  {verdict.upper()}")
    if verdict == "suspicious":
        return yellow(f"⚠️   {verdict.upper()}")
    return red(f"🚨  {verdict.upper()}")


def _risk_bar(score: float, width: int = 30) -> str:
    filled = round(score * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = f"{score:.0%}"
    if score < 0.35:
        bar_colored = green(bar)
    elif score < 0.65:
        bar_colored = yellow(bar)
    else:
        bar_colored = red(bar)
    return f"[{bar_colored}] {bold(pct)}"


def _tactic_chips(result: AnalysisResult) -> str:
    t = result.tactics
    flags = {
        "urgency": t.urgency,
        "impersonation": t.impersonation,
        "credential-harvesting": t.credential_harvesting,
        "suspicious-links": t.suspicious_links,
        "spoofing": t.spoofing,
    }
    active = [name for name, hit in flags.items() if hit]
    if not active:
        return dim("none detected")
    return "  ".join(red(f"[{name}]") for name in active)


def _print_result(idx: int, sample: SampleEmail, result: AnalysisResult) -> None:
    sep = "─" * 62
    print(f"\n{bold(sep)}")
    print(f"  {bold(f'#{idx}  {sample.label}')}")
    print(bold(sep))
    print(f"  Risk Score   {_risk_bar(result.risk_score)}")
    print(f"  Verdict      {_verdict_badge(result.verdict)}")
    print(f"  Tactics      {_tactic_chips(result)}")
    print()
    print(f"  {bold('Analysis:')}")
    for line in textwrap.wrap(result.explanation, width=60):
        print(f"    {line}")
    print()
    print(f"  {bold('Action:')}")
    for line in textwrap.wrap(result.recommended_action, width=60):
        print(f"    {line}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            red("ERROR: ANTHROPIC_API_KEY is not set.\n")
            + "Export it before running:\n"
            + "  export ANTHROPIC_API_KEY=sk-ant-...",
            file=sys.stderr,
        )
        sys.exit(1)

    detector = HookDetector()

    print()
    print(bold("  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗"))
    print(bold("  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"))
    print(bold("  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"))
    print(bold("  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"))
    print(bold("  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"))
    print(bold("  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"))
    print()
    print(f"  {dim('AI-Powered Phishing Email Detector  |  powered by Claude')}")
    print(f"  {dim('Analyzing ' + str(len(SAMPLES)) + ' sample emails...')}")

    for idx, sample in enumerate(SAMPLES, start=1):
        print(f"\n{dim(f'  Scanning #{idx}: {sample.label}...')}", end="", flush=True)
        try:
            result = detector.analyze(sample.text)
            _print_result(idx, sample, result)
        except Exception as exc:  # noqa: BLE001
            print(f"\n  {red('ERROR:')} {exc}")

    print(f"\n{bold('═' * 62)}")
    print(f"  {bold('Scan complete.')}  {dim(str(len(SAMPLES)) + ' emails analyzed.')}")
    print(f"{bold('═' * 62)}\n")


if __name__ == "__main__":
    main()
