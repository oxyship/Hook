"""
Hook — AI-powered phishing email detector.

Core detection logic backed by Claude. Accepts raw email text and returns a
structured risk assessment with a plain-English explanation of every red flag.
"""

from __future__ import annotations

from typing import Literal, Optional

import anthropic
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an elite cybersecurity analyst specializing in phishing detection,
social engineering analysis, and email threat intelligence. You have reviewed
millions of phishing campaigns across every industry vertical.

Analyze the provided email for the following threat categories:

1. URGENCY — Artificial time pressure, account-suspension threats, "act now"
   language, countdown timers, fear of losing access or money.

2. IMPERSONATION — Masquerading as a bank, tech company, government agency,
   delivery service, or executive. Display-name deception (e.g., "Apple Inc"
   sent from appleid-noreply@outlook.com).

3. CREDENTIAL HARVESTING — Requests for passwords, PINs, SSNs, credit-card
   numbers, two-factor codes, or any sensitive personal data.

4. SUSPICIOUS LINKS — Lookalike domains (paypa1.com, arnazon.com), URL
   shorteners hiding the real destination, HTTP links for sensitive actions,
   mismatched anchor text vs. actual URL, redirect chains.

5. SPOOFING — Mismatched From / Reply-To addresses, free-email providers
   impersonating corporate entities, domain typosquatting.

Risk Score Scale:
  0.00 – 0.20  Clearly legitimate — normal business or personal communication
  0.20 – 0.40  Minor concerns — unusual but most likely benign
  0.40 – 0.60  Notable red flags — treat with caution, verify through official channels
  0.60 – 0.80  Multiple phishing indicators — highly suspicious
  0.80 – 1.00  Classic phishing attempt — do not click, reply, or provide information

Be analytical and precise. Legitimate companies do send account-related emails;
focus on the specific deceptive patterns that distinguish phishing from normal
business communication. Avoid false positives on routine marketing emails."""

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class TacticsDetected(BaseModel):
    """Phishing tactics found in the analyzed email."""

    urgency: bool = Field(
        default=False,
        description="Artificial urgency or fear-based manipulation",
    )
    impersonation: bool = Field(
        default=False,
        description="Impersonating a trusted entity or brand",
    )
    credential_harvesting: bool = Field(
        default=False,
        description="Requesting passwords, credentials, or sensitive personal data",
    )
    suspicious_links: bool = Field(
        default=False,
        description="Contains deceptive, lookalike, or otherwise suspicious URLs",
    )
    spoofing: bool = Field(
        default=False,
        description="Spoofed sender address, Reply-To mismatch, or domain typosquatting",
    )


class AnalysisResult(BaseModel):
    """Complete structured phishing analysis result."""

    risk_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Threat level from 0.0 (definitely safe) to 1.0 (definite phishing)",
    )
    verdict: Literal["safe", "suspicious", "phishing"]
    tactics: TacticsDetected
    explanation: str = Field(
        description=(
            "Plain-English explanation of every red flag found — or why the "
            "email appears legitimate. Be specific: name the sender, subject, "
            "and exact language that raised concern."
        )
    )
    recommended_action: str = Field(
        description="Concrete action the recipient should take right now",
    )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class HookError(Exception):
    """Raised when Hook cannot complete analysis due to an internal error."""


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class HookDetector:
    """AI-powered phishing email detector using Claude.

    Usage::

        detector = HookDetector()
        result = detector.analyze("Subject: Urgent!\\n\\nYour account…")
        print(f"Risk {result.risk_score:.0%} — {result.verdict.upper()}")
        print(result.explanation)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-opus-4-6",
    ) -> None:
        self.model = model
        self.client = (
            anthropic.Anthropic(api_key=api_key)
            if api_key
            else anthropic.Anthropic()
        )

    def analyze(self, email_text: str) -> AnalysisResult:
        """Analyze raw email text for phishing indicators.

        Args:
            email_text: Full email content — subject line, headers, and body.
                        Plain text preferred; HTML is also accepted.

        Returns:
            :class:`AnalysisResult` containing risk score, verdict, detected
            tactics, a plain-English explanation, and a recommended action.

        Raises:
            ValueError: If *email_text* is empty or whitespace-only.
            HookError: If the API response cannot be parsed (e.g., the
                model refused to analyze the content).
            anthropic.AuthenticationError: Invalid or missing API key.
            anthropic.RateLimitError: API rate limit exceeded.
            anthropic.APIConnectionError: Network connectivity issue.
            anthropic.APIStatusError: Unexpected API-level error.
        """
        if not email_text or not email_text.strip():
            raise ValueError("email_text must not be empty")

        try:
            response = self.client.messages.parse(
                model=self.model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": (
                            "Analyze the following email for phishing indicators "
                            "and return a structured JSON result.\n\n"
                            f"--- BEGIN EMAIL ---\n{email_text.strip()}\n--- END EMAIL ---"
                        ),
                    }
                ],
                output_format=AnalysisResult,
            )
        except anthropic.BadRequestError as exc:
            raise HookError(
                f"Claude rejected the analysis request: {exc}"
            ) from exc

        if response.parsed_output is None:
            raise HookError(
                "Analysis returned no parseable result "
                f"(stop_reason={response.stop_reason!r}). "
                "The model may have refused to process this content."
            )

        return response.parsed_output
