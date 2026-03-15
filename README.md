# Hook — Phishing Email Detector

> **Phishing is responsible for over 90% of data breaches.**
> Analyzes raw email content and instantly
> surface the tactics attackers use — urgency manipulation, impersonation,
> credential harvesting, suspicious links, and spoofing — with a plain-English
> explanation of every red flag and a concrete recommended action.

---

## Demo

```
Email #2: Bank Credential Harvesting
──────────────────────────────────────────────────────────────
  Risk Score   [████████████████████████████░░] 95%
  Verdict      🚨 PHISHING
  Tactics      [urgency]  [impersonation]  [credential-harvesting]
               [suspicious-links]  [spoofing]

  Analysis:
    Impersonates Chase Bank from the domain "chas3-bank.com"
    (note the digit substitution — a classic typosquatting
    technique). Demands the victim's password, SSN, and CVV
    within 24 hours via an HTTP link to a .ru domain. All
    five phishing tactic categories are present.

  Action:
    Delete immediately. Do not click any links. Report to
    your IT/security team and forward to
    phishing@chase.com.
```

---

## Threat Model

Hook detects the five categories most commonly exploited in enterprise
and consumer phishing campaigns:

| Tactic | Description | Example |
|--------|-------------|---------|
| **Urgency** | Artificial time pressure or fear to prevent rational thought | *"Your account will be closed in 24 hours"* |
| **Impersonation** | Masquerading as a trusted brand, bank, or government agency | Display name "Apple Inc" sent from `appleid@outlook.com` |
| **Credential Harvesting** | Soliciting passwords, SSNs, credit cards, or 2FA codes | *"Reply with your verification code"* |
| **Suspicious Links** | Lookalike domains, URL shorteners, HTTP links for sensitive actions | `paypa1.com`, `amaz0n-secure.ru` |
| **Spoofing** | Mismatched From/Reply-To addresses, domain typosquatting | From: `security@bankofamerica-verify.com` |

### What Hook does NOT replace

- Your organization's mail gateway / SEG (Proofpoint, Mimecast, etc.)
- DNS-based email authentication (SPF, DKIM, DMARC)
- Security awareness training
- Incident response procedures

Hook is a **second-opinion layer** — fast, explainable AI triage that
helps end users and analysts make informed decisions before clicking.

---

## Project Structure

```
Hook/
├── hook/
│   ├── __init__.py       # Public API surface
│   └── detector.py       # Core detection logic (HookDetector, AnalysisResult)
├── tests/
│   └── test_detector.py  # Pytest unit tests (12 test cases)
├── demo.py               # CLI demo — runs 5 sample emails
├── server.py             # Flask backend (serves dashboard + /analyze endpoint)
├── dashboard.html        # Dark-theme browser UI
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set your API key

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### 3a. Run the CLI demo

```bash
python demo.py
```

### 3b. Launch the dashboard

```bash
python server.py
# → http://localhost:5000
```

### 3c. Use as a library

```python
from hook import HookDetector

detector = HookDetector()

result = detector.analyze("""
Subject: URGENT: Verify your PayPal account now
From: service@paypa1.com

Your account will be suspended unless you verify immediately...
""")

print(f"Risk:    {result.risk_score:.0%}")
print(f"Verdict: {result.verdict}")
print(f"Tactics: {[k for k, v in result.tactics.model_dump().items() if v]}")
print(f"\n{result.explanation}")
print(f"\nAction: {result.recommended_action}")
```

---

## API Reference

### `HookDetector(api_key=None, model="claude-opus-4-6")`

The main entry point. If `api_key` is omitted, reads `ANTHROPIC_API_KEY` from
the environment.

### `detector.analyze(email_text: str) -> AnalysisResult`

Analyzes raw email text and returns a structured result.

**Raises:**
- `ValueError` — empty input
- `HookError` — model refused or returned unparseable output
- `anthropic.APIError` — network/auth/rate-limit errors from the Anthropic SDK

### `AnalysisResult`

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | `float` (0–1) | 0 = safe, 1 = definite phishing |
| `verdict` | `"safe" \| "suspicious" \| "phishing"` | Human-readable verdict |
| `tactics` | `TacticsDetected` | Boolean flags for each tactic |
| `explanation` | `str` | Plain-English analysis |
| `recommended_action` | `str` | What to do right now |

### `TacticsDetected`

| Field | Type |
|-------|------|
| `urgency` | `bool` |
| `impersonation` | `bool` |
| `credential_harvesting` | `bool` |
| `suspicious_links` | `bool` |
| `spoofing` | `bool` |

---

## Running Tests

```bash
pytest tests/ -v
```

All tests mock the Anthropic API so they run without a live key:

```
tests/test_detector.py::TestRiskScores::test_legitimate_email_scores_low     PASSED
tests/test_detector.py::TestRiskScores::test_phishing_email_scores_high      PASSED
tests/test_detector.py::TestRiskScores::test_suspicious_email_is_middle_range PASSED
tests/test_detector.py::TestTacticDetection::test_urgency_tactic_detected    PASSED
...
12 passed in 0.18s
```

---

## Architecture

```
 Email text
     │
     ▼
 HookDetector.analyze()
     │
     ├── Validates input (ValueError on empty)
     │
     ├── Constructs prompt with SYSTEM_PROMPT (security analyst persona)
     │
     ├── Calls client.messages.parse(output_format=AnalysisResult)
     │       ↑ Anthropic Structured Outputs — Pydantic schema enforced
     │
     ├── Checks parsed_output is not None (HookError on refusal)
     │
     └── Returns validated AnalysisResult
```

The `SYSTEM_PROMPT` instructs Claude to act as an elite threat analyst,
defines the five tactic categories, and provides a calibrated risk score
scale. Claude's internal reasoning (via adaptive thinking) is used for
nuanced analysis — distinguishing legitimate marketing from social engineering
requires understanding sender context, domain reputation signals, and the
interplay of multiple weak indicators.

---

## Upgrade Path

### Fine-tuned classification model

For high-volume production use, fine-tune a smaller model on labeled phishing
datasets:

1. **Collect labeled data** — [PhishTank](https://phishtank.org),
   [OpenPhish](https://openphish.com), and your own SOC ticket history
2. **Generate explanations** with Hook to create training data that
   includes structured labels *and* reasoning
3. **Fine-tune Claude Haiku** (or an open-source model) via the
   [Anthropic fine-tuning API](https://docs.anthropic.com/en/docs/fine-tuning)
4. **Use the fine-tuned model** as the `model=` parameter in `HookDetector`

The fine-tuned model will be ~10× faster and cheaper than Opus while matching
its accuracy on the specific phishing patterns in your training set.

### Multi-signal enrichment

- **WHOIS lookups** — flag domains registered < 30 days ago
- **VirusTotal API** — check URLs against 70+ threat intel engines
- **SPF/DKIM/DMARC verification** — validate email authentication headers
- **Screenshot analysis** — render linked pages and use Claude Vision to detect
  fake login forms

---

## Why This Matters

> *"phishing attacks account for more than 80% of reported security incidents."*
> — Verizon Data Breach Investigations Report

> *"The average cost of a phishing-related data breach is $4.91 million."*
> — IBM Cost of a Data Breach Report 2023

Traditional rule-based filters miss targeted spear-phishing because they rely
on known-bad indicators (blocked domains, keyword lists). AI-powered analysis
understands *intent* — it can recognize that an email is impersonating an
executive even when every link is technically clean and the domain was
registered last week.

---

## License

MIT
