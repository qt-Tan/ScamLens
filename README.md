# 🛡️ ScamLens

**Explainable Scam Detection & Defence Agent**
Hackathon Track 3 — Scam Defence & Awareness

ScamLens analyzes suspicious SMS and email messages, identifies common social-engineering tactics, shows the evidence behind the detection, explains the manipulation chain, and recommends a safer next step.

## Problem

Many scam detectors only provide a risk score without explaining **why** a message is suspicious.

ScamLens aims to make scam detection more understandable by showing the detected tactics, supporting evidence, manipulation chain, and recommended next steps.

## Current Features

* SMS / Email input
* Scam tactic detection

  * Urgency
  * Fear / Threat
  * Authority
  * Sensitive information request
  * Suspicious action
  * Reward / Prize
* External URL detection
* Risk level assessment
* Evidence highlighting
* Manipulation chain explanation
* PII redaction
* Recommended safe actions
* Basic Tool Call Trace
* Basic Audit Log

## How It Works

```text
User Input (SMS / Email)
        ↓
PII Redaction
        ↓
Scam Tactic Detection
        ↓
URL Detection
        ↓
Evidence Collection
        ↓
Risk Assessment
        ↓
Manipulation Chain
        ↓
Recommended Safe Action
```

The current prototype uses rule-based detection to identify common scam patterns and provide explainable results.

## Tech Stack

* Python
* Streamlit
* Regex / Rule-based detection

## Getting Started

Install the required dependency:

```bash
pip install streamlit
```

Run the application:

```bash
streamlit run Scamlens.py
```

Then open the local Streamlit page in your browser.

## Example

### Input

```text
URGENT! Your bank account will be suspended within 2 hours.
Click here to verify your identity.
```

### Example Output

* **High Risk**
* Authority / Impersonation → "bank"
* Fear / Threat → "suspended"
* Urgency → "within 2 hours"
* Suspicious Action → "click here"
* Sensitive Information Request → "verify your identity"

### Manipulation Chain

```text
Authority → Fear → Urgency → Sensitive Information → Action
```

### Recommended Action

Do not click the link. Verify through the organisation's official app or website.

## Next Steps

The project is currently a prototype. Possible next steps include:

* Add LLM-assisted analysis
* Test with real scam and legitimate datasets
* Improve false-positive handling
* Add quantitative evaluation such as accuracy, precision, recall and F1
* Improve the UI and demo experience
* Expand scam detection patterns
* Improve the agent/tool workflow
* Add more languages if needed

## Limitations

* Current detection is mainly rule-based.
* Some legitimate messages may be incorrectly flagged.
* Some sophisticated scams may not be detected.
* Sender identity and URL reputation are not independently verified.
* Current detection is mainly focused on English messages.

## Disclaimer

ScamLens is a hackathon prototype for identifying potential scam indicators and explaining suspicious messages. It does not guarantee that a message is malicious or safe.

