import streamlit as st
import re
from datetime import datetime

# -----------------------------
# Page configuration
# -----------------------------
st.set_page_config(
    page_title="ScamLens",
    page_icon="🛡️",
    layout="centered"
)

# =========================================================
# 1. KNOWLEDGE BASE
# =========================================================

TACTICS_KB = {
    "urgency": {
        "name": "🚨 Urgency",
        "definition": "Creates artificial time pressure to stop the user from verifying.",
        "examples": ["urgent", "immediately", "right now", "within", "today",
                     "act now", "as soon as possible", "limited time", "deadline"],
        "severity": "High"
    },
    "fear": {
        "name": "😨 Fear / Threat",
        "definition": "Uses fear of losing access, money or services to influence the user.",
        "examples": ["suspended", "suspend", "blocked", "block", "locked", "lock",
                     "terminated", "closed", "penalty", "fine", "legal action",
                     "will be cancelled"],
        "severity": "High"
    },
    "authority": {
        "name": "🏦 Authority / Impersonation",
        "definition": "References a trusted organisation to make the request appear legitimate.",
        "examples": ["bank", "government", "police", "customs", "maybank",
                     "cimb", "public bank", "dhl", "pos malaysia", "lhdn", "mypb"],
        "severity": "Medium"
    },
    "reward": {
        "name": "🎁 Reward / Greed",
        "definition": "Offers a prize, refund or windfall to lure the user.",
        "examples": ["you won", "winner", "prize", "reward", "cash",
                     "refund", "lucky draw", "free gift"],
        "severity": "Medium"
    },
    "sensitive": {
        "name": "🔐 Sensitive Information Request",
        "definition": "Requests or encourages disclosure of sensitive information.",
        "examples": ["otp", "password", "passcode", "verification code",
                     "credit card", "card number", "bank account",
                     "identity", "ic number", "passport"],
        "severity": "High"
    },
    "action": {
        "name": "🖱️ Suspicious Action",
        "definition": "Pushes the user to take immediate action instead of verifying.",
        "examples": ["click", "click here", "verify", "confirm", "transfer",
                     "pay", "payment", "download", "install", "call us", "reply"],
        "severity": "Medium"
    }
}

GUIDANCE_KB = {
    "HIGH RISK": [
        "Do not click any links in this message.",
        "Do not transfer money or share OTP / passwords.",
        "Verify through the organisation's official app, website or phone number.",
        "Report the message to the relevant authority if possible."
    ],
    "SUSPICIOUS": [
        "Pause before taking any action.",
        "Independently verify the sender through an official channel.",
        "Do not share sensitive information."
    ],
    "LOW RISK": [
        "No strong scam indicators were detected.",
        "Still avoid sharing passwords, OTP codes or sensitive information.",
        "If unsure, verify through an official channel."
    ]
}

# =========================================================
# 2. PII REDACTION
# =========================================================

def redact_pii(text):
    redactions = []
    redacted = text

    patterns = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
         '[EMAIL_REDACTED]', 'email'),

        (r'(?:\+?60|0)1\d{1,2}[- ]?\d{3,4}[- ]?\d{3,5}\b',
         '[PHONE_REDACTED]', 'phone'),

        (r'\b\d{6}[- ]?\d{2}[- ]?\d{4}\b',
         '[IC_REDACTED]', 'ic'),

        (r'\b[A-Z]{1,2}\d{7,8}\b',
         '[PASSPORT_REDACTED]', 'passport'),

        (r'\b\d{10,16}\b',
         '[ACCOUNT_REDACTED]', 'account'),

        (r'\b\d{4,8}\b',
         '[OTP_REDACTED]', 'otp'),
    ]

    for pattern, replacement, label in patterns:
        matches = re.findall(pattern, redacted)
        for m in matches:
            redactions.append({"type": label, "value": str(m)})
        redacted = re.sub(pattern, replacement, redacted)

    return redacted, redactions


# =========================================================
# 3. TOOLS
# =========================================================

def detect_tactics(message):
    message_lower = message.lower()
    findings = []

    for key, tactic in TACTICS_KB.items():
        matched = [p for p in tactic["examples"] if p in message_lower]
        if matched:
            findings.append({
                "key": key,
                "type": tactic["name"],
                "evidence": matched[0],
                "all_matches": matched,
                "explanation": tactic["definition"],
                "severity": tactic["severity"]
            })

    return findings


def detect_urls(message):
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', message)
    if urls:
        return {
            "key": "url",
            "type": "🔗 External Link",
            "evidence": urls[0],
            "all_matches": urls,
            "explanation": "The message contains an external link. Verify the destination independently before opening it.",
            "severity": "Medium"
        }
    return None


def build_manipulation_chain(findings):
    order = ["authority", "fear", "urgency", "sensitive", "action", "reward", "url"]
    present = {f["key"] for f in findings}
    chain = [k for k in order if k in present]

    name_map = {k: TACTICS_KB[k]["name"] for k in TACTICS_KB}
    name_map["url"] = "🔗 External Link"
    return [name_map.get(k, k) for k in chain]


def compute_risk(findings):
    score = 0
    for f in findings:
        if f["severity"] == "High":
            score += 25
        elif f["severity"] == "Medium":
            score += 12
    score = min(score, 100)

    if score >= 60:
        level = "HIGH RISK"
        icon = "🔴"
    elif score >= 30:
        level = "SUSPICIOUS"
        icon = "🟡"
    else:
        level = "LOW RISK"
        icon = "🟢"

    return score, level, icon


def compute_confidence(findings):
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")

    if high >= 2:
        return "High"
    elif high == 1 or medium >= 2:
        return "Medium"
    else:
        return "Low"


def build_counterfactual(findings):
    counterfactuals = []
    keys = {f["key"] for f in findings}

    if "urgency" in keys:
        counterfactuals.append(
            "If the message did not create urgency, the risk would drop significantly."
        )
    if "fear" in keys:
        counterfactuals.append(
            "If it did not threaten loss of access or service, the risk would drop."
        )
    if "sensitive" in keys:
        counterfactuals.append(
            "If it did not request OTP / passwords / sensitive data, the risk would drop to LOW."
        )
    if "authority" in keys and "action" in keys:
        counterfactuals.append(
            "If the sender were verified through an official channel, the risk would drop."
        )
    if not counterfactuals:
        counterfactuals.append(
            "No strong manipulation cues were found, so removing any single cue would not change much."
        )

    return counterfactuals


def write_audit_log(step, data):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "step": step,
        "data": data
    }
    st.session_state.setdefault("audit_log", [])
    st.session_state["audit_log"].append(entry)


# =========================================================
# 4. AGENT
# =========================================================

def run_agent(message):
    # Clear previous audit log
    st.session_state["audit_log"] = []

    write_audit_log("input_received", {"length": len(message)})

    # PII redaction
    redacted_message, redactions = redact_pii(message)
    st.session_state["redactions"] = redactions
    st.session_state["redacted_message"] = redacted_message

    write_audit_log("tool_call", {
        "tool": "redact_pii",
        "redactions": len(redactions),
        "types": list({r["type"] for r in redactions})
    })

    findings = detect_tactics(redacted_message)
    write_audit_log("tool_call", {"tool": "detect_tactics", "found": len(findings)})

    url_finding = detect_urls(redacted_message)
    if url_finding:
        findings.append(url_finding)
        write_audit_log("tool_call", {"tool": "detect_urls", "found": url_finding["evidence"]})

    score, level, icon = compute_risk(findings)
    write_audit_log("tool_call", {"tool": "compute_risk", "score": score, "level": level})

    confidence = compute_confidence(findings)
    write_audit_log("tool_call", {"tool": "compute_confidence", "confidence": confidence})

    chain = build_manipulation_chain(findings)
    write_audit_log("tool_call", {"tool": "build_manipulation_chain", "chain": chain})

    counterfactuals = build_counterfactual(findings)
    write_audit_log("tool_call", {"tool": "build_counterfactual", "count": len(counterfactuals)})

    recommendation = GUIDANCE_KB[level]
    write_audit_log("tool_call", {"tool": "lookup_guidance", "level": level})

    return {
        "score": score,
        "risk_level": level,
        "risk_icon": icon,
        "confidence": confidence,
        "findings": findings,
        "manipulation_chain": chain,
        "counterfactuals": counterfactuals,
        "recommendation": recommendation,
        "redacted_message": redacted_message,
        "redactions": redactions
    }


# =========================================================
# 5. UI
# =========================================================
st.markdown("""
<style>
[data-testid="InputInstructions"] {display: none;}

.scamlens-hint {
    text-align: right;
    font-size: 0.8rem;
    color: #888;
    margin-top: -12px;
    margin-bottom: 4px;
    padding-right: 4px;
}

[data-testid="stCaptionContainer"] p,
[data-testid="stCaptionContainer"] div {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}
[data-testid="stCaptionContainer"] {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}

[data-testid="stFormSubmitButton"] {
    margin-top: 0 !important;
    padding-top: 0 !important;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ScamLens")
st.subheader("Explainable Phishing Detector")

st.write(
    "Paste a suspicious SMS or email below. "
    "ScamLens will identify potential social-engineering tactics, "
    "explain the manipulation chain, and recommend a safe next step."
)

with st.form("analyze_form", enter_to_submit=True):
    message = st.text_area(
        "Suspicious message",
        height=200,
        placeholder=(
            "Example:\n\n"
            "URGENT! Your bank account will be suspended "
            "within 2 hours. Click here to verify your identity."
        )
    )

    st.markdown(
        '<div class="scamlens-hint">💡 Press Ctrl + Enter to analyze. Press Enter for a new line.</div>',
        unsafe_allow_html=True
    )

    submitted = st.form_submit_button(
        "🔍 Analyze Message",
        use_container_width=True
    )

    st.caption(
        "🔒 Privacy: Your message is processed only for analysis in this session and is not stored permanently."
    )


if submitted:
    if not message.strip():
        st.warning("Please enter a message first.")
    else:
        st.session_state["last_result"] = run_agent(message)
        st.session_state["approvals"] = []


result = st.session_state.get("last_result")

if result:
    # Risk result
    st.header(f"{result['risk_icon']} {result['risk_level']}")
    st.write(f"Risk score: **{result['score']}/100**")
    st.write(f"Confidence: **{result['confidence']}**")

    # Findings
    st.subheader("🚩 Why is this suspicious?")
    if result["findings"]:
        for f in result["findings"]:
            with st.container():
                st.markdown(f"### {f['type']}")
                st.markdown(f"**Evidence:** `{f['evidence']}`")
                st.write(f["explanation"])
                st.caption(f"Severity: {f['severity']}")
                st.divider()
    else:
        st.success("No strong scam indicators were detected.")

    # Manipulation chain
    if result["manipulation_chain"]:
        st.subheader("🧠 Manipulation Chain")
        st.markdown(" → ".join(result["manipulation_chain"]))
        st.caption("The message attempts to move the victim through these stages.")

    # Counterfactuals
    st.subheader("🔍 What would change the risk?")
    for c in result["counterfactuals"]:
        st.write(f"- {c}")

    # Recommended action
    st.subheader("🛡️ Recommended Action")
    for action in result["recommendation"]:
        st.write(f"- {action}")

    # PII redaction details
    if result["redactions"]:
        with st.expander("🔒 PII Redaction Details"):
            st.write("Detected and redacted PII before analysis:")
            for r in result["redactions"]:
                st.write(f"- `{r['type']}` → {r['value']}")
            st.caption("Redacted message:")
            st.code(result["redacted_message"])

    # Human approval
    st.subheader("✋ Human Approval Required")

    if result["risk_level"] == "LOW RISK":
        st.info("No consequential action is recommended for low-risk messages.")
    else:
        st.write("Select an action. Consequential actions require explicit approval.")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            if st.button("✅ Quarantine", use_container_width=True):
                st.session_state.setdefault("approvals", [])
                st.session_state["approvals"].append({
                    "action": "quarantine",
                    "approved": True,
                    "timestamp": datetime.utcnow().isoformat()
                })
                write_audit_log("human_approval", {"action": "quarantine", "approved": True})
                st.success("Approved: Message marked for quarantine. (simulated)")

        with col2:
            if st.button("📢 Report", use_container_width=True):
                st.session_state.setdefault("approvals", [])
                st.session_state["approvals"].append({
                    "action": "report",
                    "approved": True,
                    "timestamp": datetime.utcnow().isoformat()
                })
                write_audit_log("human_approval", {"action": "report", "approved": True})

        with col3:
            if st.button("🔔 Notify User", use_container_width=True):
                st.session_state.setdefault("approvals", [])
                st.session_state["approvals"].append({
                    "action": "notify_user",
                    "approved": True,
                    "timestamp": datetime.utcnow().isoformat()
                })
                write_audit_log("human_approval", {"action": "notify_user", "approved": True})

        with col4:
            if st.button("❌ Reject", use_container_width=True):
                st.session_state.setdefault("approvals", [])
                st.session_state["approvals"].append({
                    "action": "reject",
                    "approved": False,
                    "timestamp": datetime.utcnow().isoformat()
                })
                write_audit_log("human_approval", {"action": "reject", "approved": False})

    # Approval history
    if st.session_state.get("approvals"):
        with st.expander("📋 Approval History"):
            st.json(st.session_state["approvals"])

    # Tool call trace
    with st.expander("🔧 Tool Call Trace"):
        for entry in st.session_state.get("audit_log", []):
            st.write(f"**{entry['step']}** — {entry['data']}")

    # Audit log
    with st.expander("📜 Audit Log"):
        st.json(st.session_state.get("audit_log", []))

    # Limitations
    with st.expander("⚠️ Limitations"):
        st.write("- This prototype uses rule-based detection and may produce false positives.")
        st.write("- Ambiguous messages may be misclassified.")
        st.write("- The tool does not verify sender identity or URL reputation.")
        st.write("- Do not rely on this tool as the only defence against scams.")

    st.caption(
        "This prototype identifies potential scam indicators "
        "and does not guarantee that a message is malicious."
    )