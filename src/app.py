import base64
import os
import re
from datetime import datetime

import pandas as pd
import streamlit as st

import reporting as R

st.set_page_config(page_title="Sentrix AI", page_icon="🛡️", layout="wide")

BOT = "assets/bot.png" if os.path.exists("assets/bot.png") else "🛡️"
USER = "assets/user.png" if os.path.exists("assets/user.png") else "🕵️"

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
html, body, .stApp, p, li, label, input, textarea, button, div {
    font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
}
code, pre, kbd, [data-testid="stCode"] *, .mono { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important; }
.stApp {
    background:
        radial-gradient(1100px 520px at 88% -12%, rgba(255,59,59,.13), transparent 60%),
        #070505;
}
[data-testid="stHeader"] { background: transparent; }
#MainMenu, footer { visibility: hidden; }
[data-testid="stSidebar"] { background: #0b0707; border-right: 1px solid #2c1010; }
[data-testid="stChatMessage"] {
    background: rgba(255,59,59,.035);
    border: 1px solid #261112;
    border-left: 3px solid #ff3b3b;
    border-radius: 8px;
}
[data-testid="stChatMessage"] img { border-radius: 8px; }
[data-testid="stChatInput"] { border: 1px solid #ff3b3b; border-radius: 10px; }
.stButton > button, .stDownloadButton > button {
    background: transparent; color: #ff7b7b; border: 1px solid #5a1a1a; border-radius: 6px;
    font-weight: 500; transition: all .15s;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    background: #ff3b3b; color: #070505; border-color: #ff3b3b;
}
button[data-baseweb="tab"] { letter-spacing: .1em; font-weight: 600; font-size: .85rem; }
.brand { font-weight: 800; letter-spacing: .2em; font-size: 1.1rem; color: #ff3b3b; }
.brand span { color: #ece6e6; font-weight: 600; }
.title { font-weight: 800; letter-spacing: .14em; font-size: 1.5rem; color: #ece6e6; }
.title b { color: #ff3b3b; }
.pill { display:inline-block; padding:2px 10px; margin:0 6px 6px 0; border:1px solid #5a1a1a;
        border-radius:999px; font-size:.68rem; letter-spacing:.1em; color:#ff7b7b; font-weight:600; }
.pill.off { color:#8a7a7a; border-color:#3a2a2a; }
.sev { padding:4px 14px; border-radius:5px; font-weight:800; letter-spacing:.14em; font-size:.8rem; }
.sev-CRITICAL { background:#ff3b3b; color:#070505; }
.sev-HIGH { background:#ff7a1a; color:#070505; }
.sev-MEDIUM { background:#ffb020; color:#070505; }
.sev-LOW { background:#3a6b3a; color:#ece6e6; }
.h { font-size:.72rem; letter-spacing:.14em; color:#ff5b5b; font-weight:700; margin:.2rem 0 .4rem; }
.stage { border:1px solid #5a1a1a; border-radius:8px; padding:10px 12px; background:#150a0c; height:100%; }
.stage b { color:#ff7b7b; font-size:.75rem; letter-spacing:.1em; display:block; margin-bottom:4px; }
.stage.last { background:#4a0a12; border-color:#ff3b3b; }
.stage span { font-size:.78rem; color:#d8cccc; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

SUGGEST = ["What should I do first?", "Explain the credential theft", "Summarize this incident in 2 sentences"]
HOST = "WS-04"

try:
    raw = R.load_chain()
except FileNotFoundError:
    st.error("data/chain.json not found. Run the chain.py incident command first, "
             "and start the app from the soc-ai-project folder.")
    st.stop()
a = R.analyze(raw)


# ---------- helpers that run in code (no LLM, so they cannot invent facts) ----------
def exe_name(n):
    return str(n["exe"]).replace("/", "\\").split("\\")[-1] or "unknown.exe"


def internal_ips():
    pat = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
    found = []
    for n in a["nodes"]:
        for ip in pat.findall(n["cmd"]):
            if ip not in found:
                found.append(ip)
    return found


def decode_answer():
    out = []
    for n in a["nodes"]:
        for m in re.finditer(r"(?i)-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", n["cmd"]):
            try:
                text = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16le")
            except Exception:
                continue
            out.append((n, text))
    if not out:
        return "No base64-encoded PowerShell commands were found in the flagged processes of this incident."
    parts = ["Decoded " + str(len(out)) + " encoded command(s):"]
    for n, text in out[:3]:
        parts.append("**Stage " + str(n["stage"]) + "** (`" + exe_name(n) + "`)\n```\n" + text[:600] + "\n```")
    return "\n\n".join(parts)


def sigma_answer():
    n = max(a["nodes"], key=lambda x: x["prob"])
    toks = [t for t in re.split(r"\s+", n["cmd"].lower()) if len(t) > 5 and "\\" not in t][:2]
    tags = ["attack." + t["id"].lower() for t in n["attack_tags"]]
    rule = ["title: Sentrix draft - suspicious " + exe_name(n), "status: experimental",
            "logsource:", "  category: process_creation", "  product: windows", "detection:",
            "  selection:", "    Image|endswith: '\\" + exe_name(n).lower() + "'"]
    if toks:
        rule.append("    CommandLine|contains:")
        rule += ["      - '" + t.replace("'", "") + "'" for t in toks]
    rule += ["  condition: selection", "level: high"]
    if tags:
        rule += ["tags:"] + ["  - " + t for t in tags]
    return ("Draft Sigma rule from the highest-scoring process (stage " + str(n["stage"]) + ", score "
            + str(n["prob"]) + "). Test it on benign data before using it; it will need tuning.\n```yaml\n"
            + "\n".join(rule) + "\n```")


def log_action(kind, detail, command):
    st.session_state["actions"].append({"time": datetime.now().strftime("%H:%M:%S"),
                                        "action": kind, "detail": detail, "command": command})


def fresh_chat():
    return [{"role": "assistant",
             "content": "Incident loaded. Here is the case file.\n\n" + R.report_markdown(a)}]


if "messages" not in st.session_state:
    st.session_state["messages"] = fresh_chat()
if "actions" not in st.session_state:
    st.session_state["actions"] = []

# ---------- sidebar ----------
models = R.ollama_models()
with st.sidebar:
    st.markdown('<div class="brand">◢◤ SENTRIX<span> // AI</span></div>', unsafe_allow_html=True)
    pills = '<span class="pill">● SYSTEM ONLINE</span>'
    pills += ('<span class="pill">● LLM ONLINE</span>' if models
              else '<span class="pill off">○ LLM OFFLINE</span>')
    st.markdown(pills, unsafe_allow_html=True)
    if not models:
        st.caption("Open the Ollama app, then reload this page.")
    model = st.selectbox("Model", models or ["llama3.2:3b"])
    st.divider()
    st.markdown('<div class="h">INCIDENT</div>', unsafe_allow_html=True)
    st.selectbox("Loaded incident", ["Demo incident - " + str(len(a["stages"])) + " stages"],
                 label_visibility="collapsed")
    if st.button("+ New chat"):
        st.session_state["messages"] = fresh_chat()
        st.rerun()
    st.download_button("Download report (.md)", R.report_markdown(a), file_name="sentrix_report.md")
    st.divider()
    st.markdown('<div class="h">QUICK ACTIONS (simulated)</div>', unsafe_allow_html=True)
    if st.button("Isolate " + HOST, type="primary"):
        log_action("Isolate host", HOST, 'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound   (or use your EDR isolate button)')
        st.toast("Logged: isolate " + HOST)
    ips = internal_ips()
    if st.button("Block " + (ips[0] if ips else "IP"), disabled=not ips):
        log_action("Block IP", ips[0], 'netsh advfirewall firewall add rule name="Sentrix block ' + ips[0]
                   + '" dir=out action=block remoteip=' + ips[0])
        st.toast("Logged: block " + ips[0])
    if st.button("Reset credentials"):
        log_action("Reset credentials", HOST, "Force password reset for every account logged on to " + HOST
                   + " during the LSASS dump window")
        st.toast("Logged: credential reset")
    st.divider()
    st.caption("Detector: random forest on process behaviour. On techniques it had never seen: "
               "precision 0.86, recall 0.72. Facts come from code; the AI only explains them. "
               "Actions above are simulated: they log the action and show the command to run.")

# ---------- header ----------
c1, c2 = st.columns([5, 1])
c1.markdown('<div class="title">SENTRIX <b>//</b> SOC ANALYST AI</div>', unsafe_allow_html=True)
c2.markdown('<div style="text-align:right"><span class="sev sev-' + a["severity"] + '">'
            + a["severity"] + "</span></div>", unsafe_allow_html=True)

n_flag = len(a["nodes"])
m1, m2, m3, m4 = st.columns(4)
m1.metric("Stages", len(a["stages"]))
m2.metric("Flagged processes", n_flag)
m3.metric("Highest score", max(n["prob"] for n in a["nodes"]))
m4.metric("Internal targets", len(internal_ips()))

tab_chat, tab_chain, tab_ev, tab_log = st.tabs(["CHAT", "ATTACK CHAIN", "EVIDENCE", "ACTION LOG"])

queued = None  # (kind, label)
with tab_chat:
    for m in st.session_state["messages"]:
        with st.chat_message(m["role"], avatar=BOT if m["role"] == "assistant" else USER):
            st.markdown(m["content"])
    st.markdown('<div class="h">TRY</div>', unsafe_allow_html=True)
    cols = st.columns(5)
    for col, q in zip(cols[:3], SUGGEST):
        if col.button(q, key="s_" + q):
            queued = ("llm", q)
    if cols[3].button("Decode command"):
        queued = ("decode", "Decode any encoded command")
    if cols[4].button("Write Sigma rule"):
        queued = ("sigma", "Write a Sigma rule for the top detection")

typed = st.chat_input("Ask Sentrix about this incident...")
if typed:
    queued = ("llm", typed)

if queued:
    kind, text = queued
    st.session_state["messages"].append({"role": "user", "content": text})
    if kind == "llm":
        with tab_chat:
            with st.chat_message("user", avatar=USER):
                st.markdown(text)
            with st.chat_message("assistant", avatar=BOT):
                hist = [{"role": m["role"], "content": m["content"]}
                        for m in st.session_state["messages"][1:]][-6:]
                msgs = [{"role": "system", "content": R.system_prompt(a)}] + hist
                answer = st.write_stream(R.llm_stream(msgs, model))
        st.session_state["messages"].append({"role": "assistant", "content": answer})
    else:
        answer = decode_answer() if kind == "decode" else sigma_answer()
        st.session_state["messages"].append({"role": "assistant", "content": answer})
        st.rerun()

with tab_chain:
    st.markdown('<div class="h">ATTACK FLOW</div>', unsafe_allow_html=True)
    scols = st.columns(len(a["stages"]))
    for i, (col, s) in enumerate(zip(scols, a["stages"])):
        techs = []
        for n in s["nodes"]:
            for t in n["attack_tags"]:
                lab = t["id"] + " " + t["name"]
                if lab not in techs:
                    techs.append(lab)
        last = " last" if i == len(a["stages"]) - 1 else ""
        col.markdown('<div class="stage' + last + '"><b>STAGE ' + str(s["stage"]) + "</b><span>"
                     + "<br>".join(techs[:3] or ["no rule match"]) + "</span></div>", unsafe_allow_html=True)
    st.caption("Each box is one stage, labelled with the MITRE ATT&CK techniques the rules matched.")
    for s in a["stages"]:
        title = ("Stage " + str(s["stage"]) + "  |  " + (", ".join(s["tactics"]) or "unclassified")
                 + "  |  " + str(s["n"]) + " processes  |  top score " + str(s["top"]))
        with st.expander(title):
            for n in s["nodes"]:
                st.code(n["cmd"], language="bash")
                tg = ", ".join(t["id"] + " " + t["name"] for t in n["attack_tags"]) or "no rule match"
                st.caption("score " + str(n["prob"]) + "  |  " + n["tier"] + "  |  " + tg)

with tab_ev:
    rows = [{"stage": n["stage"], "score": n["prob"], "tier": n["tier"], "process": n["exe"],
             "techniques": ", ".join(t["id"] for t in n["attack_tags"]),
             "command": n["cmd"][:160]} for n in a["nodes"]]
    df = pd.DataFrame(rows).sort_values(["stage", "score"], ascending=[True, False])
    st.dataframe(df, hide_index=True)

with tab_log:
    if not st.session_state["actions"]:
        st.caption("No actions yet. Use QUICK ACTIONS in the sidebar. They are simulated: "
                   "each one logs here and shows the command you would run.")
    for x in reversed(st.session_state["actions"]):
        st.markdown("**" + x["time"] + "**  |  " + x["action"] + "  |  " + x["detail"])
        st.code(x["command"], language="bash")