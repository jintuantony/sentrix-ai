import json
import re
import urllib.request

OLLAMA = "http://localhost:11434"

TACTICS = ["Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery",
           "Lateral Movement", "Command and Control", "Impact"]
PRIORITY = ["Impact", "Lateral Movement", "Credential Access", "Persistence",
            "Command and Control", "Defense Evasion", "Execution", "Discovery"]
PLAY = {
    "T1003": "Treat every account that logged on to this host as compromised: reset passwords and rotate service credentials. Check whether memory dump files (.dmp) were copied off the host.",
    "T1021": "Check the internal host(s) listed under indicators for the same activity. Remote execution means the attacker may already be on them.",
    "T1105": "Block the download URLs and domains listed under indicators at the proxy or firewall, and look for the downloaded files on disk.",
    "T1547.001": "Remove the registry run key and check other autostart locations on the host.",
    "T1053.005": "List and remove the scheduled tasks the attacker created.",
    "T1486": "Confirm backups are intact before restoring anything, and check which files were encrypted.",
    "T1490": "Shadow copies or backups may have been deleted, so check backups first.",
    "T1218.005": "Inspect the script that mshta loaded, and check its parent process and file path.",
    "T1218.011": "Inspect the DLL that rundll32 loaded, and check its parent process and file path.",
    "T1218.010": "Inspect the file that regsvr32 loaded, and check its parent process and file path.",
    "T1027": "Decode the encoded PowerShell commands to see exactly what they ran.",
    "T1047": "Check WMI activity on this host and on the target machines.",
    "T1036": "Look for system file names (such as svchost.exe) running from unusual folders.",
    "T1070.001": "Treat local logs as unreliable and pull copies from the central log store.",
    "T1562.001": "Re-enable and verify the security tools, and review any exclusions that were added.",
    "T1136.001": "Disable and investigate the newly created account.",
}


def load_chain(path="data/chain.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def is_private(ip):
    a, b = [int(x) for x in ip.split(".")[:2]]
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def analyze(raw):
    nodes = raw["nodes"]
    nfiles = len(raw.get("files", []))

    tags = {}
    for n in nodes:
        for t in n["attack_tags"]:
            e = tags.setdefault(t["id"], {"name": t["name"], "tactic": t["tactic"], "stages": set()})
            e["stages"].add(n["stage"])
    ordered = sorted(tags, key=lambda i: (PRIORITY.index(tags[i]["tactic"]), i))

    tactics = {e["tactic"] for e in tags.values()}
    if "Impact" in tactics or {"Credential Access", "Lateral Movement"} <= tactics:
        severity = "CRITICAL"
    elif "Credential Access" in tactics or "Lateral Movement" in tactics or len(tactics) >= 3:
        severity = "HIGH"
    elif tactics:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    reason = "Tactics observed: " + ", ".join(t for t in TACTICS if t in tactics) + "."

    stages, timeline = [], []
    for st in sorted({n["stage"] for n in nodes}):
        sn = sorted([n for n in nodes if n["stage"] == st], key=lambda n: -n["prob"])
        parts, tg_list, tac_list = [], [], []
        for tac in TACTICS:
            items = sorted(i + " " + e["name"] for i, e in tags.items()
                           if st in e["stages"] and e["tactic"] == tac)
            if items:
                parts.append(tac + ": " + ", ".join(items))
                tg_list += items
                tac_list.append(tac)
        top = sn[0]["prob"]
        timeline.append("Stage " + str(st) + " - " + ("; ".join(parts) if parts else
                        "suspicious process activity, no rule match (model score " + str(top) + ")"))
        stages.append({"stage": st, "tags": tg_list, "tactics": tac_list, "top": top,
                       "n": sum(n["count"] for n in sn), "nodes": sn[:3]})

    chosen, used = [], set()
    for i in ordered:
        c = [n for n in nodes if any(t["id"] == i for t in n["attack_tags"])]
        if c:
            n = max(c, key=lambda x: x["prob"])
            if n["guid"] not in used:
                chosen.append(n)
                used.add(n["guid"])
    for n in sorted(nodes, key=lambda x: -x["prob"]):
        if len(chosen) >= 6:
            break
        if n["guid"] not in used:
            chosen.append(n)
            used.add(n["guid"])
    evidence = []
    for n in chosen[:6]:
        cmd = n["cmd"][:200] + (" ..." if len(n["cmd"]) > 200 else "")
        evidence.append("[stage " + str(n["stage"]) + ", score " + str(n["prob"]) + "] " + cmd)

    blob = " ".join(n["cmd"] for n in nodes) + " " + " ".join(a for n in nodes for a in n["actions"])
    ips = sorted({x for x in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob)
                  if not x.startswith(("127.", "0."))})
    internal = [x for x in ips if is_private(x)]
    external = [x for x in ips if not is_private(x)]
    hosts = sorted(set(re.findall(r"https?://([^/\s'\"]+)", blob)) | set(re.findall(r"dns -> (\S+)", blob)))
    github = any("githubusercontent" in h or h.endswith("github.com") for h in hosts)
    ext_note = (" (GitHub's servers: raw.githubusercontent.com is a public file host, "
                "not necessarily attacker infrastructure)") if (github and external) else ""

    steps = []
    if severity in ("CRITICAL", "HIGH"):
        steps.append("Escalate to a senior analyst now (severity " + severity + ").")
    if severity == "CRITICAL":
        steps.append("Isolate this host from the network while you investigate.")
    for i in ordered:
        if i in PLAY and PLAY[i] not in steps:
            steps.append(PLAY[i])

    return {"nodes": nodes, "nfiles": nfiles, "severity": severity, "reason": reason,
            "timeline": timeline, "stages": stages, "evidence": evidence, "internal": internal,
            "external": external, "ext_note": ext_note, "hosts": hosts, "steps": steps[:9],
            "tags": tags}


def report_markdown(a, summary=None):
    out = ["**Severity: " + a["severity"] + "** - " + a["reason"], ""]
    if a["nfiles"] > 1:
        out += ["_Demo incident assembled from " + str(a["nfiles"]) + " public datasets, not one real attack._", ""]
    if summary:
        out += ["### Summary", summary, ""]
    out += ["### Timeline"] + ["- " + t for t in a["timeline"]]
    out += ["", "### Key evidence (exact commands)"] + ["- `" + e + "`" for e in a["evidence"]]
    out += ["", "### Indicators",
            "- Internal hosts (possible lateral-movement targets): " + (", ".join(a["internal"]) or "none observed"),
            "- External IPs: " + (", ".join(a["external"]) or "none observed") + a["ext_note"],
            "- Domains: " + (", ".join(a["hosts"][:8]) or "none observed")]
    out += ["", "### Recommended next steps"] + [str(k + 1) + ". " + s for k, s in enumerate(a["steps"])]
    out += ["", "### What could not be determined from this data",
            "- Which account was used and how the attacker first got in.",
            "- Host name and whether data left the network.",
            "- The detection model catches about 3 in 4 attacks it has not seen, so some activity may be missing."]
    return "\n".join(out)


def facts_text(a):
    lines = ["Severity: " + a["severity"] + ". " + a["reason"], "Timeline:"] + a["timeline"]
    for s in a["stages"]:
        lines.append("Stage " + str(s["stage"]) + " top commands:")
        for n in s["nodes"]:
            lines.append("  (score " + str(n["prob"]) + ") " + n["cmd"][:150])
    lines.append("Internal hosts targeted: " + (", ".join(a["internal"]) or "none"))
    lines.append("External IPs: " + (", ".join(a["external"]) or "none") + a["ext_note"])
    lines.append("Domains: " + (", ".join(a["hosts"][:8]) or "none"))
    lines.append("Recommended steps:")
    lines += ["  " + str(k + 1) + ". " + s for k, s in enumerate(a["steps"])]
    return "\n".join(lines)


def system_prompt(a):
    return ("You are Sentrix, an assistant for Level 1 SOC analysts. Answer ONLY from the incident "
            "facts below. Quote commands exactly. If the facts do not contain the answer, say "
            "'That is not in the data I have' and suggest what to check next. Keep answers short "
            "(under 120 words) and practical. The detector is not perfect, so say so if asked about "
            "confidence.\n\nINCIDENT FACTS:\n" + facts_text(a))


def ollama_models():
    try:
        with urllib.request.urlopen(OLLAMA + "/api/tags", timeout=1.5) as r:
            return [m["name"] for m in json.load(r).get("models", [])]
    except Exception:
        return None


def llm_stream(messages, model):
    payload = json.dumps({"model": model, "stream": True, "options": {"temperature": 0.2},
                          "messages": messages}).encode()
    req = urllib.request.Request(OLLAMA + "/api/chat", data=payload,
                                headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            for line in r:
                if not line.strip():
                    continue
                piece = json.loads(line)
                text = piece.get("message", {}).get("content", "")
                if text:
                    yield text
                if piece.get("done"):
                    break
    except Exception as e:
        yield "\n\n[Could not reach the AI model: " + str(e) + ". Open the Ollama app and try again.]"


def llm_once(messages, model):
    return "".join(llm_stream(messages, model))


def stage_dot(a):
    lines = ["digraph G {", "rankdir=LR;", 'bgcolor="transparent";',
             'node [shape=box, style="filled,rounded", fontname="Courier", fontsize=11, '
             'fontcolor="#f2e9e9", color="#ff2d2d", fillcolor="#1a0d10", penwidth=1.4];',
             'edge [color="#ff2d2d", arrowsize=0.8];']
    for s in a["stages"]:
        body = "\\n".join(t[:34] for t in s["tags"][:4]) or "(no rule match)"
        fill = "#5a0a14" if "Impact" in s["tactics"] else "#1a0d10"
        lines.append('s%d [label="STAGE %d\\n%s", fillcolor="%s"];' % (s["stage"], s["stage"], body, fill))
    for x, y in zip(a["stages"], a["stages"][1:]):
        lines.append("s%d -> s%d;" % (x["stage"], y["stage"]))
    lines.append("}")
    return "\n".join(lines)