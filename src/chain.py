import json
import re
import sys

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from features import build

args = sys.argv[1:]
brief = "--brief" in args
names = [a for a in args if not a.startswith("--")] or ["T1047__lateral_movement__windows-sysmon"]
techs = {n.split("__")[0] for n in names}
stage_of = {n: i + 1 for i, n in enumerate(names)}


def say(*a):
    if not brief:
        print(*a)


df = pd.read_csv("data/splunk_labeled.csv", low_memory=False)
for c in ["ProcessGuid", "ParentProcessGuid", "CommandLine", "Image", "ParentImage",
          "DestinationIp", "QueryName", "TargetFilename", "TargetObject"]:
    df[c] = df[c].fillna("").astype(str)
df["port"] = pd.to_numeric(df["DestinationPort"], errors="coerce").fillna(0).astype(int).astype(str)

allp = df[df["EventID"] == 1].reset_index(drop=True)
train = allp[~allp["technique"].isin(techs)]
X, top = build(train)
model = RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                               random_state=1, n_jobs=-1).fit(X, train["is_attack"].values)

target = allp[allp["attack_file"].isin(names)].drop_duplicates("ProcessGuid").reset_index(drop=True)
target = target[target["ProcessGuid"] != ""].reset_index(drop=True)
Xt, _ = build(target, top)
target["prob"] = model.predict_proba(Xt[X.columns])[:, 1]
target["stage"] = target["attack_file"].map(stage_of)
target["exe"] = target["Image"].str.extract(r"([^\\]+)$")[0].fillna("")
target["pexe"] = target["ParentImage"].str.extract(r"([^\\]+)$")[0].fillna("")

NOISE = {"csc.exe", "cvtres.exe", "conhost.exe", "splunk.exe", "splunkd.exe",
         "btool.exe", "sandcat.exe"}
BASE_PARENTS = {"services.exe", "svchost.exe", "wininit.exe", "smss.exe"}
bare = target["CommandLine"].str.fullmatch(r'"?c:\\windows\\system32\\[^\\ ]+\.exe"?\s*').fillna(False).astype(bool)
suppressed = target["exe"].isin(NOISE) | (bare & target["pexe"].isin(BASE_PARENTS))
target["flag"] = (target["prob"] >= 0.3) & ~suppressed

RULES = [
    (r"-enc\b|-encodedcommand|-e\s+[a-z0-9+/=]{20,}", "T1027", "Encoded command", "Defense Evasion"),
    (r"downloadstring|downloadfile|urlcache|verifyctl|bitsadmin.*/transfer|invoke-webrequest|curl .*http|certutil.*/url", "T1105", "Ingress tool transfer", "Command and Control"),
    (r"lsass|procdump|mimikatz|sekurlsa|comsvcs|pypykatz|wce\.exe|dumpert|reg\s+save\s+hklm\\(sam|security|system)", "T1003", "Credential dumping", "Credential Access"),
    (r"schtasks.*/create|onlogon|onstart", "T1053.005", "Scheduled task", "Persistence"),
    (r"^(?!.*reg\s+delete).*(currentversion\\run|runonce)", "T1547.001", "Registry run key", "Persistence"),
    (r"wmic.*process call create|invoke-wmimethod|win32_process", "T1047", "WMI execution", "Execution"),
    (r"mshta", "T1218.005", "Mshta proxy execution", "Defense Evasion"),
    (r"rundll32", "T1218.011", "Rundll32 proxy execution", "Defense Evasion"),
    (r"regsvr32", "T1218.010", "Regsvr32 proxy execution", "Defense Evasion"),
    (r"copy\s+c:\\windows\\system32\\cmd\.exe\s+c:\\svchost", "T1036", "Masquerading as svchost", "Defense Evasion"),
    (r"vssadmin.*delete|wbadmin.*delete|bcdedit", "T1490", "Inhibit system recovery", "Impact"),
    (r"dcrypt|cipher\s+/w|manage-bde", "T1486", "Data encrypted for impact", "Impact"),
    (r"wevtutil.*\bcl\b|clear-eventlog", "T1070.001", "Clear event logs", "Defense Evasion"),
    (r"add-mppreference|set-mppreference|disablerealtime|windefend", "T1562.001", "Impair defenses", "Defense Evasion"),
    (r"net\s+user .*/add", "T1136.001", "Create account", "Persistence"),
    (r"/s\s+\d{1,3}\.\d|-cn\s|/node:|\\\\\d+\.\d+", "T1021", "Remote execution on another host", "Lateral Movement"),
    (r"whoami|hostname|systeminfo|ipconfig|nltest", "T1082", "System/user discovery", "Discovery"),
]
TACTICS = ["Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery",
           "Lateral Movement", "Command and Control", "Impact"]


def tags(cmd):
    return [(i, n, t) for rx, i, n, t in RULES if re.search(rx, cmd)]


acts = {}
d = df[df["attack_file"].isin(names)]
for _, r in d[d["EventID"].isin([3, 22, 11, 13])].iterrows():
    g = r["ProcessGuid"]
    if r["EventID"] == 3 and r["DestinationIp"]:
        line = "network -> " + r["DestinationIp"] + ":" + r["port"]
    elif r["EventID"] == 22 and r["QueryName"]:
        line = "dns -> " + r["QueryName"]
    elif r["EventID"] == 11 and r["TargetFilename"] and "__psscriptpolicytest" not in r["TargetFilename"]:
        line = "file created -> " + r["TargetFilename"][:70]
    elif r["EventID"] == 13 and r["TargetObject"]:
        line = "registry set -> " + r["TargetObject"][:70]
    else:
        continue
    acts.setdefault(g, [])
    if line not in acts[g]:
        acts[g].append(line)

info = target.set_index("ProcessGuid").to_dict("index")
flagged = {g for g, r in info.items() if r["flag"]}

parent_of, via_of = {}, {}
for g in flagged:
    cur = info[g]["ParentProcessGuid"]
    via = []
    for _ in range(60):
        if cur in info and cur not in flagged:
            via.append(info[cur]["exe"])
            cur = info[cur]["ParentProcessGuid"]
        else:
            break
    parent_of[g] = cur if cur in flagged else ""
    if not via and info[g]["pexe"]:
        via = [info[g]["pexe"]]
    via_of[g] = via[:2]

kids_of = {}
for g in flagged:
    kids_of.setdefault(parent_of[g], []).append(g)


def sk(g):
    return (info[g]["stage"], str(info[g]["@timestamp"]))


real = target[target["is_attack"] == 1]
hi = int(((target["flag"]) & (target["prob"] >= 0.7)).sum())
rev = int(((target["flag"]) & (target["prob"] < 0.7)).sum())
print("INCIDENT:", len(names), "dataset(s) | model never saw:", ", ".join(sorted(techs)))
print("processes:", len(target), "| flagged: HIGH", hi, "+ REVIEW", rev,
      "| suppressed as baseline:", int((suppressed & (target["prob"] >= 0.3)).sum()),
      "| real attacks caught:", int(real["flag"].sum()), "of", len(real))
print()
for n in names:
    t = target[target["attack_file"] == n]
    tr = t[t["is_attack"] == 1]
    print("  stage", stage_of[n], n[:55].ljust(55), "flagged", int(t["flag"].sum()),
          "| caught", int(tr["flag"].sum()), "of", len(tr))

summary = {}
for g in flagged:
    st = info[g]["stage"]
    for i, n, t in tags(info[g]["CommandLine"].lower()):
        summary.setdefault(st, {})
        summary[st][(t, i, n)] = summary[st].get((t, i, n), 0) + 1
print()
print("KILL-CHAIN SUMMARY (stage order)")
for st in sorted(summary):
    for tac in TACTICS:
        items = [(i, n, c) for (t, i, n), c in summary[st].items() if t == tac]
        if items:
            print("  stage", st, tac.ljust(20), ", ".join(i + " " + n + " x" + str(c) for i, n, c in items))
print()


def collapse(nodes):
    groups, out_list = {}, []
    for k in nodes:
        if k not in kids_of:
            groups.setdefault((info[k]["exe"], info[k]["CommandLine"][:60]), []).append(k)
        else:
            out_list.append((k, 1))
    for lst in groups.values():
        out_list.append((lst[0], len(lst)))
    return sorted(out_list, key=lambda x: sk(x[0]))


out = []


def show(n, depth, cnt):
    r = info[n]
    pr = r["prob"]
    tier = "HIGH" if pr >= 0.7 else "REVIEW"
    pad = "    " * depth
    tg = tags(r["CommandLine"].lower())
    label = "; ".join(i + " " + n2 + " (" + t + ")" for i, n2, t in tg)
    head = pad + "[" + format(pr, ".2f") + " " + tier + "] " + r["exe"] + ("  x" + str(cnt) if cnt > 1 else "")
    say(head + ("  <- " + label if label else ""))
    if depth == 0 and via_of[n]:
        say(pad + "    launched via: " + " <- ".join(via_of[n]))
    say(pad + "    cmd: " + r["CommandLine"][:110])
    for line in acts.get(n, [])[:3]:
        say(pad + "    " + line)
    out.append({"guid": n, "parent": parent_of[n], "stage": int(r["stage"]), "source": r["attack_file"],
                "prob": round(float(pr), 3), "tier": tier, "exe": r["exe"], "count": cnt,
                "cmd": r["CommandLine"][:300], "launched_via": via_of[n],
                "attack_tags": [{"id": i, "name": n2, "tactic": t} for i, n2, t in tg],
                "actions": acts.get(n, [])[:6], "real_label": int(r["is_attack"])})
    for k, c in collapse(kids_of.get(n, [])):
        show(k, depth + 1, c)


for root, c in collapse(kids_of.get("", [])):
    show(root, 0, c)

with open("data/chain.json", "w", encoding="utf-8") as f:
    json.dump({"files": names, "nodes": out}, f, indent=1)
print("saved data/chain.json with", len(out), "nodes")