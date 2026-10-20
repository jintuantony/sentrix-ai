import pandas as pd

df = pd.read_csv("data/splunk_events.csv", low_memory=False)
for c in ["ProcessGuid", "ParentProcessGuid", "SourceProcessGUID",
          "CommandLine", "Image"]:
    df[c] = df[c].fillna("").astype(str)

df["exe"] = df["Image"].str.extract(r"([^\\]+)$")[0].fillna("")
is1 = df["EventID"] == 1
p = df[is1].copy()
p["key"] = p["CommandLine"].str.slice(0, 70)
spread = p.groupby("key")["attack_file"].nunique()
p["spread"] = p["key"].map(spread)

noise = {"cvtres.exe", "csc.exe", "logonui.exe", "smss.exe", "dismhost.exe",
         "ngentask.exe", "firefox.exe", "nxlog.exe", "splunk.exe",
         "splunkd.exe", "conhost.exe", "taskhostw.exe", "svchost.exe",
         "wermgr.exe", "werfault.exe", "backgroundtaskhost.exe", "sandcat.exe"}
lolbins = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
           "schtasks.exe", "sc.exe", "wmic.exe", "rundll32.exe",
           "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
           "whoami.exe", "net.exe", "net1.exe", "reg.exe", "procdump.exe",
           "vssadmin.exe", "scrcons.exe", "msiexec.exe", "taskkill.exe",
           "netsh.exe", "curl.exe", "wevtutil.exe", "esentutl.exe"}
odd_path = (r"\\users\\|\\temp\\|\\appdata\\|\\downloads\\|\\programdata\\"
            r"|\\atomicredteam\\|^c:\\[^\\]+\.exe")
harness = (r"-executionpolicy bypass -c [a-z]{4,8}\s*$"
           r"|write-host [0-9a-f]{8}-[0-9a-f]{4}-"
           r"|start-sleep -seconds 2; exit")
benign = (r"appxdeploymentextensions|wininetplugin|iesetup\.dll|start menu"
          r"|msiexec\.exe /v\s*$"
          r"|^\"?c:\\windows\\system32\\windowspowershell\\v1\.0\\powershell\.exe\"?\s*$"
          r"|^\"c:\\windows\\system32\\cmd\.exe\"\s*$")

p["is_harness"] = p["CommandLine"].str.contains(harness, regex=True)

seed = p[(p["spread"] < 3) & (~p["exe"].isin(noise)) & (~p["is_harness"])]
seed = seed[seed["exe"].isin(lolbins) | seed["Image"].str.contains(odd_path, regex=True)]
seed = seed[~seed["CommandLine"].str.contains(benign, regex=True)]

bad = set(seed["ProcessGuid"]) - {""}
while True:
    kids = set(p[p["ParentProcessGuid"].isin(bad) & ~p["is_harness"]]["ProcessGuid"]) - {""}
    new = kids - bad
    if not new:
        break
    bad |= new

df["is_attack"] = (df["ProcessGuid"].isin(bad) |
                   df["SourceProcessGUID"].isin(bad)).astype(int)
df["label"] = df["technique"].where(df["is_attack"] == 1, "benign")
df.to_csv("data/splunk_labeled.csv", index=False)

print("seed processes:", len(seed), "| attack process GUIDs:", len(bad))
print("attack events:", int(df["is_attack"].sum()), "of", len(df))
print()
print(df.groupby("attack_file")["is_attack"].agg(["sum", "count"]).to_string())
print()
print("attack events by EventID:")
print(df[df["is_attack"] == 1]["EventID"].value_counts().to_string())