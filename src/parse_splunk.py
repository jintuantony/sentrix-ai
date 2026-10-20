import glob, os
import xml.etree.ElementTree as ET
import pandas as pd

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
fields = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
          "ProcessId", "ParentProcessId", "SourceIp", "DestinationIp",
          "DestinationPort", "SourceImage", "TargetImage", "TargetObject",
          "TargetFilename", "ProcessGuid", "ParentProcessGuid",
          "SourceProcessGUID", "TargetProcessGUID", "GrantedAccess", "QueryName"]

rows = []
bad = 0
for path in sorted(glob.glob("data/splunk/*.log")):
    name = os.path.basename(path).rsplit(".", 1)[0]
    technique = name.split("__")[0]
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("<Event"):
                continue
            try:
                root = ET.fromstring(line)
                s = root.find(NS + "System")
                r = {
                    "Hostname": s.findtext(NS + "Computer"),
                    "Channel": s.findtext(NS + "Channel"),
                    "EventID": int(s.findtext(NS + "EventID")),
                    "@timestamp": s.find(NS + "TimeCreated").attrib.get("SystemTime"),
                }
                data = {d.attrib.get("Name"): d.text for d in root.iter(NS + "Data")}
            except Exception:
                bad += 1
                continue
            for c in fields:
                r[c] = data.get(c)
            r["NewProcessName"] = None
            r["ParentProcessName"] = None
            r["attack_file"] = name
            r["technique"] = technique
            rows.append(r)

df = pd.DataFrame(rows)
for c in ["Image", "CommandLine", "ParentImage", "SourceImage", "TargetImage",
          "TargetFilename", "TargetObject"]:
    df[c] = df[c].astype("string").str.lower()

df.to_csv("data/splunk_events.csv", index=False)

print("Rows:", len(df), "| unparsed lines:", bad)
print("Rows with ProcessGuid:", int(df["ProcessGuid"].notna().sum()))