import csv
import shutil
import urllib.request
from pathlib import Path

want = [
    ("T1105", "atomic_red_team/windows-sysmon.log"),
    ("T1105", "atomic_red_team/windows-sysmon_curl.log"),
    ("T1105", "atomic_red_team/windows-sysmon_curl_upload.log"),
    ("T1059.003", "cmd_spawns_cscript/windows-sysmon.log"),
    ("T1059.003", "powershell_spawn_cmd/windows-sysmon.log"),
    ("T1059.003", "ryuk/windows-sysmon.log"),
    ("T1486", "sam_sam_note/windows-sysmon.log"),
    ("T1486", "dcrypt/windows-sysmon.log"),
    ("T1547.001", "atomic_red_team/windows-sysmon.log"),
    ("T1547.001", "atomic_red_team/t1547001-runonce.log"),
    ("T1218.011", "atomic_red_team/windows-sysmon.log"),
    ("T1218.005", "atomic_red_team/windows-sysmon.log"),
    ("T1218.010", "atomic_red_team/windows-sysmon.log"),
    ("T1562.001", "atomic_red_team/windows-sysmon.log"),
    ("T1562.001", "defender_exclusion_sysmon/sysmon.log"),
    ("T1070.001", "atomic_red_team/windows-sysmon.log"),
    ("T1112", "atomic_red_team/windows-sysmon.log"),
    ("T1112", "blackbyte/enablelinkedconnections/blackbyte_sysmon.log"),
    ("T1136.001", "atomic_red_team/windows-sysmon.log"),
    ("T1546.003", "atomic_red_team/windows-sysmon.log"),
]

with open("data/dataset_urls.csv", encoding="utf-8") as f:
    urls = {(r["technique"], r["path"]): r["url"] for r in csv.DictReader(f)}

out = Path("data/splunk")
out.mkdir(exist_ok=True)
for tech, path in want:
    url = urls.get((tech, path))
    if not url:
        print("NOT FOUND:", tech, path)
        continue
    parts = path.split("/")
    name = tech + "__" + "_".join(parts[:-1]) + "__" + Path(parts[-1]).stem + ".log"
    dest = out / name
    if dest.exists() and dest.stat().st_size > 10000:
        print("already have", name)
        continue
    req = urllib.request.Request(url, headers={"User-Agent": "sentrix"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as g:
        shutil.copyfileobj(r, g)
    print("ok", round(dest.stat().st_size / 1e6, 1), "MB", name)