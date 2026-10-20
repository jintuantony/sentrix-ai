import csv
import json
import urllib.request

TREE = "https://api.github.com/repos/splunk/attack_data/git/trees/master?recursive=1"
MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
techs = ["T1059.003", "T1105", "T1486", "T1547.001", "T1218.011", "T1218.005",
         "T1218.010", "T1562.001", "T1070.001", "T1112", "T1136.001",
         "T1110.001", "T1055.001", "T1546.003", "T1197", "T1197.001"]


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "sentrix"})
    return urllib.request.urlopen(req, timeout=60)


def size_mb(path):
    try:
        r = get(MEDIA + path, {"Range": "bytes=0-0", "User-Agent": "sentrix"})
        cr = r.headers.get("Content-Range", "")
        total = cr.split("/")[-1] if "/" in cr else r.headers.get("Content-Length")
        return round(int(total) / 1e6, 1)
    except Exception:
        return None


data = json.load(get(TREE))
print("truncated:", data.get("truncated"), "| entries:", len(data["tree"]))
paths = [e["path"] for e in data["tree"] if e["type"] == "blob"]
base = "datasets/attack_techniques/"
rows = []
for t in techs:
    hits = [p for p in paths if p.startswith(base + t + "/")
            and p.endswith((".log", ".json", ".evtx"))]
    print("==", t, "-", len(hits), "files")
    for p in hits:
        mb = size_mb(p)
        short = p[len(base + t) + 1:]
        print("  ", (str(mb) + " MB").ljust(10), short[:80])
        rows.append([t, short, mb, MEDIA + p])

with open("data/dataset_urls.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["technique", "path", "mb", "url"])
    w.writerows(rows)
print()
print("saved", len(rows), "files to data/dataset_urls.csv")