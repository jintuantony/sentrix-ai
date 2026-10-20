import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score

df = pd.read_csv("data/splunk_labeled.csv", low_memory=False)
p = df[df["EventID"] == 1].copy().reset_index(drop=True)
for col in ["CommandLine", "Image", "ParentImage"]:
    p[col] = p[col].fillna("").astype(str)
p["exe"] = p["Image"].str.extract(r"([^\\]+)$")[0].fillna("")
p["pexe"] = p["ParentImage"].str.extract(r"([^\\]+)$")[0].fillna("")
c = p["CommandLine"]

X = pd.DataFrame(index=p.index)
X["len"] = c.str.len()
X["tokens"] = c.str.split().str.len().fillna(0)
pats = {
    "enc": r"-e(?:nc|ncodedcommand|c)?\s+[a-z0-9+/=]{20,}",
    "url": r"https?://",
    "iex": r"\biex\b|invoke-expression",
    "download": r"downloadstring|downloadfile|invoke-webrequest|bitsadmin|urlcache",
    "bypass": r"-exec(?:utionpolicy)?\s+bypass",
    "hidden": r"-w(?:indowstyle)?\s+-?hidden",
    "ip": r"\d{1,3}(?:\.\d{1,3}){3}",
    "remote": r"/s\s+\d|-cn\s|/node:|\\\\\d",
    "persist": r"/create|onlogon|onstart|new-service",
    "dump": r"lsass|\.dmp|minidump|sekurlsa|hklm\\(?:sam|security|system)",
    "chain": r"&|\|",
    "scriptblock": r"\$|\{",
    "oddpath": r"\\temp\\|\\appdata\\|\\users\\public|\\programdata\\|\\downloads\\|atomicredteam",
}
for name, pat in pats.items():
    X[name] = c.str.contains(pat, regex=True).astype(int)
X["parent_shell"] = p["pexe"].isin(
    ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"]).astype(int)
X["parent_office"] = p["pexe"].str.contains("winword|excel|outlook", regex=True).astype(int)

top = p["exe"].value_counts().head(20).index
X = pd.concat([X, pd.get_dummies(p["exe"].where(p["exe"].isin(top), "other"),
                                 prefix="exe")], axis=1)

y = p["is_attack"].values
g = p["technique"].values
print("processes:", len(p), "| attacks:", int(y.sum()))
print()


def model():
    return RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                  random_state=1, n_jobs=-1)


print("TEST ON A TECHNIQUE THE MODEL NEVER SAW")
print("technique".ljust(12), "attacks", "caught", "false_alarms", "precision", "recall")
all_t, all_p = [], []
for tech in sorted(set(g)):
    te = g == tech
    if y[te].sum() == 0:
        continue
    m = model().fit(X[~te], y[~te])
    pred = m.predict(X[te])
    tp = int(((pred == 1) & (y[te] == 1)).sum())
    fp = int(((pred == 1) & (y[te] == 0)).sum())
    pr = precision_score(y[te], pred, zero_division=0)
    rc = recall_score(y[te], pred, zero_division=0)
    print(tech.ljust(12), str(int(y[te].sum())).ljust(7), str(tp).ljust(6),
          str(fp).ljust(12), round(pr, 2), " ", round(rc, 2))
    all_t += list(y[te]); all_p += list(pred)
print("OVERALL".ljust(12), "precision", round(precision_score(all_t, all_p, zero_division=0), 2),
      "recall", round(recall_score(all_t, all_p, zero_division=0), 2))

print()
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=1)
pred = model().fit(Xtr, ytr).predict(Xte)
print("RANDOM SPLIT (easier, for comparison): precision",
      round(precision_score(yte, pred, zero_division=0), 2),
      "recall", round(recall_score(yte, pred, zero_division=0), 2))

m = model().fit(X, y)
imp = pd.Series(m.feature_importances_, index=X.columns).sort_values(ascending=False)
print()
print("TOP FEATURES")
print(imp.head(12).round(3).to_string())