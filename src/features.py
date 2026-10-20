import pandas as pd

PATS = {
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
SHELLS = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"]


def build(p, top_exes=None):
    p = p.copy().reset_index(drop=True)
    for col in ["CommandLine", "Image", "ParentImage"]:
        p[col] = p[col].fillna("").astype(str)
    exe = p["Image"].str.extract(r"([^\\]+)$")[0].fillna("")
    pexe = p["ParentImage"].str.extract(r"([^\\]+)$")[0].fillna("")
    c = p["CommandLine"]

    X = pd.DataFrame(index=p.index)
    X["len"] = c.str.len()
    X["tokens"] = c.str.split().str.len().fillna(0)
    for name, pat in PATS.items():
        X[name] = c.str.contains(pat, regex=True).astype(int)
    X["parent_shell"] = pexe.isin(SHELLS).astype(int)
    X["parent_office"] = pexe.str.contains("winword|excel|outlook", regex=True).astype(int)

    if top_exes is None:
        top_exes = list(exe.value_counts().head(20).index)
    cat = exe.where(exe.isin(top_exes), "other")
    cols = ["exe_" + e for e in top_exes] + ["exe_other"]
    d = pd.get_dummies(cat, prefix="exe").reindex(columns=cols, fill_value=0).astype(int)
    return pd.concat([X, d], axis=1), top_exes