# s3_eval.py <model-key>... — detection at a fixed false-positive rate.
#
# Every method turns a text into ONE score (lower = more malicious), so each
# (model, corpus, method) gets its own threshold, calibrated on the CALIB half
# of the benign texts to a target FP rate, and is reported on the TEST half.
# Sentence methods calibrate each window size k separately (empirical
# percentile of the benign calib texts), then take the min over k.
import json, os, sys
import numpy as np, pandas as pd

OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
rows = {r["id"]: r for r in map(json.loads, open(f"{OUT}/texts.final.jsonl"))}
TOOL = {"bench:fp-units", "mcptox-clean"}
PROMPT = {"benign:trustair-regular", "benign:jackhhao-benign", "benign:deepset-benign"}
EMAIL = {"benign:llmail-fp-emails", "benign:bipia-emails"}
INJ_FIX = {"server instructions", "tool weather: description", "probe weather: output"}
UNSEEN = ["tensortrust", "mcptox-poisoned"]
OLD_SRC = ["deadbits-instruction-bypass", "deadbits-jailbreak"]

import re as _re, collections as _c
_sent = lambda t: [x.strip().lower() for x in _re.split(r"(?<=[.!?])\s+|\\n|\n", t) if len(x.split()) >= 5]
_A = {x for r in rows.values() if r["source"] == "mcptox-A" for x in _sent(r["text"])}
for r in rows.values():   # MCPTox test tools sharing an exact template sentence with a corpus server
    if r["source"] == "mcptox-poisoned" and any(x in _A for x in _sent(r["text"])):
        r["source"] = "mcptox-poisoned-tmpl"
MINW = int(os.environ.get("MINW", "0"))

def load(key):
    meta = json.load(open(f"{OUT}/{key}/meta.json"))
    dist = np.load(f"{OUT}/{key}/dist.npy").astype(np.float32)
    q = np.load(f"{OUT}/{key}/qmeta.npy")
    if MINW:   # drop short sentence windows (k>=1) on the query side
        qt = json.load(open(f"{OUT}/{key}/qtexts.json"))
        short = np.array([len(t.split()) < MINW for t in qt]) & (q[:, 2] >= 1)
        dist = dist.copy(); dist[short] = 9
    return meta, dist, q

def text_k_scores(q, s):
    """min score per (text, k) -> DataFrame index rid, columns k."""
    df = pd.DataFrame({"rid": q[:, 0], "k": q[:, 2], "s": s})
    return df.groupby(["rid", "k"]).s.min().unstack()

def evaluate(key, meta, dist, q, corpus_src, method, ks, gamma=0.0, target=0.02, calib_on="all", fixed=None, purity=0):
    groups = [tuple(g) for g in meta["groups"]]
    cw = [i for i, (s, kd, b) in enumerate(groups) if kd == 0 and s in corpus_src and b >= purity]
    skinds = (1,) if method == "hybrid1" else (1, 3)   # hybrid1: corpus single sentences only
    cs = [i for i, (s, kd, b) in enumerate(groups) if kd in skinds and s in corpus_src and b >= purity]
    cc = [i for i, (s, kd, b) in enumerate(groups) if kd == 2]
    if method == "whole":
        s = dist[:, cw].min(1)
    elif method in ("hybrid", "hybrid1"):   # chunk vs whole corpus texts; sentence windows vs corpus sentence windows
        s = np.where(q[:, 2] == 0, dist[:, cw].min(1), dist[:, cs].min(1) if cs else 9)
    else:
        s = dist[:, cw + cs].min(1)
    if gamma:
        s = s - gamma * dist[:, cc].min(1)
    T = text_k_scores(q, s)
    T = T[[k for k in ks if k in T.columns]]
    rid = T.index.values
    split = np.array([rows[i]["split"] for i in rid]); role = np.array([rows[i]["role"] for i in rid])
    src = np.array([rows[i]["source"] for i in rid])
    if calib_on == "tool":
        bc = (role == "ben") & (split == "calib") & np.isin(src, list(TOOL))
    else:
        bc = (role == "ben") & (split == "calib")
    if fixed is not None:          # raw distance threshold, no calibration (today's rule)
        score = T.min(1).values; thr = fixed; flag = score < thr
    else:
        P = np.ones(len(T))
        for k in T.columns:
            v = T[k].values
            ref = np.sort(v[bc & ~np.isnan(v)])
            p = np.searchsorted(ref, v, side="right") / bc.sum()
            p[np.isnan(v)] = 1.0
            P = np.minimum(P, p)
        ref = np.sort(P[bc])
        thr = ref[int(np.floor(target * len(ref)))] if len(ref) else 0
        flag = P < thr if thr > 0 else P <= 0
        score = P
    res = {}
    for name in sorted(set(src)):
        m = (src == name) & (split == "test")
        if m.any():
            res[name] = (int(flag[m].sum()), int(m.sum()))
    fx = [(rows[i]["meta"]["label"], rows[i]["source"], bool(f)) for i, f in zip(rid, flag) if rows[i]["role"] == "fix"]
    res["fix:evil-inj"] = (sum(f for l, s, f in fx if "evil" in s and l in INJ_FIX), 3)
    res["fix:benign"] = (sum(f for l, s, f in fx if "benign" in s), 9)
    return res

def pct(r, names):
    h = sum(r[n][0] for n in names if n in r); t = sum(r[n][1] for n in names if n in r)
    return 100.0 * h / t if t else float("nan")

def macro(r, names):
    v = [100.0 * r[n][0] / r[n][1] for n in names if n in r and r[n][1]]
    return sum(v) / len(v) if v else float("nan")

def summary(r, corpus_src):
    seen = [s for s in corpus_src if s in r and s not in OLD_SRC]
    return {"seen(macro)": macro(r, seen), "hackaprompt": pct(r, ["hackaprompt"]), "mosscap": pct(r, ["mosscap"]),
            "tensortrust": pct(r, ["tensortrust"]), "mcptox": pct(r, ["mcptox-poisoned", "mcptox-poisoned-tmpl"]), "mcptox nov": pct(r, ["mcptox-poisoned"]), "gen-test": pct(r, ["mcpgen-test"]),
            **{"emb:" + e[:6]: pct(r, ["embedded:" + e]) for e in ("hackaprompt", "llmail-inject-p2", "tensortrust", "gandalf-ignore", "mcptox-poisoned")},
            "FP tool": pct(r, TOOL), "FP prompt": pct(r, PROMPT), "FP email": pct(r, EMAIL),
            "fix inj/3": r["fix:evil-inj"][0], "fix ben/9": r["fix:benign"][0]}

METHODS = [  # name, method, ks, gamma, purity-bin
    ("whole", "whole", [0], 0, 0),
    ("sent0-4", "any", [0, 1, 2, 3, 4], 0, 0),
    ("sent0-4 p>=.2", "any", [0, 1, 2, 3, 4], 0, 1),
    ("sent0-4 p>=.3", "any", [0, 1, 2, 3, 4], 0, 2),
    ("sent0-4 p>=.3 con.5", "any", [0, 1, 2, 3, 4], 0.5, 2),
    ("sent0-2 p>=.3", "any", [0, 1, 2], 0, 2),
    ("sent1 p>=.3", "any", [1], 0, 2),
    ("hybrid 0+1", "hybrid", [0, 1], 0, 0),
    ("hybrid 0+1 s1", "hybrid1", [0, 1], 0, 0),
    ("hybrid 0+1 p>=q2", "hybrid", [0, 1], 0, 2),
    ("hybrid 0+1+2 p>=q2", "hybrid", [0, 1, 2], 0, 2),
    ("hybrid 0+1 p>=q2 con.5", "hybrid", [0, 1], 0.5, 2),
]
if __name__ == "__main__":
    keys = sys.argv[1:]
    target = float(os.environ.get("TARGET", "0.02")); calib_on = os.environ.get("CALIB", "tool")
    only = os.environ.get("CORPORA", "base20k,+hp,+hp+mc,+hp+mc+mcpA").split(",")
    out = []
    for key in keys:
        meta, dist, q = load(key)
        allsrc = sorted({g[0] for g in meta["groups"] if g[1] in (0, 1, 3)})
        GEN = ("mcpgen", "mcpgen-full")
        base = [s for s in allsrc if s not in ("hackaprompt", "mosscap", "mcptox-A") + GEN]
        hpmc = base + ["hackaprompt", "mosscap"]
        corpora = {"base20k": base, "+hp": base + ["hackaprompt"], "+hp+mc": hpmc,
                   "+hp+mc+mcpA": hpmc + ["mcptox-A"], "+hp+mc+gen": hpmc + ["mcpgen"],
                   "+hp+mc+genfull": hpmc + ["mcpgen-full"], "+hp+mc+gen+mcpA": hpmc + ["mcpgen", "mcptox-A"]}
        if key == "minilm":
            r = evaluate(key, meta, dist, q, OLD_SRC, "whole", [0], fixed=0.40)
            out.append({"model": key, "corpus": "deadbits", "method": "TODAY <0.40", **summary(r, OLD_SRC)})
        for cn in only:
            cs = corpora[cn]
            for mname, method, ks, g, pb in METHODS:
                r = evaluate(key, meta, dist, q, cs, method, ks, g, target, calib_on, purity=pb)
                out.append({"model": key, "corpus": cn, "method": mname, **summary(r, cs)})
    df = pd.DataFrame(out)
    pd.set_option("display.width", 320); pd.set_option("display.max_columns", 40)
    print(f"target FP {target:.0%} calibrated on {calib_on} benign (calib half); numbers on TEST half")
    print(df.round(0).to_string(index=False))
    df.to_csv(f"{OUT}/summary_{'-'.join(keys)}_{calib_on}_{target}.csv", index=False)
