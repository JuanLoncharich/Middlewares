# s8_twosided.py — hybrid kNN where a window counts only if it is closer to the
# malicious neighbour than to the nearest benign contrast neighbour (optionally
# by a margin m: d_mal < d_con - m). Same calibration/report as s3_eval.
import os, sys, numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from s3_eval import load, text_k_scores, rows, TOOL, PROMPT, EMAIL, INJ_FIX
md, dist, q = load("e5-small-ml")
groups = [tuple(g) for g in md["groups"]]
EXCL = {"mcptox-A", "mcpgen"}
allsrc = sorted({g[0] for g in groups if g[1] in (0, 1, 3)} - EXCL)
cw = [i for i, (s, kd, b) in enumerate(groups) if kd == 0 and s in allsrc]
cs = [i for i, (s, kd, b) in enumerate(groups) if kd == 1 and s in allsrc]
cc = [i for i, (s, kd, b) in enumerate(groups) if kd == 2 and s in ("con:tools", "con:mcp")]
dm = np.where(q[:, 2] == 0, dist[:, cw].min(1), dist[:, cs].min(1)); dc = dist[:, cc].min(1)
for m in (None, 0.0, 0.01, 0.02):
    s = dm if m is None else np.where(dm < dc - m, dm, 9.0)
    T = text_k_scores(q, s)[[0, 1]]
    rid = T.index.values
    split = np.array([rows[i]["split"] for i in rid]); role = np.array([rows[i]["role"] for i in rid]); src = np.array([rows[i]["source"] for i in rid])
    bc = (role == "ben") & (split == "calib") & np.isin(src, list(TOOL))
    P = np.ones(len(T))
    for k in (0, 1):
        v = T[k].values; ref = np.sort(v[bc & ~np.isnan(v)])
        p = np.searchsorted(ref, v, side="right") / bc.sum(); p[np.isnan(v)] = 1.0; P = np.minimum(P, p)
    thr = np.sort(P[bc])[int(0.02 * bc.sum())]
    f = P < thr if thr > 0 else (P <= 0) & (T.min(1).values < 9)
    r = {n: 100 * f[(src == n) & (split == "test")].mean() for n in set(src) if ((src == n) & (split == "test")).any()}
    g = lambda ns: np.mean([r[n] for n in ns if n in r])
    fx = [(rows[i]["meta"]["label"], rows[i]["source"], bool(x)) for i, x in zip(rid, f) if rows[i]["role"] == "fix"]
    print(f"margin {m}: " + ", ".join(f"{k.replace('embedded:', 'emb:')[:14]} {r[k]:.0f}" for k in ("hackaprompt", "mosscap", "llmail-inject-p2", "tensortrust", "mcptox-poisoned", "mcpgen-test", "embedded:llmail-inject-p2", "embedded:tensortrust", "embedded:mcptox-poisoned") if k in r)
          + f" | FP tool {g(TOOL):.1f} prompt {g(PROMPT):.1f} email {g(EMAIL):.1f} | fixtures: evil hit {[l for l, s_, x in fx if 'evil' in s_ and x]} benign hit {[l for l, s_, x in fx if 'benign' in s_ and x]}")
