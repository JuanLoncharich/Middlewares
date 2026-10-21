# s7_head.py — a trained head instead of nearest neighbour, on the same e5
# embeddings (cache E.npy). Positives: malicious corpus windows (whole + single
# sentences; generated MCP texts give their injection sentences); negatives:
# the benign contrast corpus (dolly, glaive tools, MCP registry/READMEs).
# Score of a text = max over its query windows (chunks k=0 and sentences k=1).
# Threshold calibrated on tool-like benign CALIB to TARGET FP; report on TEST.
#   HEAD=logreg|mlp EXCLUDE=src,src python s7_head.py
import json, os, sys, collections
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("CALIB", "tool")
from s3_eval import rows, TOOL, PROMPT, EMAIL

OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
D = f"{OUT}/e5-small-ml"
E = np.load(f"{D}/E.npy").astype(np.float32)
pos = {t: i for i, t in enumerate(json.load(open(f"{D}/strings.json")))}
meta = json.load(open(f"{D}/meta.json"))
qm = np.load(f"{D}/qmeta.npy"); qt = json.load(open(f"{D}/qtexts.json"))
TARGET = float(os.environ.get("TARGET", "0.02"))
EXCL = set(filter(None, os.environ.get("EXCLUDE", "mcptox-A,mcpgen-full").split(",")))
HEAD = os.environ.get("HEAD", "logreg")

X, y, w = [], [], []
for (src, kd, b), ts in zip(map(tuple, meta["groups"]), meta["gtexts"]):
    if kd == 3 or src in EXCL:
        continue
    lab = 0 if kd == 2 else 1
    for t in ts:
        X.append(pos[t]); y.append(lab)
X = E[np.array(X)]; y = np.array(y)
# balance: each malicious source weighs the same in total (mosscap/llmail are huge)
src_of = []
for (src, kd, b), ts in zip(map(tuple, meta["groups"]), meta["gtexts"]):
    if kd == 3 or src in EXCL:
        continue
    src_of += [src if kd != 2 else "con"] * len(ts)
cnt = collections.Counter(src_of)
nmal = len([s for s in cnt if s != "con"])
sw = np.array([(0.5 / nmal) / cnt[s] if s != "con" else 0.5 / cnt["con"] for s in src_of]) * len(src_of)
print(f"train: {int(y.sum())} malicious windows from {nmal} sources, {int((1 - y).sum())} benign", flush=True)

if HEAD == "logreg":
    from sklearn.linear_model import LogisticRegression
    clf = LogisticRegression(C=float(os.environ.get("C", "4")), max_iter=3000)
    clf.fit(X, y, sample_weight=sw)
    prob = lambda M: clf.decision_function(M)
else:
    import torch
    torch.manual_seed(0)
    Xt, yt, wt = torch.from_numpy(X), torch.from_numpy(y).float(), torch.from_numpy(sw).float()
    net = torch.nn.Sequential(torch.nn.Linear(X.shape[1], 256), torch.nn.ReLU(), torch.nn.Dropout(0.2), torch.nn.Linear(256, 1))
    opt = torch.optim.AdamW(net.parameters(), 1e-3, weight_decay=1e-4)
    for ep in range(6):
        perm = torch.randperm(len(Xt))
        for i in range(0, len(perm), 1024):
            j = perm[i:i + 1024]
            loss = (torch.nn.functional.binary_cross_entropy_with_logits(net(Xt[j]).squeeze(1), yt[j], reduction="none") * wt[j]).mean()
            opt.zero_grad(); loss.backward(); opt.step()
    net.eval()
    prob = lambda M: net(torch.from_numpy(M)).squeeze(1).detach().numpy()

keep = qm[:, 2] <= 1
Q = E[np.array([pos[t] for t, k in zip(qt, keep) if k])]
s = np.concatenate([prob(Q[i:i + 50000]) for i in range(0, len(Q), 50000)])
rid = qm[keep, 0]
score = collections.defaultdict(lambda: -1e9)
for r, v in zip(rid, s):
    if v > score[r]:
        score[r] = v
ids = list(score)
sc = np.array([score[i] for i in ids])
src = np.array([rows[i]["source"] for i in ids]); split = np.array([rows[i]["split"] for i in ids]); role = np.array([rows[i]["role"] for i in ids])
bc = (role == "ben") & (split == "calib") & np.isin(src, list(TOOL))
thr = np.quantile(sc[bc], 1 - TARGET)
flag = sc > thr
res = {}
for name in sorted(set(src)):
    m = (src == name) & (split == "test")
    if m.any():
        res[name] = 100 * flag[m].mean()
grp = lambda names: np.mean([res[n] for n in names if n in res])
print(f"HEAD={HEAD} EXCLUDE={sorted(EXCL)} target FP {TARGET:.0%} (tool calib)")
for k in ("hackaprompt", "mosscap", "llmail-inject-p2", "gandalf-ignore", "tensortrust", "mcptox-poisoned", "mcptox-poisoned-tmpl", "mcpgen-test",
          "embedded:hackaprompt", "embedded:llmail-inject-p2", "embedded:tensortrust", "embedded:mcptox-poisoned"):
    if k in res:
        print(f"  {k:30s} {res[k]:5.1f}%")
print(f"  FP tool {grp(TOOL):.1f}%  FP prompt {grp(PROMPT):.1f}%  FP email {grp(EMAIL):.1f}%")

# ---- combination with the kNN hybrid: flag if either fires, FP budget split
if os.environ.get("COMBO", "1") == "1":
    from s3_eval import load, text_k_scores
    md, dist, q = load("e5-small-ml")
    groups = [tuple(g) for g in md["groups"]]
    allsrc = sorted({g[0] for g in groups if g[1] in (0, 1, 3)} - EXCL)
    cw = [i for i, (s_, kd, b) in enumerate(groups) if kd == 0 and s_ in allsrc]
    cs = [i for i, (s_, kd, b) in enumerate(groups) if kd == 1 and s_ in allsrc]
    ks = np.where(q[:, 2] == 0, dist[:, cw].min(1), dist[:, cs].min(1))
    T = text_k_scores(q, ks)[[0, 1]]
    T = T.reindex(ids)
    kb = bc
    P = np.ones(len(T))
    for k in (0, 1):
        v = T[k].values; ref = np.sort(v[kb & ~np.isnan(v)])
        p = np.searchsorted(ref, v, side="right") / kb.sum(); p[np.isnan(v)] = 1.0
        P = np.minimum(P, p)
    # head percentile among benign calib (higher score = more malicious)
    refh = np.sort(sc[kb]); ph = 1 - np.searchsorted(refh, sc, side="left") / kb.sum()
    for share in (0.5, 0.75):
        a_k, a_h = TARGET * share, TARGET * (1 - share)
        tk = np.sort(P[kb])[int(np.floor(a_k * kb.sum()))]
        th = np.sort(ph[kb])[int(np.floor(a_h * kb.sum()))]
        f = (P < tk) | (ph < th)
        r2 = {n: 100 * f[(src == n) & (split == "test")].mean() for n in set(src) if ((src == n) & (split == "test")).any()}
        g2 = lambda names: np.mean([r2[n] for n in names if n in r2])
        print(f"COMBO kNN {share:.0%} of budget + head {1-share:.0%}: " + ", ".join(
            f"{k} {r2[k]:.0f}" for k in ("hackaprompt", "mosscap", "llmail-inject-p2", "tensortrust", "mcptox-poisoned", "mcptox-poisoned-tmpl", "mcpgen-test",
                                         "embedded:llmail-inject-p2", "embedded:tensortrust", "embedded:mcptox-poisoned") if k in r2)
              + f" | FP tool {g2(TOOL):.1f} prompt {g2(PROMPT):.1f} email {g2(EMAIL):.1f}")
