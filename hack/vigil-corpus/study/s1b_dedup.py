# s1b_dedup.py — near-dedup the new malicious sources and split them.
# Uses MiniLM once (model-independent splits for every later model):
# drop a new text whose cosine to any kept text (old corpus/holdout included)
# is >= 0.95; cap mosscap; 15% of each new source goes to calib/test halves.
import json, os, random
import numpy as np, torch
from sentence_transformers import SentenceTransformer

OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
NEAR, HOLD, CAP = 0.95, 0.15, {"mosscap": 15000, "hackaprompt": 100000}
random.seed(17)
rows = [json.loads(l) for l in open(f"{OUT}/texts.jsonl")]
m = SentenceTransformer("all-MiniLM-L6-v2", device="cuda")
m.half()
enc = lambda xs: m.encode(xs, batch_size=32, normalize_embeddings=True, convert_to_tensor=True).float().cpu()

base = [r for r in rows if r["role"] == "mal" and r["split"] != "new"]
K = enc([r["text"] for r in base])
kept = {}
for src in ("hackaprompt", "mosscap"):
    cand = [r for r in rows if r["source"] == src and r["split"] == "new"]
    keep = []
    for s in range(0, len(cand), 4096):
        blk = cand[s:s + 4096]
        B = enc([r["text"] for r in blk])
        drop = (B @ K.T).max(1).values >= NEAR
        S = B @ B.T
        S.fill_diagonal_(0)
        S = torch.triu(S) >= NEAR
        drop = drop.cpu().numpy(); S = S.cpu().numpy()
        for j in range(len(blk)):
            if not drop[j]:
                drop |= S[j]
        sel = [j for j in range(len(blk)) if not drop[j]]
        keep += [blk[j] for j in sel]
        K = torch.cat([K, B[sel]])
        if len(keep) >= CAP[src]:
            break
    keep = keep[:CAP[src]]
    n_h = round(len(keep) * HOLD)
    for i, r in enumerate(keep):
        r["split"] = ("calib" if i % 2 == 0 else "test") if i < n_h else "corpus"
    kept[src] = (len(cand), len(keep), n_h)
    print(src, "candidates", len(cand), "kept", len(keep), "holdout", n_h, flush=True)

rows = [r for r in rows if r["split"] != "new"]
with open(f"{OUT}/texts.final.jsonl", "w") as o:
    for r in rows:
        o.write(json.dumps(r, ensure_ascii=False) + "\n")
from collections import Counter
print(sorted(Counter((r["role"], r["split"]) for r in rows).items()))
