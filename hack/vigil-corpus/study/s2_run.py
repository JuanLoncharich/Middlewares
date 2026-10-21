# s2_run.py <model-key> — embed every window with one model and search.
#
# Corpus side (role mal split corpus, role con): each text gives its whole
# text (kind 0) and sentence windows of 1..3 sentences (kind 1, <=30/text).
# Each malicious corpus window also gets a PURITY bin: its cosine distance to
# the nearest benign contrast window (quartile bins of that distance). A
# window close to benign text ("Hi Jim, hope you are well") is not evidence.
# Query side (every evaluation text): split like the runner (500-char chunks,
# 100 overlap); each chunk gives its whole chunk (k=0) and windows of
# k = 1..4 consecutive sentences (<=40/chunk).
# Per query window we keep the min distance to every group
# (malicious source x kind x purity bin, and each contrast source), so any
# corpus subset is a min over columns.
# Embeddings are cached per string (E.npy + strings.json) across reruns.
import json, os, re, sys, time
import numpy as np, torch
from sentence_transformers import SentenceTransformer

MODELS = {
    "minilm": ("sentence-transformers/all-MiniLM-L6-v2", ""),
    "bge-small": ("BAAI/bge-small-en-v1.5", ""),
    "bge-base": ("BAAI/bge-base-en-v1.5", ""),
    "e5-small-ml": ("intfloat/multilingual-e5-small", "query: "),
    "bge-m3": ("BAAI/bge-m3", ""),
    "qwen3-0.6b": ("Qwen/Qwen3-Embedding-0.6B",
                   "Instruct: Retrieve texts that use the same prompt-injection or jailbreak technique\nQuery: "),
}
KEY = sys.argv[1]
NAME, PREFIX = MODELS[KEY]
OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
DST = f"{OUT}/{KEY}"
os.makedirs(DST, exist_ok=True)
dev = "cuda" if torch.cuda.is_available() else "cpu"
torch.set_num_threads(12)
BINS = [0.2, 0.3, 0.4]

def sentences(t):
    out = []
    for p in re.split(r"(?<=[.!?])\s+|\n+", t):
        w = p.split()
        for i in range(0, len(w), 40):
            out.append(" ".join(w[i:i + 40]))
    return [s for s in out if s]

def windows(t, kmax, cap):
    s, res = sentences(t), []
    for k in range(1, kmax + 1):
        for i in range(len(s) - k + 1):
            w = " ".join(s[i:i + k])
            if len(w.split()) >= 3:
                res.append((k, w))
    return res[:cap]

def chunks(t, size=500, ov=100):
    if len(t) <= size:
        return [t]
    return [t[i:i + size] for i in range(0, max(1, len(t) - ov), size - ov)]

rows = [json.loads(l) for l in open(f"{OUT}/texts.final.jsonl")]
mal_src = sorted({r["source"] for r in rows if r["role"] == "mal" and r["split"] == "corpus"})
con_src = sorted({r["source"] for r in rows if r["role"] == "con"})

# kind 0 = whole text, 1 = single-sentence windows, 3 = 2-3 sentence windows.
# Rows with meta.inj (our generated MCP corpus) take their sentence windows
# from the injection alone, not from the benign host text around it.
mal_w = {(s, kd): [] for s in mal_src for kd in (0, 1, 3)}
con_w = {s: [] for s in con_src}
for r in rows:
    if r["role"] == "mal" and r["split"] == "corpus":
        mal_w[(r["source"], 0)].append(r["text"])
        src_t = (r.get("meta") or {}).get("inj") or r["text"]
        for k, w in windows(src_t, 3, 30):
            mal_w[(r["source"], 1 if k == 1 else 3)].append(w)
    elif r["role"] == "con":
        con_w[r["source"]] += [r["text"]] + [w for _, w in windows(r["text"], 3, 30)]
for d in (mal_w, con_w):
    for g in d:
        d[g] = list(dict.fromkeys(d[g]))

qmeta, qtexts = [], []   # (row id, chunk idx, k)
for r in rows:
    if r["role"] in ("mal", "ben", "fix") and r["split"] in ("calib", "test"):
        for ci, ch in enumerate(chunks(r["text"])):
            qmeta.append((r["id"], ci, 0)); qtexts.append(ch)
            for k, w in windows(ch, 4, 40):
                qmeta.append((r["id"], ci, k)); qtexts.append(w)

need = list(dict.fromkeys([t for v in mal_w.values() for t in v] + [t for v in con_w.values() for t in v] + qtexts))
# ---- embedding cache keyed by string
if os.path.exists(f"{DST}/strings.json"):
    have = json.load(open(f"{DST}/strings.json")); E = np.load(f"{DST}/E.npy")
elif os.path.exists(f"{DST}/E.npy") and os.path.exists(f"{DST}/meta.json"):   # first-version cache
    old = json.load(open(f"{DST}/meta.json"))
    have = list(dict.fromkeys([t for g in old["gtexts"] for t in g] + json.load(open(f"{DST}/qtexts.json"))))
    E = np.load(f"{DST}/E.npy"); assert len(have) == len(E), (len(have), len(E))
else:
    have, E = [], None
pos = {t: i for i, t in enumerate(have)}
miss = [t for t in need if t not in pos]
print(f"{KEY}: mal windows {sum(map(len, mal_w.values()))}, con windows {sum(map(len, con_w.values()))}, "
      f"query windows {len(qtexts)}, cached {len(need) - len(miss)}, to encode {len(miss)}", flush=True)
enc_s = 0.0
if miss:
    model = SentenceTransformer(NAME, device="cpu")   # load fp32 on CPU, halve, then move:
    model.max_seq_length = min(model.max_seq_length, 512)  # the GPU is shared with llama-server
    if dev == "cuda":
        try:
            model.half().to("cuda")
        except torch.OutOfMemoryError:
            torch.cuda.empty_cache(); model = model.float().to("cpu"); print("  model does not fit on the GPU: CPU", flush=True)
    t0 = time.time()
    order = sorted(range(len(miss)), key=lambda i: len(miss[i]))
    M = np.empty((len(miss), model.get_sentence_embedding_dimension()), np.float16)
    cpu_model = None
    for s in range(0, len(order), 5000):
        idx = order[s:s + 5000]
        texts = [PREFIX + miss[i] for i in idx]
        bs = 32 if len(texts[-1]) < 600 else 8   # sorted by length: long texts in small batches
        try:
            M[idx] = model.encode(texts, batch_size=bs, normalize_embeddings=True,
                                  convert_to_numpy=True, show_progress_bar=False).astype(np.float16)
        except torch.OutOfMemoryError:            # the GPU is shared with llama-server
            torch.cuda.empty_cache()
            if cpu_model is None:
                cpu_model = SentenceTransformer(NAME, device="cpu"); cpu_model.max_seq_length = model.max_seq_length
            M[idx] = cpu_model.encode(texts, batch_size=16, normalize_embeddings=True,
                                      convert_to_numpy=True, show_progress_bar=False).astype(np.float16)
            print("  (block on CPU)", flush=True)
        if s % 50000 == 0:
            print(f"  encoded {min(s + 5000, len(order))}/{len(order)}  {time.time() - t0:.0f}s", flush=True)
    enc_s = time.time() - t0
    E = M if E is None else np.vstack([E, M])
    have += miss
    np.save(f"{DST}/E.npy", E); json.dump(have, open(f"{DST}/strings.json", "w"))
    pos = {t: i for i, t in enumerate(have)}
    del model
    torch.cuda.empty_cache()
elif not os.path.exists(f"{DST}/strings.json"):
    json.dump(have, open(f"{DST}/strings.json", "w"))

def mat(texts):
    return torch.from_numpy(E[[pos[t] for t in texts]].astype(np.float32))

sdev = "cuda" if torch.cuda.is_available() and torch.cuda.mem_get_info()[0] > 4e9 else "cpu"
print("search device", sdev, flush=True)

def nearest(Q, C, QB=8192, CB=16384):
    best = torch.full((len(Q),), -9.0); barg = torch.full((len(Q),), -1, dtype=torch.int32)
    for cs in range(0, len(C), CB):
        Cb = C[cs:cs + CB].to(sdev)
        for qs in range(0, len(Q), QB):
            v, a = (Q[qs:qs + QB].to(sdev) @ Cb.T).max(1)
            v, a = v.float().cpu(), a.cpu()
            upd = v > best[qs:qs + QB]
            best[qs:qs + QB][upd] = v[upd]; barg[qs:qs + QB][upd] = a[upd].int() + cs
    return (1 - best).numpy(), barg.numpy()

t1 = time.time()
# ---- purity of every malicious corpus window
Ccon = mat([t for v in con_w.values() for t in v])
groups, gtexts = [], []
dcon = {g: nearest(mat(ts), Ccon)[0] for g, ts in mal_w.items() if ts}
# purity bins = quartiles of the distance to benign, per model (scales differ)
BINS = list(np.quantile(np.concatenate(list(dcon.values())), [0.25, 0.5, 0.75]))
print("purity quartile edges", [round(float(x), 3) for x in BINS], flush=True)
for (s, kd), ts in mal_w.items():
    if not ts:
        continue
    d = dcon[(s, kd)]
    b = np.digitize(d, BINS)
    for bi in range(len(BINS) + 1):
        sel = [t for t, x in zip(ts, b) if x == bi]
        if sel:
            groups.append((s, kd, bi)); gtexts.append(sel)
for s, ts in con_w.items():
    groups.append((s, 2, -1)); gtexts.append(ts)
del Ccon
print(f"purity {time.time() - t1:.0f}s", flush=True)

Q = mat(qtexts)
dist = np.full((len(qtexts), len(groups)), 9, np.float16)
arg = np.full((len(qtexts), len(groups)), -1, np.int32)
for gi, ts in enumerate(gtexts):
    d, a = nearest(Q, mat(ts))
    dist[:, gi] = d.astype(np.float16); arg[:, gi] = a
print(f"search {time.time() - t1:.0f}s", flush=True)

np.save(f"{DST}/dist.npy", dist)
np.save(f"{DST}/arg.npy", arg)
np.save(f"{DST}/qmeta.npy", np.array(qmeta, np.int32))
json.dump({"bins": [float(x) for x in BINS], "groups": groups, "gtexts": gtexts, "encode_seconds_new": enc_s, "model": NAME, "dim": int(E.shape[1])},
          open(f"{DST}/meta.json", "w"))
json.dump(qtexts, open(f"{DST}/qtexts.json", "w"))
print("done", KEY)
