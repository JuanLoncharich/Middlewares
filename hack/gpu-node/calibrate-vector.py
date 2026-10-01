#!/usr/bin/env python3
"""Calibrate whole-payload scanning for the VECTOR engine (MiniLM -> corpus).

Same benign payloads and planted injections as calibrate-windows.py, but the
question is: does `min over windows of (cosine distance to the nearest known
attack)` separate benign tool output from injected payloads at the engine's
threshold (0.45)? Uses the real Vigil corpora, brute force, no Chroma needed:

  mkdir corpus && cd corpus
  for n in instruction-bypass jailbreak; do curl -sSL -o $n.json \\
    https://huggingface.co/datasets/deadbits/vigil-$n-all-MiniLM-L6-v2/resolve/main/embeddings.json; done
  VIGIL_MODEL_DIR=/path/to/models VIGIL_CORPUS_DIR=corpus venv/bin/python hack/gpu-node/calibrate-vector.py
"""
import importlib.util
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "images", "vigil-stub"))
os.environ.setdefault("VIGIL_ORT_PROVIDER", "cpu")

import numpy as np  # noqa: E402
import embedder  # noqa: E402

spec = importlib.util.spec_from_file_location("calwin", os.path.join(HERE, "calibrate-windows.py"))
calwin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calwin)

MD = os.environ["VIGIL_MODEL_DIR"]
CORPUS = os.environ["VIGIL_CORPUS_DIR"]


def load_corpus():
    vecs, texts = [], []
    for name in ("instruction-bypass", "jailbreak"):
        for row in json.load(open(os.path.join(CORPUS, f"{name}.json"))):
            e = row["embeddings"]
            vecs.append(json.loads(e) if isinstance(e, str) else e)
            texts.append(row.get("text", ""))
    m = np.array(vecs, dtype=np.float32)
    m /= np.clip(np.linalg.norm(m, axis=1, keepdims=True), 1e-9, None)
    return m, texts


def min_distance(emb, corpus, text, max_windows=400):
    vectors, meta = emb.encode_windows(text, max_windows)
    v = np.array(vectors, dtype=np.float32)
    sims = v @ corpus.T
    best = sims.max(axis=1)
    return float(1.0 - best.max()), meta["windows"]


def main():
    ap = __import__("argparse").ArgumentParser()
    ap.add_argument("--positions", type=int, default=3)
    ap.add_argument("--max-kib", type=int, default=50)
    args = ap.parse_args()
    random.seed(11)
    emb = embedder.Embedder(MD)
    corpus, texts = load_corpus()
    print(f"corpus: {len(corpus)} vectors\n")

    bases = calwin.build_bases(args.max_kib)
    benign, injected, per_inj = [], [], {k: [] for k in calwin.INJECTIONS}
    for label, text in bases.items():
        d, n = min_distance(emb, corpus, text)
        benign.append(d)
        print(f"  benign {label:<15} {len(text)/1024:5.1f} KiB ({n:>3} windows)  min distance {d:.3f}")
        for kind, inj in calwin.INJECTIONS.items():
            for _ in range(args.positions):
                pos = random.randint(0, len(text))
                # Only windows touching the insertion can change, so embed the
                # local context and keep the base payload's own minimum.
                local = text[max(0, pos - 600):pos] + "\n" + inj + "\n" + text[pos:pos + 600]
                dl, _ = min_distance(emb, corpus, local)
                dist = min(d, dl)
                injected.append(dist)
                per_inj[kind].append(dist)

    print("\nmin distance to the nearest known attack (lower = more attack-like; engine threshold 0.45)")
    print(f"  BENIGN   min {min(benign):.3f}  median {sorted(benign)[len(benign)//2]:.3f}")
    print(f"  INJECTED min {min(injected):.3f}  median {sorted(injected)[len(injected)//2]:.3f}  max {max(injected):.3f}")
    for kind in calwin.INJECTIONS:
        xs = sorted(per_inj[kind])
        print(f"     {kind:<18} min {xs[0]:.3f}  median {xs[len(xs)//2]:.3f}  max {xs[-1]:.3f}")
    for thr in (0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60):
        fp = sum(x < thr for x in benign)
        tp = sum(x < thr for x in injected)
        print(f"  threshold < {thr:.2f}   false positives {fp}/{len(benign)}   detected {tp}/{len(injected)} ({100*tp/len(injected):.0f}%)")


if __name__ == "__main__":
    main()
