# s5_latency.py — CPU cost per Vigil request, per model (run with nothing else busy).
# One request = one runner chunk (~500 chars): today Vigil embeds 1 string; the
# sentence method embeds the chunk + its 1- and 2-sentence windows.
import json, os, re, statistics, sys, time
import torch
from sentence_transformers import SentenceTransformer
sys.path.insert(0, os.path.dirname(__file__))
torch.set_num_threads(int(os.environ.get("THREADS", "2")))   # Vigil's pod: 2 CPU limit
MODELS = {"minilm": "sentence-transformers/all-MiniLM-L6-v2", "bge-small": "BAAI/bge-small-en-v1.5",
          "bge-base": "BAAI/bge-base-en-v1.5", "e5-small-ml": "intfloat/multilingual-e5-small"}
OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
rows = [json.loads(l) for l in open(f"{OUT}/texts.final.jsonl")]
chunks = [r["text"][:500] for r in rows if r["source"] == "embedded:llmail-inject-p2"][:40]

def wins(t):
    s = [x for x in re.split(r"(?<=[.!?])\s+", t) if x]
    return [t] + s + [" ".join(s[i:i + 2]) for i in range(len(s) - 1)]

print(f"threads={torch.get_num_threads()}  avg strings per request (sentence method): "
      f"{statistics.mean(len(wins(c)) for c in chunks):.1f}")
for key, name in MODELS.items():
    m = SentenceTransformer(name, device="cpu")
    params = sum(p.numel() for p in m.parameters()) / 1e6
    for c in chunks[:3]:
        m.encode(wins(c))  # warm-up
    res = {}
    for label, f in (("whole", lambda c: [c]), ("sent", wins)):
        ts = []
        for c in chunks:
            t0 = time.perf_counter(); m.encode(f(c), batch_size=32); ts.append(1000 * (time.perf_counter() - t0))
        res[label] = statistics.median(ts)
    print(f"{key:12} {params:6.0f}M params  whole {res['whole']:6.1f} ms   chunk+sentence windows {res['sent']:6.1f} ms")
