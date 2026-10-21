# s1d_mcpgen.py — add our LLM-generated poisoned MCP texts (out/mcpgen.jsonl,
# from s6_gen_mcp.py) to out/texts.final.jsonl.
#
# Filter: the injection must really be inside the poisoned text (>= 60% of its
# word types appear there) and say something (>= 6 words); exact duplicates
# (normalised) of an injection are dropped. 10% (stable hash) is held out as
# test source "mcpgen-test" (in-distribution sanity check); the rest enters the
# corpus twice, as two alternative sources over the same texts:
#   mcpgen       whole = poisoned text, sentence windows from the injection only
#   mcpgen-full  whole = poisoned text, sentence windows from the whole text
# Idempotent: rows of earlier runs (source mcpgen*) are replaced.
import hashlib, json, os, re

OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
words = lambda t: set(re.findall(r"\w+", t.lower()))
rows = [r for r in map(json.loads, open(f"{OUT}/texts.final.jsonl")) if not r["source"].startswith("mcpgen")]
nid = max(r["id"] for r in rows) + 1
seen, kept, drop = set(), [], {"not inside": 0, "short": 0, "dup": 0}
for g in map(json.loads, open(f"{OUT}/mcpgen.jsonl")):
    inj, pois = re.sub(r"\s+", " ", g["injection"]).strip(), re.sub(r"\s+", " ", g["poisoned_text"]).strip()
    wi = words(inj)
    if len(inj.split()) < 6:
        drop["short"] += 1; continue
    if len(wi & words(pois)) < 0.6 * len(wi):
        drop["not inside"] += 1; continue
    k = " ".join(sorted(wi))
    if k in seen:
        drop["dup"] += 1; continue
    seen.add(k)
    meta = {"inj": inj, "goal": g["goal"], "style": g["style"], "place": g["place"], "lang": g["lang"], "gen_i": g["i"]}
    if int(hashlib.sha256(pois.encode()).hexdigest(), 16) % 10 == 0:
        kept.append({"text": pois[:4000], "source": "mcpgen-test", "role": "mal", "split": "test", "meta": meta})
    else:
        for src in ("mcpgen", "mcpgen-full"):
            m = dict(meta) if src == "mcpgen" else {k2: v for k2, v in meta.items() if k2 != "inj"}
            kept.append({"text": pois[:4000], "source": src, "role": "mal", "split": "corpus", "meta": m})
for r in kept:
    r["id"] = nid; nid += 1
with open(f"{OUT}/texts.final.jsonl", "w") as o:
    for r in rows + kept:
        o.write(json.dumps(r, ensure_ascii=False) + "\n")
from collections import Counter
print("dropped", drop, "kept", Counter(r["source"] for r in kept))
