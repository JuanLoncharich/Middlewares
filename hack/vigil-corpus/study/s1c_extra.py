# s1c_extra.py — two additions to texts.final.jsonl (rewritten in place,
# original kept as texts.final.orig.jsonl):
#  1. MCPTox split BY SERVER: poisoned tools of half the servers become a
#     corpus source "mcptox-A" (measurement only, no data licence); the other
#     servers' poisoned tools stay as the test set "mcptox-poisoned".
#  2. "embedded:<src>": a held-out attack (test split, <= 50 words) inserted
#     at a random sentence boundary of a benign TEST text with >= 3 sentences
#     — the dilution case: an injection hidden inside an otherwise normal text.
import hashlib, json, os, random, re, shutil
OUT = os.path.expanduser("~/.cache/mcp-eval/corpus3/out")
DL = os.path.expanduser("~/.cache/mcp-eval/dl2")
random.seed(23)
src_f = f"{OUT}/texts.final.orig.jsonl"
if not os.path.exists(src_f):
    shutil.copy(f"{OUT}/texts.final.jsonl", src_f)
rows = [json.loads(l) for l in open(src_f)]
rows = [r for r in rows if r["source"] != "mcptox-poisoned"]
clean = lambda t: re.sub(r"\s+", " ", t).strip()

servers = {}
for d in json.load(open(f"{DL}/mcptox/pure_tool.json")):
    for v in d.values():
        servers.setdefault(v["server_name"], []).append(clean(v["tool_content"]))
names = sorted(servers)
A = {n for n in names if int(hashlib.sha256(n.encode()).hexdigest(), 16) % 2 == 0}
seen = set()
for n in names:
    for t in servers[n]:
        if t in seen:
            continue
        seen.add(t)
        rows.append({"text": t, "source": "mcptox-A" if n in A else "mcptox-poisoned", "role": "mal",
                     "split": "corpus" if n in A else "test", "meta": {"server": n}})
print("mcptox servers A/B", len(A), len(names) - len(A),
      "texts A", sum(r["source"] == "mcptox-A" for r in rows), "B", sum(r["source"] == "mcptox-poisoned" for r in rows))

def sents(t):
    return [s for s in re.split(r"(?<=[.!?])\s+", t) if s]
hosts = [r for r in rows if r["role"] == "ben" and r["split"] == "test" and len(sents(r["text"])) >= 3 and len(r["text"]) >= 250]
print("hosts", len(hosts))
for src in ("hackaprompt", "llmail-inject-p2", "tensortrust", "gandalf-ignore", "mcptox-poisoned"):
    atk = [r["text"] for r in rows if r["source"] == src and r["split"] == "test" and len(r["text"].split()) <= 50]
    random.shuffle(atk)
    for a in atk[:150]:
        h = random.choice(hosts)
        s = sents(h["text"])
        i = random.randint(1, len(s) - 1)
        rows.append({"text": " ".join(s[:i] + [a] + s[i:]), "source": "embedded:" + src, "role": "mal", "split": "test",
                     "meta": {"host": h["source"], "attack": a[:200]}})
for i, r in enumerate(rows):
    r["id"] = i
with open(f"{OUT}/texts.final.jsonl", "w") as o:
    for r in rows:
        o.write(json.dumps(r, ensure_ascii=False) + "\n")
from collections import Counter
print({k: v for k, v in Counter(r["source"] for r in rows).items() if k.startswith(("embedded", "mcptox"))})
