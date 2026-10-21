# s1_build.py — text only, no model. Builds every text set for the corpus-3 study.
#
#   python s1_build.py  (paths below)
#
# Writes out/texts.jsonl, one row per text:
#   {id, text, source, role, split}
#   role  = mal     malicious corpus candidate / malicious evaluation text
#           ben     benign evaluation text (false positives)
#           con     benign CONTRAST corpus (never evaluated)
#           fix     fixture units (evil/benign MCP fixtures of the repo)
#   split = corpus | calib | test      (mal: corpus = goes into Chroma)
#
# Splits are fixed here, once, so every model and method sees the same texts.
# Malicious new sources (hackaprompt, mosscap) are near-deduplicated later by
# s1b_dedup.py (needs an embedding model); this script only exact-dedups.
import glob, hashlib, json, os, random, re, unicodedata
import pandas as pd

H = os.path.expanduser("~/.cache/mcp-eval")
OLD, DL, BENCH, OUT = f"{H}/corpus2/out", f"{H}/dl2", f"{H}/corpus2/bench", f"{H}/corpus3/out"
os.makedirs(OUT, exist_ok=True)
random.seed(13)

EN = set("the a an and or to of in is are you your this that for with on it be not do all any what how please me my i".split())
ES = set("el la los las de que y en un una por para con es no tu su lo al del se como más pero mi yo".split())
OTHER = set("der die das und ist nicht ich sie le les et est je vous pas une o não você em de um uma il di che non sono".split()) - EN - ES

def lang(t):
    w = re.findall(r"[a-záéíóúñüçãõàèìòâêôäöß]+", t.lower())
    if not w:
        return None
    en = sum(x in EN for x in w); es = sum(x in ES for x in w); ot = sum(x in OTHER for x in w)
    if max(en, es) == 0:
        return "en" if t.isascii() else None
    if ot > max(en, es):
        return None
    return "en" if en >= es else "es"

def clean(t):
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", str(t))).strip()

def key(t):
    return re.sub(r"[^a-z0-9áéíóúñ]+", " ", re.sub(r"\d+", "0", t.lower())).strip()

def half(t):  # stable calib/test assignment
    return "calib" if int(hashlib.sha256(t.encode()).hexdigest(), 16) % 2 == 0 else "test"

rows, seen = [], set()
def add(text, source, role, split, min_words=3, max_chars=4000, dedup=True):
    t = clean(text)
    if len(t.split()) < min_words or len(t) < 12:
        return False
    t = t[:max_chars]
    if lang(t) is None:
        return False
    k = key(t)
    if dedup and k in seen:
        return False
    seen.add(k)
    rows.append({"text": t, "source": source, "role": role, "split": split})
    return True

# --- fixtures and benchmark first, so nothing else can duplicate them
fix_keys = set()
for f in ("evil/new-surface", "evil/new-probe", "benign/new-surface", "benign/new-probe"):
    for u in json.load(open(f"{BENCH}/{f}.json")):
        rows.append({"text": u["text"], "source": "fixture:" + f, "role": "fix", "split": "test",
                     "meta": {k: v for k, v in u.items() if k != "text"}})
        fix_keys.add(key(clean(u["text"]))); seen.add(key(clean(u["text"])))
for u in json.load(open(f"{BENCH}/fp-units.json")):
    t = u["text"]
    rows.append({"text": t, "source": "bench:fp-units", "role": "ben", "split": half(t)})
    seen.add(key(clean(t)))
for name, xs in json.load(open(f"{OLD}/benign_sets.json")).items():
    for t in xs[:1000]:
        add(t, "benign:" + name, "ben", half(clean(t)))

# --- malicious, already split in the corpus-2 study (near-deduped with MiniLM there)
for l in open(f"{OLD}/corpus.jsonl"):
    r = json.loads(l); add(r["text"], r["source"], "mal", "corpus", min_words=1)
for l in open(f"{OLD}/holdout.jsonl"):
    r = json.loads(l); add(r["text"], r["source"], "mal", half(clean(r["text"])), min_words=1)

# --- new malicious sources: candidates only, s1b near-dedups and splits them
hp = pd.read_parquet(f"{DL}/hackaprompt/hackaprompt.parquet", columns=["user_input", "correct", "level"])
hp = hp[hp.correct & (hp.level >= 1)]
for t in hp.user_input.sample(frac=1, random_state=3):
    add(t, "hackaprompt", "mal", "new")
ms = pd.concat([pd.read_parquet(f) for f in sorted(glob.glob(f"{DL}/mosscap/*.parquet"))])
for t in ms.prompt.sample(frac=1, random_state=3):
    add(t, "mosscap", "mal", "new")
# Tensor Trust: a family never put in any corpus (no data licence) -> test only
for f in sorted(glob.glob(f"{DL}/tensortrust/*.jsonl")):
    for l in open(f):
        add(json.loads(l)["attack"], "tensortrust", "mal", "test")

# MCPTox (no data licence -> evaluation only): 485 poisoned tool descriptions
# from real MCP servers, and those servers' clean tool descriptions.
for f in sorted(glob.glob(f"{DL}/mcptox/def_tool/*.py")):
    m = re.search(r'"""(.*?)"""', open(f).read(), re.S)
    if m:
        add(m.group(1), "mcptox-poisoned", "mal", "test")
for srv in json.load(open(f"{DL}/mcptox/response_all.json"))["servers"].values():
    for m in re.finditer(r"Tool: (\S+)\nDescription: (.*?)(?=\n\s*\n|\nInput|\nTool: |\Z)", srv["clean_system_promot"], re.S):
        t = f"{m.group(1)}: {m.group(2)}"
        add(t, "mcptox-clean", "ben", half(clean(t)))

# --- benign CONTRAST corpus (never evaluated)
con = []
for l in open(f"{DL}/dolly/dolly.jsonl"):
    d = json.loads(l)
    con.append((d["instruction"], "con:dolly"))
    for p in re.split(r"\n\s*\n", d["context"] or ""):
        con.append((p, "con:dolly"))
for item in json.load(open(f"{DL}/glaive/glaive.json")):
    for m in re.finditer(r'\{\s*"name":\s*"([^"]+)",\s*"description":\s*"([^"]+)"', item.get("system", "")):
        con.append((f"{m.group(1)}: {m.group(2)}", "con:tools"))
    for m in re.finditer(r'"description":\s*"([^"]{25,})"', item.get("system", "")):
        con.append((m.group(1), "con:tools"))
for l in open(f"{DL}/registry/servers.jsonl"):
    d = json.loads(l)
    if d.get("description"):
        con.append((d["description"], "con:mcp"))
for line in open(f"{DL}/awesome/README.md"):
    m = re.match(r"\s*[-*]\s+\[[^\]]+\]\([^)]+\)[^-–]*[-–]\s+(.{20,})", line)
    if m:
        con.append((re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", m.group(1)), "con:mcp"))
for f in glob.glob(f"{DL}/mcp-servers/src/*/README.md"):
    for p in re.split(r"\n\s*\n", open(f).read()):
        if not p.lstrip().startswith(("```", "|", "#", "<", "!")):
            con.append((re.sub(r"[*`_]", "", p), "con:mcp"))
random.shuffle(con)
CAP = {"con:dolly": 15000, "con:tools": 15000, "con:mcp": 15000}
n = {}
for t, s in con:
    if n.get(s, 0) >= CAP[s]:
        continue
    if add(t, s, "con", "corpus"):
        n[s] = n.get(s, 0) + 1

for i, r in enumerate(rows):
    r["id"] = i
with open(f"{OUT}/texts.jsonl", "w") as o:
    for r in rows:
        o.write(json.dumps(r, ensure_ascii=False) + "\n")
from collections import Counter
print(Counter((r["role"], r["source"], r["split"]) for r in rows).most_common())
