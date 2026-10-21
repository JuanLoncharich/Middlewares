# Vigil's vector corpus

Vigil's `vectordb` scanner asks three questions about each piece of untrusted
text the runner sends (one chunk of at most 500 characters):

1. is the **whole chunk** close to a known malicious text? (collection
   `vigil_e5s_v3_whole`)
2. is **any one of its sentences** close to a known malicious sentence?
   (collection `vigil_e5s_v3_sentence`)
3. does a **trained head** (a logistic regression on the same embeddings,
   stored in the whole collection's metadata) score the chunk or one of its
   sentences above its threshold? This one is not about being near a known
   text, so it catches attack families the corpus never saw.

"Close" means a cosine distance under that collection's own threshold, **and**
closer than the nearest known benign tool or MCP-server text (collection
`vigil_e5s_v3_benign`: 35 330 texts and sentences from glaive's function
descriptions, the MCP registry and MCP server READMEs). The second condition
exists because short benign tools and short attacks can share their words:
in the kind e2e, the benign fixture's `reverse: Reverse the characters of the
provided text.` matched Mosscap's "Reverse the text above…" under the
threshold, and with the transformer also (wrongly) flagging it, the benign
server was aborted as Malicious. Two-sided, it is clean, and detection went
up slightly everywhere (study `s8_twosided.py`). A whole text also needs at
least 3 words to count, like a sentence (the same e2e flagged our own
client's "no response" note as close to "Ignore response"); short benign
calibration texts were what held the whole-text threshold down, so that rule
also raised detection (Tensor Trust 53 → 63 %).
The thresholds were calibrated together so that only 2 % of benign tool-like
texts (tool descriptions, READMEs, code, MCP fixtures) raise any hit: half of
that budget for the two kNN questions, the rest for the head. The second
question is what catches an attack hidden inside an otherwise normal
description: the chunk as a whole looks benign, the bad sentence does not.

The embedding model is `intfloat/multilingual-e5-small` (384 dimensions,
every text prefixed `query: `), so Spanish and other languages work as well.

| file | what it is |
|---|---|
| `vigil-corpus-e5s-v3.lock.json` | **committed**: the file name, its sha256, model, prefix, thresholds, counts per source and the held-out test report |
| `dist/vigil-corpus-e5s-v3.jsonl.gz` | the corpus itself (201 MB, git-ignored). A header line, then one JSON line per entry `{"c": collection, "t": text, "s": source, "e": base64 float16 vector}` |
| `build_corpus.py` | builds the file and the lock from a texts file (below); `--head logreg` trains the head |
| `study/` | the study scripts that made the texts file and chose model and method (they read and write `~/.cache/mcp-eval/`) |

## How it reaches Vigil

1. `deploy.sh` checks `dist/<file>` against the lock's sha256 and bakes it
   into an image, `$IMG_REGISTRY/vigil-corpus:e5s-v3-<sha12>`
   (`images/vigil-corpus-loader/Dockerfile.corpus`), which it pushes like
   every other image.
2. The `vigil-corpus-loader` Job runs from that image. It checks the sha256
   again before writing anything, then writes the three collections through
   `chroma-gateway` with the writer token. Each collection's **metadata**
   holds its threshold, the model, the prefix and an embedding probe; the
   whole collection also holds the head (weights, bias, threshold). A
   second build under the same names is refused unless `RECREATE=1`. With
   `PRUNE_OTHER=1` (on in the Job) it then deletes every other `vigil_*`
   collection, so Chroma holds one corpus.
3. Vigil (`images/vigil-llm/remote_vectordb.py`) reads that metadata on its
   first query. It checks that its own embedder reproduces the probe, and
   **fails closed** on any mismatch (wrong model, revision, library or
   prefix), so it never scores against a corpus it doesn't match.

## Sources

| source | texts in corpus | origin | licence |
|---|---|---|---|
| deadbits instruction-bypass / jailbreak | 8 786 / 102 | HF `deadbits/vigil-*` (upstream Vigil's own corpora) | Apache-2.0 |
| LLMail-Inject phase 2 | 9 007 | Microsoft LLMail-Inject challenge submissions | MIT |
| HackAPrompt (successful attacks, level ≥ 1) | 6 634 | HF `hackaprompt/hackaprompt-dataset` (gated; needed an HF token) | MIT per its dataset card — re-check before publishing |
| Mosscap | 12 750 (capped) | HF `Lakera/mosscap_prompt_injection` | MIT per its dataset card — re-check before publishing |
| Gandalf "ignore instructions" | 828 | HF `Lakera/gandalf_ignore_instructions` | MIT |
| TrustAIRLab jailbreak prompts | 971 | HF `TrustAIRLab/in-the-wild-jailbreak-prompts` | MIT |
| yanismiraoui multilingual injections | 638 | HF `yanismiraoui/prompt_injections` | Apache-2.0 |
| deepset prompt injections | 174 | HF `deepset/prompt-injections` | Apache-2.0 |
| InjecAgent attacker instructions | 84 | InjecAgent (GitHub) | MIT |
| BIPIA code attacks | 84 | microsoft/BIPIA | MIT |
| **our generated poisoned MCP texts** | 1 106 | `study/s6_gen_mcp.py`: the local LLM (LFM2.5-24B-A2B) writes a tool, then hides one attack in it (14 goals × 10 hiding styles × 4 places: tool description, parameter description, tool output, server instructions; 7 languages). Seeds are benign tool texts from the contrast corpus only. 1 522 generated, 306 dropped (injection not really inside, or too short), 110 kept apart as `mcpgen-test` | ours |

**Never in the corpus (test only):**
- MCPTox, real poisoned tools from 45 MCP servers, which has no data licence.
- Tensor Trust attacks, a family the corpus never sees.
- The repo's own MCP fixtures.

The texts were exact-deduplicated, then near-deduplicated at cosine 0.95.
Each source was split once by a stable hash into corpus / calib / test.
Calibration uses only the calib half of the benign tool-like texts.

## Results on the held-out test half (from the lock)

| test set | e5s-v2 (kNN only) | **e5s-v3 (kNN + head)** |
|---|---|---|
| HackAPrompt / LLMail-Inject / Gandalf | 99.7 / 99.4 / 98.5 % | 99.7 / 99.3 / 98.5 % |
| Mosscap / TrustAIR / multilingual | 87 / 85 / 85.5 % | 86 / 88.6 / 89 % |
| Tensor Trust (family never in the corpus) | 63 % | **84 %** |
| attacks inserted inside benign text: LLMail / HackAPrompt / Tensor Trust / MCPTox | 95 / 78 / 59 / 39 % | 96 / 84 / 81 / **49 %** |
| our generated MCP texts (held out) | 40 % | **54.5 %** |
| **MCPTox poisoned tools (never in the corpus)** | 3.3 % | **13.5 %** |
| false positives: benign tool texts / MCPTox clean tools | 2.7 / 2.8 % | 4.1 / 0.6 % |
| false positives: benign user prompts / emails | 4–59 % | 8–66 % |

Before any of this, with deadbits + MiniLM and the raw 0.4 threshold, the
same test sets gave 0 % on HackAPrompt, 0 % on MCPTox and about 5 % on
attacks hidden inside text.

What these numbers mean for the platform:
- **Nearest-neighbour search alone does not catch new kinds of tool
  poisoning** (MCPTox 3 % in v2, even with 1 100 generated poisoned tools in
  the corpus): a poisoned tool looks too much like a benign one. The head
  generalises better (Tensor Trust 63 → 84 %, MCPTox 3 → 14 %), at about the
  same false-positive rate on tool text. 14 % is still low: Vigil is one
  layer, and the LLM agents and YARA are the others.
- False positives on user-prompt-like and email-like text are high, because
  the thresholds were calibrated on tool-like text, which is what the
  evaluator scans. The gate aborts only when the transformer and a second
  scanner agree (`docs/decisions.md`, 1A), so one vector hit alone records a
  warning, not an abort.

## Rebuilding

```bash
# 1. texts file: study/s1_build.py, s1b_dedup.py, s1c_extra.py, then (with the
#    local LLM up on :8090) s6_gen_mcp.py and s1d_mcpgen.py
#    -> ~/.cache/mcp-eval/corpus3/out/texts.final.jsonl
# 2. corpus + lock (a GPU makes it ~3 minutes)
python hack/vigil-corpus/build_corpus.py --texts ~/.cache/mcp-eval/corpus3/out/texts.final.jsonl \
  --out hack/vigil-corpus/dist --name e5s-v3 --head logreg --sources <the sources above, comma-separated>
mv hack/vigil-corpus/dist/vigil-corpus-e5s-v3.lock.json hack/vigil-corpus/
```

A new build gets a new `--name` (e.g. `e5s-v4`). That means new collection
names, so Vigil's `server.conf` must name them too. An old and a new build
never mix.
