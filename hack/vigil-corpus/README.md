# Vigil's vector corpus

Vigil's `vectordb` scanner asks two questions about each piece of untrusted
text the runner sends (one chunk of at most 500 characters):

1. is the **whole chunk** close to a known malicious text? (collection
   `vigil_e5s_v1_whole`)
2. is **any one of its sentences** close to a known malicious sentence?
   (collection `vigil_e5s_v1_sentence`)

"Close" means a cosine distance under that collection's own threshold.
Each threshold was calibrated so that only 2 % of benign tool-like texts
(tool descriptions, READMEs, code, MCP fixtures) raise any hit. The second
question is what catches an attack hidden inside an otherwise normal
description: the chunk as a whole looks benign, the bad sentence does not.

The embedding model is `intfloat/multilingual-e5-small` (384 dimensions,
every text prefixed `query: `), so Spanish and other languages work as well.

| file | what it is |
|---|---|
| `vigil-corpus-e5s-v1.lock.json` | **committed**: the file name, its sha256, model, prefix, thresholds, counts per source and the held-out test report |
| `dist/vigil-corpus-e5s-v1.jsonl.gz` | the corpus itself (173 MB, git-ignored). A header line, then one JSON line per entry `{"c": collection, "t": text, "s": source, "e": base64 float16 vector}` |
| `build_corpus.py` | builds the file and the lock from a texts file (below) |
| `study/` | the study scripts that made the texts file and chose model and method (they read and write `~/.cache/mcp-eval/`) |

## How it reaches Vigil

1. `deploy.sh` checks `dist/<file>` against the lock's sha256 and bakes it
   into an image, `$IMG_REGISTRY/vigil-corpus:e5s-v1-<sha12>`
   (`images/vigil-corpus-loader/Dockerfile.corpus`), which it pushes like
   every other image.
2. The `vigil-corpus-loader` Job runs from that image. It checks the sha256
   again before writing anything, then writes both collections through
   `chroma-gateway` with the writer token. Each collection's **metadata**
   holds its threshold, the model, the prefix and an embedding probe. A
   second build under the same names is refused unless `RECREATE=1`.
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

| test set | detected |
|---|---|
| HackAPrompt / LLMail-Inject / Gandalf | 99 % / 98.5 % / 97 % |
| Mosscap / TrustAIR / multilingual | 81 % / 81 % / 85 % |
| Tensor Trust (family never in the corpus) | 47 % |
| attacks inserted inside benign text: LLMail / HackAPrompt / Tensor Trust / MCPTox | 95 % / 72 % / 53 % / 33 % |
| our generated MCP texts (held out) | 32 % |
| **MCPTox poisoned tools (never in the corpus)** | **2 %** |
| false positives: benign tool texts / MCPTox clean tools | 2.4 % / 1.7 % |
| false positives: benign user prompts / emails | 10–49 % |

Before this corpus, with deadbits + MiniLM and the raw 0.4 threshold, the
same test sets gave 0 % on HackAPrompt, 0 % on MCPTox and about 5 % on
attacks hidden inside text.

What these numbers mean for the platform:
- **Similarity search does not catch new kinds of tool poisoning.** MCPTox
  stays at 2 % even with 1 100 generated poisoned tools in the corpus: a
  poisoned tool looks too much like a benign one for nearest-neighbour search
  under a 2 % false-positive budget. A trained classification head on the
  same embeddings does better (study `s7_head.py`: Tensor Trust 75 %,
  MCPTox 8–17 %, generated MCP 46 %, at the same false-positive rate). It is
  not part of this corpus; it needs a decision.
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
  --out hack/vigil-corpus/dist --name e5s-v1 --sources <the sources above, comma-separated>
mv hack/vigil-corpus/dist/vigil-corpus-e5s-v1.lock.json hack/vigil-corpus/
```

A new build gets a new `--name` (e.g. `e5s-v2`). That means new collection
names, so Vigil's `server.conf` must name them too. An old and a new build
never mix.
