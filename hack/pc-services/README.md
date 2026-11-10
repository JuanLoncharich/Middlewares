# pc-services — what the GPU PC serves to the cluster, by API

The PC is **not** a cluster node. It runs two APIs in Docker, listening only
on its ZeroTier address, and the k0s cluster calls them:

```
 k0s cluster (ZeroTier 10.147.17.0/24)                    GPU PC (10.147.17.21)
 ┌──────────────────────────────────────┐                ┌──────────────────────────────┐
 │ Occludra ── Bearer LOCAL_LLM_API_KEY ─┼──── :8080 ────▶│ llm   llama.cpp, Gemma (GPU) │
 │                                      │                │                              │
 │ operator / evaluator / Occludra      │                │ vigil-auth  nginx: token +   │
 │   └▶ vigil-service:5000              │                │   /analyze/{prompt,response} │
 │        vigil relay (nginx) ─ Bearer ─┼──── :5000 ────▶│   └▶ vigil  scanner (CPU)    │
 │                                      │                │        └▶ chroma  the corpus │
 └──────────────────────────────────────┘                └──────────────────────────────┘
```

- **llm** — llama.cpp's OpenAI-compatible server on the GPU. Occludra is
  its only caller (`LOCAL_LLM_URL` in `deploy/k0s/render.env`).
- **vigil** — the prompt-injection scanner: the same image and `server.conf`
  the cluster ran (`manifests/vigil-deployment.yaml`) and our YARA rules.
  Not published.
- **chroma** — a single-node Chroma with Vigil's corpus (240,459 vectors),
  on this PC's disk. Not published, and on a Docker network with no way out
  that only Vigil joins: Chroma has no authentication of its own.
- **vigil-auth** — nginx in front of Vigil: checks the bearer token and lets
  only the two scan calls (and `GET /ready` for the relay's probe) through.
- In the cluster, `manifests/vigil-remote.yaml` keeps `vigil-service`, now a
  relay that adds the token. Nothing that calls Vigil changed.

PC off → the relay is not ready → scans fail and evaluations and the chat
**fail closed**, as before.

## Use

```bash
hack/pc-services/pc up          # LLM + Vigil, waits until healthy
hack/pc-services/pc up vigil    # just one group: llm | vigil
hack/pc-services/pc status
hack/pc-services/pc smoke       # one call to each API through its token check
hack/pc-services/pc logs vigil
hack/pc-services/pc down
```

Nothing starts at boot (`restart: "no"`). First start of Vigil downloads its
classifier and embedder (~1.5 GB) and loads the corpus into Chroma (a few
minutes), both under `~/.cache/mcp-eval/pc-services/`.

## Setup (once)

1. `cp hack/pc-services/pc.conf.example hack/pc-services/pc.conf` if any
   default does not fit (ZeroTier IP, model path).
2. Tokens, in `~/.config/mcp-eval/` (0600), written by
   `CONTEXT=k0s hack/gitops/secrets.sh deploy/k0s`:
   - `local-llm.key` — the LLM's API key (also in Occludra's Secret);
   - `vigil-api-token` — Vigil's token (also in Secret `vigil-remote-token`).

## Memory

The PC has 14 GiB of RAM and a zram swap, and `systemd-oomd` watches it:
when RAM **and** swap pass 90 % it SIGKILLs the cgroup using the most swap.
A container killed that way shows `Exited (137)` with `OOMKilled=false`
(that flag means only the kernel's OOM killer) and nothing in `dmesg`. To check:
`journalctl --since today | grep systemd-oomd`.

On 2026-11-10 that cgroup was the LLM, twice: its weights and KV are in
VRAM, but llama.cpp also keeps prompt states in host RAM (`--cache-ram`,
default 8192 MiB, plus 32 context checkpoints per slot). Long agent prompts
(30k tokens) grew it to ~5 GiB in swap, and Vigil's start-up peak (3.5 GiB
while it loads its models, ~0.7 GiB after) tipped the PC over. The LLM now
runs with `LLM_CACHE_RAM=1024` and `LLM_CTX_CHECKPOINTS=8` (`pc.conf`).

Measured with Gemma 4 12B, 12 different 25k-token prompts:

| service | RAM | VRAM |
|---|---|---|
| llm | 1.1–2.8 GiB resident + ≤1 GiB swap | ~11 GiB |
| vigil | ~0.7 GiB (3.5 GiB peak at start) | — |
| chroma | ~0.25 GiB (0.7 GiB peak) | — |

Anything else heavy on the PC (a kind cluster, Plato) eats into this margin.

## The corpus lives on the PC

Vigil compares every text with a corpus of known injections kept in Chroma.
Until 2026-11-10 it read the cluster's distributed Chroma through Traefik,
so a scan needed six cluster pods and the ZeroTier path to be healthy; when
a worker went down, scans answered 500 and the whole platform failed closed.

Now `pc up` starts a one-container Chroma here and fills it once from the
corpus image the cluster uses (`VIGIL_CORPUS_IMG` in `deploy/k0s/render.env`;
the loader checks the file's sha256 against
`hack/vigil-corpus/vigil-corpus-e5s-v3.lock.json`). A new corpus in
`render.env` is loaded on the next `pc up`, and the old one is deleted.

To reload from scratch: `pc down vigil`, delete
`~/.cache/mcp-eval/pc-services/chroma`, `pc up vigil`.
