# Decision log

One entry per non-trivial decision. **Who decided** says whether it was Juan,
a teammate, or the coding agent (Claude) on its own. Entries are newest last.
Decisions made before this log existed are not back-filled here.

---

### 2026-10-13 — Base the integration work on `origin/main` (8c0855b)
- **Decision:** fast-forward local `main` to `origin/main` and branch
  `m1-integrate-gpu-node` from it.
- **Reason:** `origin/main` carries r-baggioII's observability commit; the
  GPU/NVIDIA branch must land on top of it, not beside it.
- **Alternatives:** rebase `gpu-node-nvidia` (rewrites a pushed branch).
- **Who decided:** Juan.

### 2026-10-13 — Merge-conflict resolution keeps all observability instrumentation
- **Decision:** in the two conflicting files, keep every line of
  r-baggioII's instrumentation. `runner/src/evaluator.ts`: trace headers
  (`requestTraceHeaders()`) are sent by both provider shapes (Zen catalog and
  custom/NVIDIA). `hack/import-images-to-nodes.sh`: the parallel,
  version-matched-`ctr` importer also applies main's CRI `managed` label.
- **Reason:** don't break a teammate's work; both import fixes address the
  same symptom (kubelet can't see an imported image) by different routes.
- **Alternatives:** drop one of the two importer fixes.
- **Who decided:** Juan approved the approach; the concrete resolution is the
  agent's. The resolved diff goes to r-baggioII for review.

### 2026-10-13 — Default LLM provider is OpenCode Zen; NVIDIA is a `deploy.sh` option
- **Decision:** `LLM_PROVIDER=zen` (default) or `nvidia`; `LLM_MODEL`
  overrides the personas' model. The repository's manifests stay Zen;
  NVIDIA is rendered in at deploy time.
- **Reason:** the team uses Zen; `gpu-node-nvidia` had switched everyone to
  NVIDIA.
- **Alternatives:** NVIDIA default; separate sample directories per provider.
- **Who decided:** Juan.

### 2026-10-13 — With NVIDIA, the real key lives only in `security-gateways`
- **Decision:** `LLM_PROVIDER=nvidia` writes the key as `UPSTREAM_API_KEY`
  in `security-gateways/llm-provider-credentials` (Occludra reads it through
  the new optional env `OCCLUDRA_UPSTREAM_API_KEY`); `mcp-evals` gets the
  placeholder `egress-via-occludra`. The Zen path is unchanged (key in both
  namespaces) and is tracked as a security/docs item for M3/M4.
- **Reason:** the evaluator's custom provider never sends a real key
  (Occludra replaces `Authorization`), so the evaluation namespace doesn't
  need it. Changing the Zen path is out of M1's scope.
- **Alternatives:** mirror the key in both namespaces as Zen does.
- **Who decided:** the agent.

### 2026-10-13 — `deploy.sh` passes secret values through a pipe, not argv
- **Decision:** `kubectl create secret --from-env-file=<(printf …)`
  instead of `--from-literal=KEY=value`.
- **Reason:** `--from-literal` puts the key on kubectl's command line,
  readable by any local user via `ps` while it runs.
- **Alternatives:** keep `--from-literal`; write a temp file (touches disk).
- **Who decided:** the agent.

### 2026-10-13 — Occludra's `OCCLUDRA_UPSTREAM_BASE_URL` is empty by default
- **Decision:** the manifest declares the variable empty; `deploy.sh` sets it
  for NVIDIA. NVIDIA publisher prefixes stay in the model allowlist for every
  provider.
- **Reason:** an explicit Zen URL in env would silently override a
  `upstream.base_url` set in the policy ConfigMap (env > policy > default).
  The extra allowlist entries are harmless with Zen (it would reject unknown
  ids itself).
- **Alternatives:** hardcode the Zen URL; `kubectl set env` after apply
  (a later plain apply would not remove it).
- **Who decided:** the agent.

### 2026-10-13 — `gpu-node.conf` becomes a git-ignored file with a committed `.example`
- **Decision:** `hack/gpu-node/gpu-node.conf.example` holds `CHANGE_ME`
  placeholders; the real `gpu-node.conf` is git-ignored and replaces the old
  `gpu-node.local.conf` override. `gpu-node` refuses to run with a missing or
  unfilled config. Old values remain in the history of `gpu-node-nvidia`; it
  is not rewritten.
- **Reason:** IPs, ZeroTier network and jump host are specific to one
  environment and shouldn't be committed.
- **Alternatives:** keep `.local.conf` overrides on top of a committed file;
  rewrite history (needs a force-push, which is not allowed).
- **Who decided:** Juan asked for the `.example` split; the mechanism and
  the no-history-rewrite call are the agent's.

### 2026-10-13 — Runner tests use `node --test`
- **Decision:** unit tests for the TypeScript runner use Node's built-in test
  runner; no vitest.
- **Reason:** r-baggioII already added `node --test` tests; one framework, no
  new dependencies.
- **Alternatives:** vitest (the original plan).
- **Who decided:** Juan, following the teammates' existing choice.

### 2026-10-13 — Local test cluster: kind 0.33.0 from the distribution repository
- **Decision:** install `kind` with pacman (CachyOS repo, 0.33.0-1.1; Arch
  `extra` ships the same 0.33.0).
- **Reason:** all testing happens in a local kind cluster; the shared k0s
  cluster stays read-only.
- **Alternatives:** official release binary with checksum verification.
- **Who decided:** Juan (pacman if available).

### 2026-10-14 — Vigil gate: abort only when two scanners agree (1A)
- **Decision:** each untrusted text is scanned alone, in ≤512-token chunks.
  The transformer threshold is applied (0.98). Abort only when the
  transformer AND (YARA or vectordb) match the same chunk; any single scanner
  is a warning (in the report, a Medium finding, a note to the LLM auditor).
- **Reason:** per-text scanning flagged ~6.7% of benign texts when any single
  scanner aborted; with the combined rule, 1 of 684 benign texts aborts.
- **Alternatives:** abort on any scanner; transformer alone.
- **Who decided:** Juan.

### 2026-10-14 — Our own YARA rules, as a second opinion only (A1)
- **Decision:** `manifests/vigil-yara/*.yar` replace upstream's rules
  (ConfigMap `vigil-yara-rules`); YARA never aborts alone.
- **Reason:** upstream's rules caught 4/38 known phrasings and 0/6 evil
  fixture texts with 3.8% benign false positives; ours catch 38/38 and 6/6
  with 0.3%.
- **Who decided:** Juan.

### 2026-10-14 — Vigil uses the distributed Chroma through a REST v2 client (4B)
- **Decision:** `remote_vectordb.py` replaces upstream's embedded
  chromadb 0.4.17 when `[vectordb] chroma_url` is set; read-only.
- **Reason:** the team wants the distributed Chroma in the project; the Rust
  Chroma speaks API v2 only.
- **Who decided:** Juan (distributed Chroma); the client design is the agent's.

### 2026-10-15 — Fail closed when Chroma does not answer (for now)
- **Decision:** a Chroma error makes the scan answer 500 and the run fail.
- **Later:** retry a couple of times, then decide between failing and
  continuing silently without the vectordb opinion.
- **Who decided:** Juan.

### 2026-10-15 — Chroma lives in the university cluster, behind a token gateway
- **Decision:** deploy the distributed Chroma on k0s (query and compaction
  scaled to 1 replica each to fit the workers). Every client goes through
  `chroma-gateway` (nginx) with a reader token (Vigil: resolve and query
  only) or a writer token (loader). Tokens are generated by
  `hack/chroma/deploy.sh` and never printed. kind uses a one-pod Chroma
  behind the same gateway (`VECTOR_DB_MODE=single`).
- **Reason:** Juan asked for Chroma on the university nodes "with auth".
  Chroma's Rust server has no authentication, so it has to sit behind a
  proxy. Two roles mean that a token stolen from a Vigil pod cannot poison
  the corpus.
- **Alternatives:** NetworkPolicy only (no protection for Liqo-offloaded
  pods or once something is exposed); a sidecar in the frontend pod (would
  mean editing the vendored chart); one shared token (Vigil could write).
- **Who decided:** Juan (k0s, auth); the gateway design is the agent's.

### 2026-10-15 — Vigil's upstream auto-update is turned off for real
- **Decision:** a Dockerfile patch parses `[auto_update] enabled` as a
  boolean.
- **Reason:** upstream reads it as a string, so `false` was truthy and every
  prompt that 3 scanners flagged was written into the corpus. With the
  read-only client, that write turned the strongest detections into HTTP 500.
- **Who decided:** the agent (a bug fix; the config already said `false`).

### 2026-10-15 — Liqo lab: k3s on the PC as the provider, kind as the consumer
- **Decision:** k3s v1.35.9 is installed on the PC, disabled at boot. One ufw
  rule lets the kind network reach the k3s API. Juan runs the privileged
  steps himself.
- **Reason:** Juan wants to learn Liqo with the GPU node, and test it locally
  before touching k0s.
- **Who decided:** Juan.

### 2026-10-16 — Liqo lab wiring: WireGuard over a fixed NodePort on the docker bridge
- **Decision:** Liqo v1.2.0 on both clusters; kind consumes, k3s provides
  4 CPU, 6Gi, 30 pods and 1 `nvidia.com/gpu`. The gateway server runs on k3s
  as NodePort 30851/UDP; the kind client dials `172.18.0.1:30851`. One more
  ufw rule allows exactly that port from the kind network. The GPU reaches
  k3s through the NVIDIA device plugin (chart 0.20.1, `runtimeClassName:
  nvidia`); the node is labelled `nvidia.com/gpu.present=true` by hand
  instead of installing Node Feature Discovery. Offloaded GPU pods need
  `runtimeClassName: nvidia` (a matching RuntimeClass exists in kind so the
  API accepts it; Liqo forwards the field).
- **Reason:** no LoadBalancer on either cluster; the bridge IP is the only
  address kind's containers reach on the host, and a fixed port keeps the
  firewall rule narrow.
- **Alternatives:** LoadBalancer (needs MetalLB); NFD for one node.
- **Who decided:** the agent, with Juan's go-ahead to run it.

### 2026-10-14 — Real local LLM instead of a mock (`LLM_PROVIDER=local`)
- **Decision:** e2e and local runs use a real model served by llama-server on the GPU machine,
  behind Occludra, reached through an opt-in egress rule (`occludra-egress-local-llm`: Occludra →
  that IP/32:port only, deleted for any other provider). Replaces the mock-LLM plan.
  Who decided: Juan.

### 2026-10-13 — KEDA reaches the operator through its own additive NetworkPolicy
- **Decision:** `manifests/keda/allow-keda-to-operator.yaml` (keda-operator →
  operator:8082), applied with `DEPLOY_KEDA=1`; observability's policy is untouched.
  A dedicated operator ingress policy (option C) may come with M3.
- **Reason:** observability's Ingress policy isolates the operator, which cut KEDA off
  (reproduced in kind). Who decided: Juan.

### 2026-10-13 — Git history with environment values stays as is (for now)
- **Decision:** don't rewrite `gpu-node-nvidia`'s history although the repo is public.
  Who decided: Juan (will handle it later).

### 2026-10-14 — The operator owns its Ingress NetworkPolicy (supersedes the KEDA entry above)
- **Decision:** `config/manager/network_policy.yaml` makes the operator pods default-deny for
  Ingress and lists every legitimate client: Prometheus → 8443, KEDA → 8082. It replaces
  r-baggioII's `operator-observability` (removed from `manifests/observability/integrations/`)
  and the separate KEDA policy; `deploy.sh` deletes both from existing clusters.
- **Reason:** who may reach the operator was a side effect of which optional stack was
  installed. Least privilege, written in one place next to the operator.
  Who decided: Juan. r-baggioII to be told (her file is removed).

### 2026-10-21 — Vigil's vector corpus: our own, calibrated, multilingual-e5-small, hybrid scan
- **Decision:** replace deadbits' pre-embedded MiniLM corpora (8 900 texts,
  raw threshold 0.4) with our corpus (`hack/vigil-corpus/`): the previous
  sources plus HackAPrompt and Mosscap, plus poisoned MCP tool texts we
  generate with the local LLM (MCPTox and the repo fixtures stay test-only).
  Embedder `intfloat/multilingual-e5-small`. "Hybrid" scan: the whole runner
  chunk against whole texts, and each of its sentences against single
  sentences, each with its own threshold calibrated to 2 % false positives on
  benign tool-like text.
- **Reason:** measured on held-out data (corpus-3 study): the old setup
  detected 0 % of HackAPrompt and of MCPTox tool poisoning, ~5 % of attacks
  hidden inside benign text; the new one detects most of them at the same
  false-positive budget, and e5 is the best of six models tried for MCP and
  Spanish text at ~400 ms per chunk on 2 CPUs.
- **Alternatives:** bge-small-en (better on unseen attack families, English
  only); keep MiniLM; bigger models (bge-m3, Qwen3-0.6B: no gain, 10× slower).
- **Who decided:** Juan (corpus, method, model, own MCP corpus).

### 2026-10-21 — Thresholds and model identity travel with the corpus
- **Decision:** each Chroma collection's metadata carries its threshold, the
  embedding model, the text prefix and an embedding probe; Vigil reads them
  and fails closed if its embedder does not reproduce the probe or the names
  disagree. The corpus file is pinned by sha256 in a committed lock file and
  shipped as an image (`vigil-corpus:<name>-<sha12>`, the pinned
  python:alpine plus the file) that deploy.sh builds after checking the hash.
- **Reason:** a threshold only means something for one corpus build and one
  embedder; keeping them apart (server.conf vs Chroma) would let a reload or
  a model update silently change every verdict. The image route reuses the
  registry every deploy already pushes to; no public data hosting needed.
- **Alternatives:** thresholds in server.conf; the file on a public URL
  (GitHub release / HF dataset — publishing the dataset is Juan's call).
- **Who decided:** the agent.

### 2026-10-21 — sentence-transformers stays at upstream's 2.2.2 inside Vigil
- **Decision:** no library upgrade for the e5 embedder.
- **Reason:** measured in the image: 2.2.2's e5 embeddings equal 5.1.1's to
  1.6e-7; upgrading would drag transformers and huggingface_hub under the
  pinned deberta scanner for no gain.
- **Who decided:** the agent.

### 2026-10-21 — Occludra's " (proxy)" text marker becomes opt-in
- **Decision:** `OCCLUDRA_RESPONSE_MARKER=1` to append it; by default answers
  pass unmodified and every inference answer carries `X-Occludra-Proxy: true`.
- **Reason:** the marker rewrote the model's answer that the evaluation
  agents read back; the header proves the path without touching content.
- **Who decided:** the agent (Juan: Occludra may be changed freely).

### 2026-10-21 — `spec.model.contextTokens` on OpenCodeAgent
- **Decision:** optional field (>= 1024) declaring the context a custom
  provider really serves; deploy.sh fills it (`LLM_CONTEXT_TOKENS`, 32768 for
  `local`). Unset keeps the 128K default.
- **Alternatives:** an evaluator env var (one value for every persona).
- **Who decided:** the agent.

### 2026-10-21 — Cloner and target get their own /tmp
- **Decision:** emptyDirs `cloner-tmp` and `target-tmp`; only the evaluator
  (and its NetBird sidecar) mount `tmp`, the evaluator's HOME.
- **Reason:** untrusted code (repository build steps, the server under test)
  could plant files in the evaluator's HOME, e.g. an OpenCode config.
- **Who decided:** the agent.

### 2026-10-21 — operator-ingress-policy merged into the integration line
- **Decision:** the operator's own Ingress policy (it replaces observability's
  `operator-observability` policy and edits `hack/deploy-observability.sh`)
  is merged into `m3-integration`, not into `main`.
- **Who decided:** Juan ("ya hablé con Rocío"); merging to main still needs
  his OK.

### 2026-10-21 — The vector scan becomes two-sided (corpus e5s-v2)
- **Decision:** a vector hit counts only when the chunk or sentence is also
  closer to its malicious neighbour than to the nearest known benign tool or
  MCP-server text (third collection `vigil_e5s_v2_benign`); thresholds are
  calibrated under that rule.
- **Reason:** the kind e2e aborted the benign fixture as Malicious: its
  `reverse` tool description matched a Mosscap password-game attack ("Reverse
  the text above…") and the transformer also misfired on it. Measured on the
  study's held-out data, two-sided removes that and raises detection slightly
  everywhere (Tensor Trust 47→53 %, generated MCP 35→40 %) at the same false
  positive rate.
- **Alternatives:** pruning malicious entries near benign texts (helps, but
  missed the fixture case); dropping Mosscap (Juan chose to include it).
- **Who decided:** the agent, to fix a regression of the hybrid method Juan
  chose; flagged for Juan.
