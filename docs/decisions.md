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
