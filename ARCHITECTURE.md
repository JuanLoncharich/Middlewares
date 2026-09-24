# Architecture — MCP Server Security Evaluation Platform

Automated static + dynamic security evaluation of Model Context Protocol (MCP)
servers on Kubernetes, wrapped in a three-layer LLM security perimeter
(**Vigil** inbound prompt-injection scanner → **Occludra** outbound LLM-egress
redaction gateway → **NetBird** WireGuard transport mesh), plus a containerized
OpenCode "programmer's workstation" that reaches LLMs through the same
perimeter from the host's Docker.

```
                              ┌────────────────────────────────────────────────┐
   operator plane             │ ns mcp-eval-system                             │
                              │ Deployment mcp-eval-controller-manager (--leader-elect)
                              │  ├─ MCPServerReconciler       cron → runs      │
                              │  └─ MCPEvaluationRunReconciler Job builder     │
                              └───────────────┬────────────────────────────────┘
                                              │ creates / owns / watches
                              ┌───────────────▼────────────────────────────────┐
   execution plane            │ ns mcp-evals (PodSecurity restricted: enforced) │
   one batch/Job per run      │ MCPEvaluationRun Job → Pod                      │
                              │  ├─ init  cloner     git clone + toolchain      │
                              │  ├─ side  netbird    userspace WG + SOCKS5 :1080│
                              │  ├─ ctr   target    UNTRUSTED MCP server        │
                              │  │                  stdio ⇄ /ipc FIFOs          │
                              │  └─ ctr   evaluator  @opencode-ai/sdk runner    │
                              │           ├─ OpenCode child server 127.0.0.1:4096+
                              │           ├─ Vigil /analyze (inbound scan)      │
                              │           └─ LLM calls ──► Occludra /v1         │
                              └───────┬───────────────────────────┬─────────────┘
                              Vigil    │                           │  completions
                              ┌────────▼─────────┐    ┌────────────▼───────────┐
   gateway plane              │ Deployment vigil │    │ Deployment occludra    │
   ns security-gateways       │ :5000 /analyze   │    │ :8080 /v1 (OpenAI API) │
   (PSA privileged: TUN only) │ 2 replicas + PDB │    │ 2 replicas + PDB       │
                              │ [stub: heuristics│    │ regex redaction,       │
                              │  no DB]          │    │ hot-reloaded policy    │
                              └────────┬─────────┘    └────────────┬───────────┘
                                       │  NetBird WireGuard mesh   │ replaces Authz
                                       └───────────┬───────────────┘ with secret key
                                                   ▼
                                        upstream LLM: OpenCode Zen
                                        https://opencode.ai/zen/v1

   workstation plane          docker container opencode-programmer (net `kind`)
   programmer's laptop ────── NodePort 30080 → occludra / 30500 → vigil
```

---

## 1. Component inventory — what each artifact *is*

Every row names the artifact, its concrete Kubernetes (or Docker) kind, where
its code lives, and whether it holds state.

| Artifact | Kind / type | Namespace / scope | Source | State |
|---|---|---|---|---|
| `MCPServer` | **CRD** (`security.eval.io/v1alpha1`, shortname none) | cluster-scoped resource, ns `mcp-evals` instances | `api/v1alpha1/mcpserver_types.go` | instance state in etcd (`status`) |
| `MCPEvaluationRun` | **CRD** (shortname `mcprun`), has `status` **subresource** | ns `mcp-evals` | `api/v1alpha1/mcpevaluationrun_types.go` | primary results store (etcd) |
| `OpenCodeAgent` | **CRD** | ns `mcp-evals` | `api/v1alpha1/opencodeagent_types.go` | persona config (etcd) |
| `MCPServerReconciler` | **controller** (Reconcile loop, controller-runtime) | runs inside manager pod | `internal/controller/mcpserver_controller.go` | stateless; recomputes from etcd each pass |
| `MCPEvaluationRunReconciler` | **controller** | same | `internal/controller/mcpevaluationrun_controller.go` (1437 lines) | stateless; builds Jobs, watches Pods |
| controller-manager | **Deployment** `mcp-eval-controller-manager` (2 replicas, `--leader-elect`, PDB minAvailable 1, topology spread, `PriorityClass mcp-eval-critical`) | `mcp-eval-system` | repo root `Dockerfile`, `cmd/main.go` | none (etcd is the state) |
| cloner | **init container** of the run Pod | `mcp-evals` | `images/cloner/` (bash) | writes `/workspace`, exits |
| target sandbox | **container** (`target`) of the run Pod, UID 10002 | `mcp-evals` | `images/target/` (bash supervisor) | ephemeral, jailed |
| evaluator | **container** (`evaluator`) of the run Pod, UID 10001 | `mcp-evals` | `runner/` (TypeScript → `dist/evaluator.js`) | ephemeral; writes results to 4 places (§8.1) |
| OpenCode child server | **in-process subprocess** spawned by the SDK inside the evaluator container (`opencode serve`, loopback 4096+) | evaluator container | npm `opencode-ai` | session files in container `/tmp` |
| netbird run sidecar | **sidecar container** (userspace WireGuard) | run Pod | `netbirdio/netbird:latest` | emptyDir `/var/lib/netbird` |
| netbird node client | **DaemonSet** `netbird-node` (TUN mode, CAP_NET_ADMIN) | `security-gateways`, 1/node | `manifests/netbird-daemonset.yaml` | emptyDir state |
| Occludra gateway | **Deployment** `occludra` (2 replicas, PDB min 1, rolling maxUnavailable 0) + **Service** `occludra-service` (ClusterIP 8080) + **Service** `occludra-np` (NodePort 30080) | `security-gateways` | `images/occludra-gateway/` (Go, single file `main.go`) | **stateless**; policy read per-request |
| `occludra-policy` | **ConfigMap** (mounted at `/conf`, watched per-request) | `security-gateways` | `manifests/occludra-deployment.yaml` | policy source of truth (etcd) |
| Vigil scanner | **Deployment** `vigil` (replicas via `VIGIL_REPLICAS`, default 2; HPA 70 % CPU, `VIGIL_HPA_MIN`→8; PDB) + **Service** `vigil-service` (ClusterIP 5000) + **Service** `vigil-np` (NodePort 30500) | `security-gateways` | dev: `images/vigil-stub/` (Python, six engines, models baked); prod pin `deadbits/vigil-llm:latest` | **stub: stateless** (~2.5 GiB RSS with both deberta sessions); vector scan queries the distributed Chroma (§5.2.1) |
| Distributed Chroma | SysDB coordinator (`sysdb`) + Rust SysDB + Log Service WAL (StatefulSet) + **2 Query Nodes** + **2 Compactors** + Work Queue + Fn Consumer + Garbage Collector + Rust frontend (REST v2 :8000); chart vendored at `manifests/chroma/chart/` | `chroma` | `manifests/chroma/` (chart + values + worker/frontend configs), images `chromadb/<svc>:<sha>` | object segments in **MinIO**; catalog in **Postgres** |
| `vigil-server-conf` | **ConfigMap** (`server.conf`, scanner enable/disable) | `security-gateways` | `manifests/vigil-deployment.yaml` | scanner profile (etcd) |
| NetworkPolicies | **NetworkPolicy** ×5 static + **1 generated per run** (`<run>-evaluate-egress`) | `security-gateways` / `mcp-evals` | `manifests/occludra-deployment.yaml`, `workstation-nodeport.yaml`, controller §4 | — |
| LLM credentials | **Secret** `llm-provider-credentials` (key `OPENCODE_API_KEY`) — exists in **both** `mcp-evals` (evaluator passes it to its own gateway calls' config; real key upstream lives in the gateway) and `security-gateways` (decoded only by occludra) | both ns | created by `deploy.sh` | etcd |
| netbird auth | **Secret** `netbird-auth` (setup key) | `security-gateways` | `deploy.sh` | etcd |
| workstation | **Docker container** `opencode-programmer` (NOT a Kubernetes resource) on docker network `kind` | host Docker | `images/opencode-workstation/` | config in `$HOME/.config/opencode` |
| local registry | **Docker container** `kind-registry` (`registry:2`, `localhost:5001`) | host Docker | kind setup | image layers on volume |
| kind cluster | **kind** `mcp-test` (node `mcp-test-control-plane`, k8s v1.33.1, CNI kindnet — **does enforce** NetworkPolicy via nftables NFQUEUE) | host Docker | — | etcd on node disk |

The evaluation state itself lives exclusively in etcd (§8); the vector plane
(§5.2) is the one deliberate exception to "no application database": the
distributed Chroma cluster keeps its object segments in MinIO and its
catalog in Postgres, walled off in namespace `chroma`.

---

## 2. API plane — the CRDs in full

Group `security.eval.io`, version `v1alpha1` (`api/v1alpha1/groupversion_info.go`);
deepcopy generated (`zz_generated.deepcopy.go`); CRD manifests in
`config/crd/bases/`. All three CRDs carry standard `conditions []metav1.Condition`.

### 2.1 `MCPServer` — the scheduling unit
| Spec field | Type / validation | Default | Notes |
|---|---|---|---|
| `repositoryUrl` | string, **pattern `^https://`** | required | http git URLs refused at admission |
| `ref` | string | `main` | cloner rejects refs starting with `-` (option-injection guard) |
| `path` | string, no leading `/`, no `..` | — | repo sub-directory containing the server |
| `transport` | enum `stdio` \| `sse` | `stdio` | sandbox transport |
| `targetPort` | int ≥1024 | `8080` | SSE listen port |
| `schedule` | string, 5-field cron (standard) | required | parsed by `cron.ParseStandard` |
| `active` | *bool | `true` | `false` pauses scheduling, clears `nextScheduledTime` |
| `credentialsSecretRef` | string | — | optional private-repo credentials |
| `agentSuite[].name` | []AgentReference, ≥1 | required | names of `OpenCodeAgent`s to run |
| `timeoutSeconds` | int ≥60 | `900` | → Job `activeDeadlineSeconds` |
| `runHistoryLimit` | int ≥0 | `5` | terminal runs retained per server |

Status: `lastEvaluationDate`, `nextScheduledTime`, `overallRiskStatus`
(`Safe/Caution/Untrusted/Malicious/Unknown`), `lastRunRef`.

### 2.2 `MCPEvaluationRun` — the results record (shortname `mcprun`)
Spec: `serverRef` (required), `agents[]` (required, ≥1),
`timeoutSeconds` (default 900). **Status is the platform's durable results
store** — written by the evaluator through the status subresource and
confirmed by the run controller:

| Status field | Written by | Content |
|---|---|---|
| `phase` | both | `Pending → Cloning → Running → Evaluating → Completed \| Failed` (enum) |
| `currentAgent` | evaluator | persona currently executing |
| `agentResults` map[agent]→**schemaless JSON** (`RawExtension`, `PreserveUnknownFields`) | evaluator, **incrementally after each agent** | full structured output per persona — survives later agent failures |
| `findings[]` | evaluator | `{agent, severity: Critical/High/Medium/Low/Info, title, description, remediation}` |
| `finalScore`, `scoring{safetyScore, reliabilityScore ∈ 0–100, riskCategory ∈ Safe/Caution/Untrusted/Malicious/Unknown, summary}` | evaluator (synthesizer) | final verdict |
| `message` | both | failure stage/agent + error class, or completion summary |
| `jobName`, `startTime`, `completionTime` | controller | lifecycle |
| conditions | both | `Ready`, etc. |

Printer columns: Phase, Server, Score, Risk, Age.

### 2.3 `OpenCodeAgent` — persona-as-data
`role` (string; evaluator routes `StaticSecurityAuditor`→static evidence,
`DynamicProtocolFuzzer`→dynamic, `RogueBehaviorProbe`→adversarial,
`SynthesisScorer`→synthesis; anything else = generic synthesis of all prior
outputs) · `model{providerID, modelID, timeoutMs=30000, retryCount=2}` ·
`systemPrompt` · `outputFormat{type: "json_schema" (enum), schema: RawExtension}`
· `config` (free-form, reserved). Shipped personas (`config/samples/`):
`mcp-sast-auditor` (SAST), `mcp-fuzz-tester` (fuzz), `mcp-rogue-detector`
(probes), `mcp-synthesizer` (synthesis) — all `opencode/muse-spark-1.3-contributor-free`.

---

## 3. Operator plane — the two controllers

### 3.1 `MCPServerReconciler` (`internal/controller/mcpserver_controller.go`)
Reconcile order (every pass, stateless):
1. Fetch MCPServer. If `active=false`: clear `nextScheduledTime`, idle.
2. Parse `schedule` with `cron.ParseStandard`; compute next fire from **wall
   clock vs `status.lastEvaluationDate`** (no in-memory timers → correct
   after operator restart/failover; missed fires fire once on catch-up).
3. `isDue()` → if due **and** `security.eval.io/trigger-now=true` annotation
   present **or** schedule elapsed: `createRun()` builds an MCPEvaluationRun
   (copies `serverRef`, agent names, timeout); then
   `clearTriggerAnnotation()` removes the annotation.
4. `missingAgents()` validates `agentSuite` names resolve to existing
   OpenCodeAgents; unresolved names are reported in status rather than
   silently skipped.
5. `syncLatestRunResult()` mirrors the newest terminal run's
   finalScore/risk into `MCPServer.status` (so `kubectl get mcpserver`
   answers without joins).
6. `pruneRuns()` deletes oldest terminal runs beyond `runHistoryLimit`.
7. Requeue at `min(next fire, fallback)`.

### 3.2 `MCPEvaluationRunReconciler` (`internal/controller/mcpevaluationrun_controller.go`)
Owns run → Job → Pod. Key mechanics:

- `buildJob()` (line ~772) constructs the batch/Job:
  - containers: init `cloner` → sidecar `netbird` (starts first as a regular
    container before `target`/`evaluator` need it) → `target` → `evaluator`;
  - `backoffLimit: 0` at the Job level (evaluation-verdict failures fail
    loudly), `ttlSecondsAfterFinished: 600` (Job + Pod garbage-collected 10 min
    after terminal), `activeDeadlineSeconds: spec.timeoutSeconds`. The RUN
    controller adds the recovery layer on top: transient infrastructure
    failures (Evicted / NodeLost / image-pull stuck / OOMKilled / pod Pending
    with no container progress for 5 min) delete and recreate the Job, bounded
    by `status.retries ≤ 2` (condition `Retried`, event `JobRetried`); beyond
    that the run fails `JobRetriesExhausted`. A transient error while CREATING
    the Job (API-server 5xx/timeouts/network) is retried with
    controller-runtime backoff instead of failing the run — only Invalid /
    Forbidden-class errors fail it permanently.
  - Terminal runs delete their per-run `<run>-evaluate-egress` NetworkPolicy
    (owner-ref GC remains the backstop when the run object is deleted), so
    retained history runs no longer accumulate stale policies.
  - `complete()` no longer silently marks Completed at score 0: with no
    termination message AND no recorded `agentResults`/`scoring` the run fails
    `EvaluatorResultsMissing`; with results present (patched by the evaluator
    before it lost its termination message) it completes from them.
  - Pod `automountServiceAccountToken: false` globally; **only the evaluator
    mounts** a 1-hour projected SA token (`mcp-eval-runner`) — RBAC limited
    to `get/list/watch/patch/update` MCPEvaluationRun **status** (config/rbac/runner_role.yaml);
  - env injected into evaluator: `OPENCODE_API_KEY` (secret
    `llm-provider-credentials`), `VIGIL_URL`, `VIGIL_ENABLED`,
    `VIGIL_ENFORCE`, `VIGIL_TIMEOUT_MS`, `VIGIL_MAX_PAYLOAD_BYTES`,
    `OCCLUDRA_BASE_URL`, `OCCLUDRA_ENABLED`, `MESH_PROXY`,
    `MESH_BRIDGE_PORT=18080`, `RUN_NAME`, `WORKSPACE_DIR=/workspace`,
    `IPC_DIR=/ipc`, `OUTPUT_DIR=/output`, `RUN_NAMESPACE/RUN_NAME` for status patches;
  - volumes (§8 for backing): `/workspace` shared workspace,
    `/ipc` FIFOs, `/tmp`, `/output` reports, `/token` projected.
- **Phased egress**: pod label `security.eval.io/net-phase` starts `clone`
  (NetworkPolicy allows only git hosts + package registries :443); the
  controller flips it to `evaluate` **once, exactly**, after all init
  containers terminate (`ensureEvaluateNetPhase`, line ~580).
- `ensureEvaluateNetworkPolicy()` (line ~1194) creates the per-run
  `<run>-evaluate-egress` NetworkPolicy **before the Job exists** — the
  comment in code: created BEFORE the Job "so the net-phase label flip never
  has a window" without coverage. Mesh mode contents: DNS to kube-dns,
  API-server endpoint IPs (`resolveAPIServerAddresses()`, resolved at
  reconcile time), NetBird control/data plane (UDP 51820, relay ports).
  Legacy mode (`MESH_ENFORCE=false`): + gateway service ports 8080/5000 and
  public 443.
- Watches the run Pod: `complete()` (line ~453) confirms evaluator-written
  results and timestamps; `fail()` (line ~504) records stage/agent + error
  class into `status.message`; both also rely on the evaluator's
  `/dev/termination-log` for `kubectl describe` visibility.
- Manager flags (`cmd/main.go`): `--metrics-bind-address` (default off),
  `--health-probe-bind-address :8081`, `--leader-elect` (**enabled** via
  manager.yaml; Deployment replicas: 2 — one active, one hot standby, PDB
  minAvailable 1 + topology spread). `/readyz` includes a real API-server
  reachability check (`internal/controller/health.go`: GET on the API
  server's own `/readyz`, cached 5 s), so a wedged manager leaves Service
  endpoints instead of holding its lease blind.

---

## 4. Execution plane — the run Job, container by container

### 4.1 Cloner (init container, `images/cloner/clone.sh`)
Input validation (fail-fast, security-oriented): `REPO_URL` must be https,
`REPO_REF` must not start with `-`, `REPO_PATH` relative without `..`,
transport ∈ {stdio, sse}. Then: shallow `git clone` into `/workspace/repo`,
toolchain detection (node/npm → `npm install`; python/uv → `uv sync`;
go → `go build`), and emission of `/workspace/.mcp-launch.json`
`{cmd, args, cwd, transport, port}` — the contract the target supervisor
consumes. Runs only during net-phase `clone`.

Every network-facing step (git clone/fetch, npm ci/install, uv pip install,
go build) runs through a `bounded()` helper: 300 s wall-clock timeout × 3
attempts with 5 s backoff (`OP_TIMEOUT_SECONDS` / `OP_RETRIES`), plus
`GIT_HTTP_LOW_SPEED_*` guards — a flaky registry or hung upstream retries or
fails early instead of silently burning the whole Job deadline
(backoffLimit is 0 and this init container is the single clone attempt, so
the script itself must be the recovery layer).

### 4.2 Target sandbox (`images/target/entrypoint.sh`)
Jails the **untrusted** MCP server (the threat model's adversary):
- securityContext: UID 10002 (distinct from evaluator 10001), `runAsNonRoot`,
  `readOnlyRootFilesystem`, all caps dropped, `allowPrivilegeEscalation: false`,
  RuntimeDefault seccomp; **no** secrets, **no** SA token, **no** CA bundle;
  `/workspace` mounted **read-only**; writable: `/tmp` and `/ipc` only.
- stdio transport: server stdin/stdout bound to named FIFOs
  `/ipc/stdin` + `/ipc/stdout` — its only I/O channel; never leaves the Pod netns.
  (FIFO open blocks until the evaluator opens the counter-end — built-in
  rendezvous.)
- sse transport: server bound to `127.0.0.1:$MCP_PORT` (loopback only).
- Supervisor restarts the server on crash (bounded restarts), logs to its
  own channel bounded by the 64Mi `/tmp` sizeLimit.

### 4.3 Evaluator (`runner/src/*.ts`, compiled to `dist/evaluator.js`)
The orchestrator. Module map:

| File | Responsibility |
|---|---|
| `evaluator.ts` | main() flow, agent orchestration, OpenCode boot (`bootOpencode`: `createOpencode` spawns `opencode serve` on 127.0.0.1:4096+ with config `{model, permission:"deny", autoupdate:false, share:"disabled", snapshot:false, provider.opencode.options.baseURL = OCCLUDRA_BASE_URL}`), structured-output recovery from plain text, report writing. **Degraded continuation**: a failing persona is recorded in `agentResults` and the remaining agents still run; the run completes `degraded: N/M failed` when ≥1 agent succeeded and fails only when all failed. Strict-mode Vigil detections stay a hard abort. Process-level `uncaughtException`/`unhandledRejection` handlers patch `Failed` + write the termination message before exiting; SIGTERM aborts the in-flight agent's OpenCode call via its AbortController; before the first security-gateway call the runner waits for the netbird SOCKS5 proxy to accept connections (`MESH_READY_TIMEOUT_MS`, default 60 s) |
| `k8s.ts` | status writer: **merge-patch on the status subresource** (`patchNamespacedCustomObjectStatus`), retry w/ backoff, never throws; patches carrying a terminal phase get extended backoff and a final `flushTerminalPatch()` from the shutdown path (a lost terminal write would otherwise strand the CR non-terminally); a 404 (run deleted) aborts retries; `fetchAgent`/`fetchServer` retry transient API errors and fail fast on 404; dry-run mode reads `${OUTPUT_DIR}/server.json` + `agents/<name>.json` instead of the API |
| `vigil.ts` | VigilClient: POST `/analyze {prompt}` with timeout + retry/backoff; verdict parsing across all response shapes; `VigilUnavailableError` classification (caller decides strict fail-closed vs monitor); `excerptOf` for logs |
| `meshhttp.ts` | NetBird transport: SOCKS5 (RFC 1928) client with user/pass auth staging; `fetch-over-SOCKS5` for the evaluator's own Vigil/Occludra calls; `waitForSocks5Proxy()` readiness gate; local **HTTP↔SOCKS5 bridge** listener on `127.0.0.1:18080` exported as `HTTP_PROXY`/`HTTPS_PROXY` so the OpenCode child process (cannot be taught SOCKS5) rides the mesh too; bridged upstream requests and CONNECT tunnels carry a 10-min inactivity bound so a hung netbird cannot stall them forever |
| `mcpclient.ts` | MCP client over stdio-FIFO or SSE loopback transport |
| `static.ts` | SAST evidence: repo tree, launch metadata, flagged patterns |
| `fuzz.ts` | protocol fuzzing: ~25 mutated cases per advertised tool (type confusion, boundary values, injection strings in arguments), error/telemetry capture |
| `probes.ts` | rogue-behaviour probes: indirect instruction injection via tool results, exfil-attempt detection |
| `types.ts` / `logger.ts` | shared types, structured JSON logging |

main() order: env validation → status `Running` → mesh bootstrap (SOCKS5 +
bridge + proxy env) → MCP connect + initialize → collect advertised surface
→ **Vigil scan `source="advertised-surface"`** (initialize instructions, tool
descriptions, prompts, resources — strict mode aborts the run on detection:
score 0, riskCategory Malicious, Critical finding; unreachable scanner also
fails closed) → per agent (suite order): status `Evaluating` + `currentAgent`
→ evidence assembly per role → prompt via OpenCode → Vigil scan of
tool/probe outputs (`source="fuzz-responses"` etc.) → **status patch
`agentResults[<agent>]` immediately** → next → synthesizer scores 0–100
safety/reliability, risk category, findings → status `finalScore/scoring` →
`Completed` → write report → exit.

**Zen free-tier gate (2026-09 fix, forensics in `dlp-test-results/forensics/`)**:
OpenCode Zen's free tier rejects `/responses` bodies lacking tool definitions
containing at least `bash` and `read` ("free tier can only be used from
within OpenCode") — headers are irrelevant (CLI and SDK send byte-identical
header sets). `toolsForKind()` therefore advertises exactly
`{bash:true, read:true}` while `permission:"deny"` at boot keeps every tool
execution refused — posture unchanged, gate satisfied. The gateway also
normalizes `tool_choice` to `"auto"` (Zen rejects `"none"`; the CLI itself
sends `"auto"`). Reference completed run: `filesystem-mcp-run-vnrsr`
(score 47, Caution).

---

## 5. Security-gateway plane (namespace `security-gateways`)

The namespace is PodSecurity **privileged** for exactly one reason: the
gateway netbird sidecars need `CAP_NET_ADMIN` for their TUN devices. Nothing
untrusted is ever scheduled here.

### 5.1 Occludra — LLM egress redaction gateway
**Kind**: Deployment ×2 (PDB minAvailable 1, rolling maxUnavailable 0, topology
spread, `PriorityClass mcp-eval-critical`) + ClusterIP `occludra-service:8080`
+ NodePort `occludra-np:30080`. Stateless Go service
(`images/occludra-gateway/main.go`); the only LLM egress point of the platform.
HTTP probes hit the real `/healthz`; **graceful shutdown** drains in-flight LLM
streams on SIGTERM (25 s budget inside the pod's 30 s grace period); the server
sets `ReadHeaderTimeout`/`IdleTimeout` (WriteTimeout stays unlimited so SSE
responses are never cut mid-stream) and the upstream client uses a tuned
Transport (`MaxIdleConnsPerHost: 20`, `IdleConnTimeout: 90s`). No upstream
retry: LLM POSTs are not idempotent and the evaluator's per-agent retry
already covers transient failures.

Request pipeline for `POST /v1/chat/completions` and `/v1/responses`
(everything else proxies verbatim; `/healthz` for probes):
1. Read body (cap 32 MiB), parse JSON object.
2. **Model allowlist** — bare model id must match one of:
   `^(claude|muse|grok|kimi|qwen|glm|deepseek|gemini|minimax|step)`,
   `.*-free`, `^o[1345]`, `^gpt` — else `403` before any upstream dial.
3. **Recursive redaction**: walk every string value in the JSON tree
   (messages, system prompts, tool names, everything), apply detectors
   in order, replace matches with `[REDACTED]` (`default_action: redact`;
   per-detector `action: block` rejects with `403` instead).
4. `tool_choice` normalization → `"auto"` (Zen free-tier compat; logged).
5. **Authorization replacement**: client's Authorization header is dropped;
   `Authorization: Bearer <OPENCODE_API_KEY from secret>` injected — per-client
   credentials never travel upstream and need not exist.
6. Proxy to `OCCLUDRA_UPSTREAM_BASE_URL` (default `https://opencode.ai/zen/v1`),
   streaming the response back with per-chunk flush (SSE-safe, 10-min client timeout).

Detector set (ConfigMap `occludra-policy`, **hot-reloaded per request** —
kubelet propagates ConfigMap volume updates; the gateway re-reads the file
on every scrub request and keeps the previous policy on transient read/parse
errors, so updates converge without restarts and are never mixed mid-request):

| Detector | Pattern class | Example caught |
|---|---|---|
| `email` | emails | `jane.doe@acme.com` |
| `us-ssn` | `NNN-NN-NNNN` | `123-45-6789` |
| `phone-intl` | intl phone shapes | `+1 555 234 5678` |
| `iban` | IBAN | `DE89 3704 …` |
| `api-key` | `sk-…`(16+), `AKIA…`(16), `ghp_/gho_…`(20+), `xox…`, `-----BEGIN … PRIVATE KEY-----` | `sk-proj-9Xk…` |
| `bearer-token` | `bearer/authorization [: = ]` + 16+ chars | `Authorization: Bearer eyJ…` |
| `password-context` | `password/passphrase/passcode/passwd (is\|are\|:\|=) ≥6 non-space` | `password is Xq7vR2mKp9wZ4tFj` |
| `secret-assignment` | `api key\|secret\|token\|credential (is\|are\|:\|=) ≥8` | `secret: hunter2222…` |
| `person-name-context` | role word (`customer/client/patient/employee/subscriber/beneficiary`) + optional honorific + `First Last` | `customer, Richard Philips` |
| `large-amount` | ≥6-digit bare numbers, comma-grouped | `1300201`, `1,300,201` |
| `currency-amount` | `$ € £ USD EUR`-prefixed amounts | `$1,300,201` |

Logging: `log_prompts: false`, `log_redactions: true` → exactly one line per
scrubbed request, **counts and detector names only** (e.g.
`model "muse-spark-1.3-contributor-free": 2 redaction(s) person-name-context=1,large-amount=1`);
content-identical requests emit nothing. Absence of a log line = clean
pass-through.

### 5.2 Vigil — inbound prompt-injection scanner
**Kind**: Deployment ×2 (PDB) + ClusterIP `vigil-service:5000` + NodePort
`vigil-np:30500`. Contract: `POST /analyze {"prompt": "…"}` →
`{"injection_detected": bool, "confidence": float (0–1),
"status": "blocked"\|"allowed", "scanners": [names], "runs": {…}}`;
`GET /health` (also the probe target, with a startupProbe absorbing slow
corpus-loading boots). Content is never logged (`log_payloads: false`).
The netbird TUN sidecars on both gateways are liveness-probed with the same
exec check the DaemonSet uses (`test -S /var/run/netbird/wt0.sock || ip link
show wt0`) so a wedged sidecar is restarted instead of silently dropping the
pod from the mesh; the userspace run sidecar (no TUN, no stable socket path)
relies on the evaluator's SOCKS5 readiness gate + run-level retries instead.

**Deployed implementation today is the test double** (`images/vigil-stub/`,
Debian-slim Python, UID 10004, read-only rootfs): **six detection engines**,
verdict = OR over the engines that fire, each degrading independently
(`runs.<engine>.available: false`, 60 s init-retry cooldown) so no single
engine can fail a request:

| Engine | Mechanism | Threshold / default |
|---|---|---|
| `heuristics` | deterministic regex families, 0.6 per hit (cap 1.0) | fires at score ≥ 0.5 (`VIGIL_STUB_THRESHOLD`); `VIGIL_STUB_ALWAYS_BLOCK=1` forces a detection for abort-path drills |
| `yara` | vigil-llm's own rules vendored into the image (`data/yara/*.yar`, Apache-2.0) via yara-python | any rule match fires (10 rules: instruction bypass, secrets, ReAct patterns, …) |
| `vector` | all-MiniLM-L6-v2 (int8 ONNX, baked) → distributed Chroma (§5.2.1) | cosine distance < 0.45 (`VIGIL_VECTOR_THRESHOLD`) |
| `transformer` | protectai/deberta-v3-base-prompt-injection (the vigil-llm config's model lineage), fp32 ONNX baked | P(INJECTION) > 0.98 (`VIGIL_TRANSFORMER_THRESHOLD`) |
| `canonical` | protectai/deberta-v3-base-prompt-injection-v2 — stands in for vigil-llm's retired `canonical` classifier, an independent training run | P(INJECTION) > 0.85 (`VIGIL_CANONICAL_THRESHOLD`) |
| `sentiment` | VADER negative-sentiment signal (upstream-identical semantics) | neg > 0.7 (`VIGIL_SENTIMENT_THRESHOLD`) |

All model artifacts are baked at build (no runtime downloads, container
boots offline); deberta models ship **fp32 on purpose** — dynamic int8
quantization corrupts deberta-v3's disentangled attention (verified:
obvious injections scored 0.003 post-quantization). The engines warm up
sequentially at startup (~20 s) and `/health` answers 503 until the pass
completes, so probes hold the pod out of the endpoints while the ~1.5 GiB
of models load. Measured on the deployed stack: paraphrased injections fire
heuristics+transformer+canonical+vector, the DAN jailbreak fires
transformer+canonical+vector (0.41 against the jailbreak corpus), a pasted
RSA key fires yara+transformer+canonical, benign prompts pass clean;
~1–3 s per scan with all six engines.

Heuristic families (the `heuristics` engine):

| Pattern (abridged) |
|---|---|
| `ignore-instructions` | `(ignore\|forget\|disregard\|drop\|override\|bypass)` … ≤40 chars … `(instructions\|prompts\|rules\|directives)` |
| `reveal-system-prompt` | `(reveal\|print\|output\|repeat\|show\|display\|expose\|disclose\|leak\|dump)` … `(system prompt\|your prompt\|initial/hidden/operating instructions)` |
| `role-hijack` | `you are now a/an …` |
| `disregard-safety` | `disregard (all\|any) (safety\|content) …` |
| `exfiltration` | `curl/wget/fetch/POST http…` + env/HOME/PATH/TOKEN/KEY |
| `exfil-marker` | `send (all\|the) (data\|content\|files) to http…` |
| `hidden-instruction` | `[system]`, `(system note)`, `<\|im_start\|>` |
| `credential-harvest` | `api key\|password\|secret\|token [:=] ≥8 chars` (requires the separator — "password is X" passes here; that path is Occludra's job on egress) |

The `vector` engine (active when `VIGIL_CHROMA_URL` is set, the deploy.sh
default) embeds the prompt and queries the **distributed Chroma cluster**
(§5.2.1) over its REST v2 frontend. Measured separation on the deployed
stack: paraphrased injections ≈ 0.23–0.27, jailbreak role-hijacks ≈ 0.41,
benign prompts ≥ 0.73. Failure policy mirrors vigil-llm's: an outage of any
engine — including the whole vector plane — degrades that engine's verdict
(`runs.<engine>.available: false`, 60 s init-retry cooldown) rather than
failing the request; a reload of the deployment clears cached failures.

**The production image (`deadbits/vigil-llm`) is a scanner *library* over
several detection engines** — what the stub replaces:
- heuristic regex + **YARA** rule scanning (offline, fast);
- a **canonical prompt-injection classifier** (BERT-family, model download);
- **embedding-similarity scanning backed by a real vector database** — the
  upstream implementation uses an *embedded on-disk* ChromaDB inside the
  container; this platform instead runs the distributed cluster below and
  keeps the scanner stateless;
- optional response-side scanners (sentiment, canary/leaked-secret detection).

In the shipped ConfigMap (`vigil-server-conf`) the upstream-embedded ML
scanners (`canonical`, `transformer`, `vector`) remain **commented out** —
the vector layer is served by the distributed cluster, so the real image
needs no PV and no on-disk database to gain the same detection class. The

#### 5.2.1 Distributed Chroma over MinIO (namespace `chroma`)

The vector plane is a full **distributed Chroma** deployment, rendered from
chroma-core's own chart (`manifests/chroma/chart/`, vendored from
`chroma-core/chroma@30d701a4`, values + worker configs in `manifests/chroma/`)
and deployed by `deploy.sh` with `DEPLOY_VECTOR_DB=1` (default):

| Component | Implementation | Role |
|---|---|---|
| SysDB coordinator (`sysdb`) | Go, catalog in **Postgres** (`postgres:5432`, DBs `sysdb`+`log`, PVC 5 Gi) | global metadata, collection catalog, segment placement; hands the storage config (MinIO endpoint/keys) to every worker |
| Rust SysDB (`rust-sysdb-service`) | Rust rewrite of the catalog | multi-region catalog the Rust workers and frontend consult (`mcmr_sysdb`) |
| **Log Service** (`rust-log-service`, StatefulSet) | WAL over S3 | every write is recorded here first and acknowledged — index building never blocks writes; peer discovery via `MemberList` CustomResources (CRD shipped by the chart) |
| **Compactors** (`compaction-service` ×2, StatefulSet) | rendezvous-hash assigned | consume the log asynchronously, build HNSW/SPANN index segments, write them to object storage |
| **Query Nodes** (`query-service` ×2, StatefulSet) | stateless search replicas | load prebuilt indexes from MinIO through local SSD/memory caches (`hostPath` `/cache`); scale `replicaCount` with read traffic |
| Frontend (`rust-frontend-service`) | Rust gateway, REST v2 on :8000 | the only client entrypoint: auth/routing; serves `vigil` and the corpus loader |
| Work Queue + Fn Consumer + Garbage Collector | support services | distributed task queue; index/version garbage collection |
| **MinIO** (`minio:9000`, PVC 20 Gi) | S3 API, `chroma-storage` bucket | all WAL fragments and compacted index segments; the reason query nodes can stay stateless |
| OTel collector | OTLP sink | chroma components export traces/metrics there; failures are non-fatal |

Corpus: the Job `vigil-corpus-loader` (`images/vigil-corpus-loader/`, stdlib
Python) downloads the pre-embedded corpora from HuggingFace and loads them
into collections `vigil_instruction_bypass`
(`deadbits/vigil-instruction-bypass-all-MiniLM-L6-v2`, 8 800 vectors) and
`vigil_jailbreak` (`deadbits/vigil-jailbreak-all-MiniLM-L6-v2`, 104 vectors)
— 384-dim `all-MiniLM-L6-v2` embeddings, collections created with
**cosine** space (the loader tries spann- then hnsw-shaped configs). The Job
is idempotent (skips loaded collections; `FORCE_LOAD=1` re-adds). It is the
only pod in the namespace with internet egress (NetworkPolicy
`allow-corpus-loader-egress`).

Vigil sizing note: each replica peaks at **~2.5 GiB RSS** (two fp32
deberta-v3 sessions + MiniLM + runtime). `VIGIL_REPLICAS` / `VIGIL_HPA_MIN`
/ `VIGIL_MAX_UNAVAILABLE` (deploy.sh; defaults 2 / 2 / 0) exist because
laptop-class single-node clusters cannot hold a surge replica alongside the
first one — there, `VIGIL_REPLICAS=1 VIGIL_HPA_MIN=1 VIGIL_MAX_UNAVAILABLE=1`
keeps the six-engine scanner deployable; production nodes size for 2+.

Namespace `chroma` is default-deny in both directions: full intra-namespace
mesh, ingress to the frontend only from Vigil scanner pods (port 8000), DNS
egress, and the loader's HTTPS egress. The `security-gateways` egress policy
(`gateway-egress`) carries the mirror-image rule letting Vigil pods reach
the frontend. Image pin: `CHROMA_IMG_TAG` (short commit SHA from the
`chromadb` Docker Hub org — **verify CPU compatibility when bumping**: some
main-branch builds SIGILL on non-AVX-512 hosts; see the note in
`manifests/chroma/values-mcp-eval.yaml`).
stub keeps **no state at all** — no DB, no cache, nothing to persist.

### 5.3 NetBird — WireGuard transport mesh
**Kinds**: DaemonSet + per-pod sidecars; management server is **external**
(`NETBIRD_MANAGEMENT_URL`, e.g. `https://netbird.example.com:443`), setup
key from Secret `netbird-auth`.
- DaemonSet `netbird-node` (ns `security-gateways`): TUN mode,
  `CAP_NET_ADMIN` + `/dev/net/tun` hostPath CharDevice, state emptyDir,
  startupProbe (no livenessProbe — TUN mode exposes no health endpoint).
- Gateway sidecars (inside vigil/occludra pods): TUN `wt0`; give stable mesh
  identities `vigil.<NETBIRD_DNS_DOMAIN>` / `occludra.<…>` (default domain
  `netbird.selfhosted`).
- Run sidecar (eval Job, ns `mcp-evals`): **userspace** mode
  (`NETBIRD_USERSPACE_HOSTWIRESOCK=yes`) — zero capabilities,
  PodSecurity-restricted-safe; exposes SOCKS5 on `127.0.0.1:1080` only.

Data path (mesh mode): evaluator/bridge → SOCKS5 → userspace WireGuard →
gateway peer. Enforcement layers: per-run NetworkPolicy (blocks plain
ClusterIP path), WireGuard cryptokey routing (unauthenticated packets
dropped), NetBird ACLs (scope the evaluation setup-key group to
`vigil`+`occludra` peers only). `MESH_ENFORCE=false` (operator env) removes
the sidecar and falls back to in-cluster service DNS names.

### 5.4 NetworkPolicy rule sets (static, `manifests/occludra-deployment.yaml`)
| Policy | Effect |
|---|---|
| `default-deny-ingress` (gateways ns) | baseline deny, empty podSelector |
| `allow-wireguard-from-eval` | UDP/51820 from `mcp-evals` ns AND from 0.0.0.0/0 (cryptokey-authenticated anyway) |
| `allow-service-ports-in-namespace` | TCP 8080/5000 only from inside `security-gateways` |
| `gateway-egress` | DNS→kube-dns; private ranges for NetBird planes (TCP 443/33073/10000/33080, UDP 51820/3478/49152-65535); public TCP 443 **excluding** all private/link-local/metadata CIDRs |
| `allow-nodeport-from-docker-workstations` (`workstation-nodeport.yaml`) | TCP 8080/5000 from docker bridge `172.21.0.0/16` only — without this, kindnet's NFQUEUE enforcement silently blackholes external NodePort traffic (verified empirically) |
| `<run>-evaluate-egress` (generated) | per-run egress, contents per mode — see §3.2 |

---

## 6. Workstation plane — the programmer's computer

A plain Docker container (deliberately *outside* Kubernetes) that behaves
like a developer laptop whose only internet is the security perimeter.

- **Image** `opencode-workstation:latest` (`images/opencode-workstation/`):
  `node:22-bookworm-slim` + git/curl/jq + `npm i -g opencode-ai` (1.18.31);
  user `programmer` uid 1000 (base `node` user removed to free the uid).
- **Entrypoint** renders `~/.config/opencode/opencode.json` from
  `opencode.json.template`: provider `opencode` with
  `options.baseURL = $OCCLUDRA_BASE_URL` (default
  `http://mcp-test-control-plane:30080/v1`), local model declaration
  `muse-spark-1.3-contributor-free`, `autoupdate:false`,
  `share:"disabled"`, `snapshot:false`; then `exec sleep infinity`.
- **Credentials**: `OPENCODE_API_KEY=egress-via-occludra` is a **dummy** —
  the gateway strips client Authorization and injects the cluster's real
  upstream key. No real LLM credential exists on the workstation, ever.
- **Exposure** (`manifests/workstation-nodeport.yaml`): NodePort Services
  `occludra-np:30080` / `vigil-np:30500` + NetworkPolicy admitting only the
  docker `kind` bridge subnet (172.21.0.0/16) to 8080/5000. The evaluation
  path is untouched: eval pods stay blocked from the ClusterIPs and use the
  mesh.
- **Provable perimeter coverage**: even OpenCode's background
  title-generator call (model `gpt-5.4-nano`) traverses the gateway and
  shows up in redaction logs — there is no bypass path from the container.
- **Vigil access**: `/analyze` is directly reachable for interactive
  injection probing (`curl $VIGIL_URL/analyze`).

---

## 7. Evaluator results — exactly where they go

Four destinations, four lifetimes (this is the complete persistence story):

1. **`MCPEvaluationRun.status` subresource (etcd) — the durable system of
   record.** The evaluator merge-patches incrementally through
   `k8s.ts patchStatus()` (retry + backoff, never fatal; a failed patch
   retries, then logs and moves on — the Job exit code and termination log
   still carry the verdict). Patches: `phase: Running` →
   `phase: Evaluating` + `currentAgent` per agent → `agentResults[<agent>]`
   after **each** agent (partial results survive later failures — now by
   design, since failed agents degrade the run instead of aborting it) →
   `findings` → `finalScore` + `scoring` → `phase: Completed`. On error:
   `phase: Failed` + `message` (stage/agent + error class). Terminal-phase
   patches get extended backoff plus one final `flushTerminalPatch()` from
   the shutdown path; if even that fails, the verdict survives in
   `/dev/termination-log` and the run controller reads it back (its
   `EvaluatorResultsMissing` guard catches the truly-empty case). Survives
   pod deletion, TTL, cluster restarts; visible via `kubectl get mcprun -o
   yaml`.
2. **`/output/evaluation-report.json`** inside the evaluator container —
   the full report (all agent outputs, evidence, telemetry) written by
   `writeReport()`. Backing: emptyDir on the run Pod → **dies with the
   Pod**, which dies 10 min after terminal phase
   (`ttlSecondsAfterFinished: 600`). Retrieve with
   `kubectl cp` while the pod lives; after that only (1) and (3) remain.
3. **`/dev/termination-log`** — one-line summary of the final state;
   surface via `kubectl describe pod` / `kubectl get pod -o
   jsonpath={..status.containerStatuses[].lastState.terminated.message}`.
   Same lifetime as (2).
4. **Dry-run mode** (`DRY_RUN=1`): no API calls; status writer instead
   reads `${OUTPUT_DIR}/server.json` + `agents/<name>.json` fixture files
   and prints patches to stdout — offline development of the evaluator.

Mirror copy: `MCPServerReconciler.syncLatestRunResult()` copies the newest
run's score/risk into `MCPServer.status` — so the *server* object always
answers "how risky is this MCP server today" without a client-side join.

---

## 8. Data stores — complete inventory

| # | Store | Technology | Location / kind | Lifetime | Contents |
|---|---|---|---|---|---|
| 1 | **Cluster state (the only database)** | etcd, Raft-replicated | kind node `/var/lib/etcd` (via kube-apiserver) | cluster lifetime | every CR (MCPServer/MCPEvaluationRun/OpenCodeAgent incl. full `agentResults`), Jobs, Pods, ConfigMaps, Secrets, NetworkPolicies, Services |
| 2 | Run workspace | **emptyDir, disk-backed on purpose** (explicitly not `medium: Memory` — code comment: Memory-medium emptyDirs mount as tmpfs and would eat node RAM for large repos) | run Pod, mounted `/workspace` (target: read-only) | pod lifetime | cloned repo, `.mcp-launch.json` |
| 3 | IPC FIFOs | emptyDir + named pipes (FIFOs work on any medium; pipe buffers are kernel memory) | run Pod `/ipc` | pod lifetime | evaluator ⇄ target stdio stream |
| 4 | Evaluator temp | emptyDir 64Mi | run Pod `/tmp` | pod lifetime | supervisor/server logs, scratch |
| 5 | Evaluator report | emptyDir | run Pod `/output` | pod lifetime (TTL 600 s) | `evaluation-report.json` (§7.2) |
| 6 | SA token | projected volume, 1 h TTL | run Pod `/token` (evaluator only) | auto-rotated | k8s credentials for status patches |
| 7 | Occludra policy | **ConfigMap** `occludra-policy` → etcd, mounted `/conf` | gateway pods | permanent; hot-reloaded per request | 11 detectors, model allowlist, logging flags |
| 8 | Vigil config | **ConfigMap** `vigil-server-conf` → etcd, mounted `/conf` | vigil pods | permanent | scanner profile (ML scanners off by default) |
| 9a | **Distributed Chroma — object segments** | **MinIO** (`minio.chroma:9000`, PVC 20 Gi, bucket `chroma-storage` auto-created) | `chroma` ns, MinIO Deployment | permanent (PVC) | WAL fragments + compacted HNSW/SPANN index segments of the Vigil corpora |
| 9b | **Distributed Chroma — catalog** | **Postgres 15** (`postgres.chroma:5432`, PVC 5 Gi) | `chroma` ns | permanent (PVC) | tenants/databases/collections/segment placement (SysDB), migrated by the chart's `sysdb-migration` Job |
| 9c | **Vigil corpora** | collections `vigil_instruction_bypass` (8 800×384d) + `vigil_jailbreak` (104×384d), cosine space | inside Chroma (query nodes serve them; replicas stay stateless) | permanent via 9a | known injection/jailbreak prompts, HF `deadbits/*-all-MiniLM-L6-v2` |
| 10 | LLM upstream keys | **Secret** `llm-provider-credentials` (etcd) | `mcp-evals` + mirrored `security-gateways` | permanent | decoded **only** by occludra containers; evaluator's copy only ever configures the dummy-key path |
| 11 | NetBird identity | Secret `netbird-auth` + emptyDir `/var/lib/netbird` | sidecars/daemonset | emptyDir: pod lifetime (re-enroll on restart) | setup key, peer state, WireGuard keys |
| 12 | OpenCode session store | files under `$XDG_DATA_HOME` | evaluator container `/tmp` emptyDir; workstation container fs | ephemeral | session transcripts/messages — deliberately throwaway |
| 13 | Container images | `registry:2` on docker volume | host, `localhost:5001` (kind node has certs.d mirror config) | volume lifetime | occludra-gateway, vigil-stub, mcp-cloner, mcp-target-sandbox, mcp-evaluator (`:local`) |
| 14 | Host test evidence | git-tracked files | `dlp-test-results/` in this repo | permanent | round-1 baseline, forensics captures, round-2 verification |

Non-goals (explicit, evaluation plane): no SQL/NoSQL application database, no
message queue, no object storage. Anything that must survive a pod is a
Kubernetes object; everything else is engineered to be disposable. The one
deliberate exception is the security perimeter's **vector plane** (§5.2.1):
a distributed Chroma cluster with its own MinIO + Postgres, walled off in
namespace `chroma` and consumed only through the Vigil scanner.

---

## 9. Distribution & HA model — natively distributed vs not

| Capability | Mechanism | Natively distributed? |
|---|---|---|
| Cluster state | etcd Raft (kind = single node here; the repo history targets k0s multi-master too) | **yes** (replicated protocol; single instance in this dev cluster) |
| Operator | Deployment, 2 replicas, `--leader-elect` enabled, PDB minAvailable 1, topology spread, `PriorityClass mcp-eval-critical` | **yes** — one active + hot standby, survives node drain |
| Scheduling correctness | cron math vs etcd timestamps every reconcile | survives failover/restarts, no timers |
| Run creation | uncached (APIReader) active-run check at fire time closes the cache-lag dedup window | no double-create on reconcile races |
| Evaluation workloads | independent batch Jobs per run; transient infra failures recreate the Job (≤2, `status.retries`); stuck-Pending pods fast-retried at 5 min | **yes** — embarrassingly parallel across servers; infra flakes recover without waiting for the next cron |
| Occludra | HPA 2→8 (CPU 70 %), shared ConfigMap policy, PDB 50 %, rolling maxUnavailable 0, topology spread, HTTP probes + graceful shutdown + in-flight backpressure | **yes** |
| Vigil | HPA 2→8 (CPU 70 %), PDB 50 %, topology spread, `/health` HTTP probes + startupProbe + in-flight backpressure; scanner pods are stateless — the vector corpora live in the distributed Chroma (§5.2.1) | **yes** — a replacement replica re-reads corpora from the cluster, nothing to rebuild locally |
| Mesh data plane | NetBird WireGuard peer-to-peer | **yes** — no central data chokepoint (management plane is external/SPOF) |
| Policy distribution | kubelet ConfigMap sync (~1 min) + per-request re-read | eventually consistent, atomic per request |
| Node capacity | Cluster Autoscaler on OpenStack (ephemeral Nova VMs, scale-out on pending pods, scale-in after 5 min idle); static on kind | **yes** on OpenStack (gated by `DEPLOY_AUTOSCALER=openstack`) |
| Workstation | single Docker container | **no** — single-user dev tool by design |
| Accepted SPOFs | see §9.2 — each has an in-cluster or redundancy path | |

### 9.2 External SPOFs — elimination paths

The four dependencies outside the platform's own manifests, and how each
stops being a single point of failure:

| SPOF | Failure impact today | Elimination path (shipped) |
|---|---|---|
| Host registry (`kind-registry`) | new image pulls fail on host restart | **In-cluster registry** — `manifests/registry.yaml` (`IN_CLUSTER_REGISTRY=1`): registry:2 on a PVC inside the cluster, reschedules across nodes; on OpenStack, uncomment the Swift backend block for multi-replica HA + pull-through cache for third-party images. The registry is on the availability path only (a pull delay), never on the correctness path — Job retries absorb it |
| External NetBird management | no new enrollments / ACL changes while it's down | **Self-hosted control plane** — `manifests/netbird-controlplane.yaml` (`DEPLOY_NETBIRD_CP=1`): management (PVC-backed) + signal ×2 + relay ×2 in `security-gateways`. Requires an OIDC IdP (netbird prerequisite). Key nuance: even today a management outage does NOT break the WireGuard data plane — established peer sessions keep flowing; self-hosting removes the *operational* SPOF (enrollment/ACL) |
| OpenCode Zen upstream (only LLM provider) | all evaluations fail while the provider is down | **Gateway-level failover** — Occludra `OCCLUDRA_FALLBACK_UPSTREAM_BASE_URL` + `OCCLUDRA_FALLBACK_API_KEY`: on primary transport failure, 5xx or 429 the request is retried against the secondary provider before the first byte is streamed (no mid-stream duplication). Combined with the runner's per-agent degradation, a full provider outage now degrades instead of failing |
| kind node (single-node etcd/apiserver) | whole cluster gone with the node | Infra, not manifests: production path is **k0s multi-master on OpenStack** (3 control-plane VMs, etcd quorum) + the Cluster Autoscaler for workers. Documented; out of repo scope by design |

Consistency notes: per-run NetworkPolicy exists **before** the Job (no
uncovered label-flip window) and is **deleted when the run turns terminal**
(owner-ref GC backstop on run deletion); net-phase flips exactly once;
evaluator status patches are optimistic merge-patches (conflicts →
retry/backoff, controller re-reconcile confirms); run-level `status.retries`
bounds Job recreation so recovery cannot loop.

Vector-plane availability (§5.2.1): query nodes (×2), compactors (×2), the
log service and both SysDBs tolerate pod loss; the plane's remaining SPOFs
are MinIO and Postgres — single-replica but PVC-backed and
`PriorityClass mcp-eval-critical`. Their failure mode is graceful by
construction: the Vigil vector scanner degrades to the heuristics layer
(`runs.vector.available: false`, 60 s init-retry cooldown) and evaluations
continue; the corpora are re-loaded idempotently by the corpus-loader Job
once the plane recovers. Scaling paths follow chroma's own model: query
nodes scale horizontally with read traffic (stateless), MinIO/Postgres
scale by moving to external S3/RDS equivalents via the worker configs.

---

## 9.1 Load profile — what happens at each point under heavy traffic

| Point | Load source | Behaviour as traffic rises | Scaling mechanism |
|---|---|---|---|
| Operator (manager) | reconcile of N servers × M runs; every run's Job/NP/pod transitions | The default single reconcile worker would serialize everything; workers are now 8 (run ctrl) / 4 (server ctrl), each reconcile is stateless. List/watch goes through the informer cache; the uncached fire-time list is one extra read per actual fire | Vertical: CPU/mem 500m/512Mi. Horizontal replicas add standby only (leader election) — throughput comes from workers. Retry storms bounded by the default exponential rate limiter |
| MCPEvaluationRun Jobs | one pod per run; each ~1.1 vCPU / 1 GiB requests | Pods go Pending when nodes fill — this is the signal the Cluster Autoscaler consumes | Embarrassingly parallel; bounded per-server by the single-active-run rule, cluster-wide by node capacity / autoscaler MAX |
| Occludra | every LLM completion of every agent of every run (regex scrub CPU + long-lived SSE streams) | Up to HPA max 8 replicas; beyond per-replica `OCCLUDRA_MAX_INFLIGHT=64` in-flight it answers 503 + Retry-After (clients back off) instead of exhausting memory | HPA CPU 70 %, 2→8, PDB 50 %; backpressure as the last resort |
| Vigil | every untrusted payload scan (surface, fuzz, probes) of every run | Same envelope: HPA to 8 replicas; stub saturates at `VIGIL_STUB_MAX_INFLIGHT=64` with 503 + Retry-After (the evaluator's Vigil client retries ≥5xx) | HPA CPU 70 %, 2→8, PDB 50 %; backpressure as the last resort |
| NetBird | userspace WireGuard inside each eval pod (sidecar) and per gateway pod | Per-pod resource, scales 1:1 with pods; TUN sidecars liveness-probed | No central data plane to scale (management plane is the documented external SPOF) |
| API server / etcd | CR patches (status per agent), Jobs, per-run NPs, events | controller-runtime informer caches absorb reads; writes are merge-patches, retries with backoff. Metrics-server adds kubelet scrape load | Cluster-infra concern (multi-master on production OpenStack; single-node kind accepted locally) |
| Upstream LLM (Zen) | N runs × 4 agents streaming completions | 429s from the provider surface as agent errors → per-agent degradation, never a lost run | External quota; degradation semantics absorb it safely |

**Node autoscaling (OpenStack, ephemeral VMs):** pending eval pods / HPA
replicas that don't fit trigger Cluster Autoscaler (`--cloud-provider=openstack`)
→ a fresh Nova VM joins the worker group (autoscale `AUTOSCALER_MIN`..`MAX`),
runs its wave, and is deleted once unneeded for 5 min
(`--scale-down-unneeded-time`). Eval Jobs are never preempted for scale-in
(above the expendable cutoff) — a node with a running evaluation is not
reaped. On the local kind cluster nothing is deployed (`deploy.sh` gates both
`AUTOSCALE_METRICS` and `DEPLOY_AUTOSCALER`).

---

## 10. End-to-end request lifecycles

**Scheduled evaluation**: cron due (or `trigger-now` annotation) →
`createRun` → run controller creates `<run>-evaluate-egress` NetworkPolicy
then Job (net-phase `clone`) → cloner clones+installs → net-phase flips to
`evaluate` → evaluator boots mesh, connects MCP over FIFOs, collects +
Vigil-scans the advertised surface → four persona prompts via OpenCode→
Occludra→Zen (tools advertised, execution denied; `tool_choice` normalized)
→ incremental status patches → synthesis scores 0–100 → `Completed` →
score mirrored to MCPServer → TTL cleanup at 600 s.

**Workstation LLM call**: `opencode run "…"` → local config baseURL
`http://mcp-test-control-plane:30080/v1` → kube-proxy DNAT → gateway pod
→ allowlist → recursive redaction (`[REDACTED]`, count logged) →
tool_choice normalization → Authorization swapped to gateway key →
`https://opencode.ai/zen/v1/responses` (SSE) → streamed back → CLI renders.
The upstream sees: gateway IP, gateway key, scrubbed text, `tool_choice:"auto"`.

**Workstation injection probe**: `curl $VIGIL/analyze` → NodePort 30500 →
heuristic scan → verdict JSON.

---

## 11. Deployment & operations

`deploy.sh` knobs: `IMG_REGISTRY` (required), `IMG_TAG=latest`,
`OPENCODE_API_KEY` (required unless `SKIP_SECRET=1`), `SKIP_BUILD=1`,
`OCCLUDRA_IMG`, `VIGIL_IMG` (default `deadbits/vigil-llm:latest`; if pointed
at the stub path it builds/pushes `images/vigil-stub`). Builds 5 images,
pushes, applies CRDs+manager (`make deploy`), security layers (including the
shared `PriorityClass mcp-eval-critical`), samples, secret, triggers first
run. With `MESH_ENFORCE=true` (default) `NETBIRD_SETUP_KEY` is **required** —
the script exits early rather than deploying a mesh whose runs cannot enroll.

Local dev loop: images `:local` in `kind-registry` → rebuild via
`docker build -t localhost:5001/<img>:local <dir> && docker push` →
`kubectl -n <ns> rollout restart deploy/<dep>` (gateways) or
`kubectl -n mcp-evals annotate mcpserver filesystem-mcp
security.eval.io/trigger-now=true` (new run) → `kubectl -n mcp-evals get
mcprun -w`. Workstation rebuild:
`docker build -t opencode-workstation:latest images/opencode-workstation &&
docker rm -f opencode-programmer && docker run -d --name opencode-programmer
--network kind --hostname programmers-laptop opencode-workstation:latest`.

Reference evidence: run `filesystem-mcp-run-vnrsr` Completed (4 agents,
score 47, Caution); DLP round-2 all-green (`dlp-test-results/run2/`): api-key,
password, customer+amount all `[REDACTED]` before the LLM; both
"Forget…"/"Ignore…" phrasings blocked by Vigil at confidence 1.0.

## 12. References

- Vigil-LLM (upstream project & scanner/vector-DB architecture):
  https://github.com/deadbits/vigil-llm · https://vigil.deadbits.ai/overview/release-blog
  (upstream uses an embedded on-disk ChromaDB; this platform serves the same
  detection class from the distributed cluster of §5.2.1)
- Distributed Chroma (chart + component images + architecture):
  chart vendored from https://github.com/chroma-core/chroma (`k8s/distributed-chroma`,
  commit 30d701a4) · component images https://hub.docker.com/u/chromadb
  (per-commit SHA tags) · architecture doc
  https://github.com/chroma-core/chroma/blob/main/docs/mintlify/reference/architecture/distributed.mdx
- Vigil embedding corpora (all-MiniLM-L6-v2, 384-dim, pre-embedded):
  https://huggingface.co/datasets/deadbits/vigil-instruction-bypass-all-MiniLM-L6-v2 ·
  https://huggingface.co/datasets/deadbits/vigil-jailbreak-all-MiniLM-L6-v2
- MinIO: https://min.io (S3-compatible object storage; chroma pins the release
  by digest in `manifests/chroma/minio.yaml`)
- OpenCode Zen: https://opencode.ai/zen/v1/models
- NetBird: https://docs.netbird.io/
- MCP: https://modelcontextprotocol.io/
