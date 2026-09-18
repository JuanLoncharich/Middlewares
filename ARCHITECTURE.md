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
| controller-manager | **Deployment** `mcp-eval-controller-manager` (1 replica, `--leader-elect`) | `mcp-eval-system` | repo root `Dockerfile`, `cmd/main.go` | none (etcd is the state) |
| cloner | **init container** of the run Pod | `mcp-evals` | `images/cloner/` (bash) | writes `/workspace`, exits |
| target sandbox | **container** (`target`) of the run Pod, UID 10002 | `mcp-evals` | `images/target/` (bash supervisor) | ephemeral, jailed |
| evaluator | **container** (`evaluator`) of the run Pod, UID 10001 | `mcp-evals` | `runner/` (TypeScript → `dist/evaluator.js`) | ephemeral; writes results to 4 places (§8.1) |
| OpenCode child server | **in-process subprocess** spawned by the SDK inside the evaluator container (`opencode serve`, loopback 4096+) | evaluator container | npm `opencode-ai` | session files in container `/tmp` |
| netbird run sidecar | **sidecar container** (userspace WireGuard) | run Pod | `netbirdio/netbird:latest` | emptyDir `/var/lib/netbird` |
| netbird node client | **DaemonSet** `netbird-node` (TUN mode, CAP_NET_ADMIN) | `security-gateways`, 1/node | `manifests/netbird-daemonset.yaml` | emptyDir state |
| Occludra gateway | **Deployment** `occludra` (2 replicas, PDB min 1, rolling maxUnavailable 0) + **Service** `occludra-service` (ClusterIP 8080) + **Service** `occludra-np` (NodePort 30080) | `security-gateways` | `images/occludra-gateway/` (Go, single file `main.go`) | **stateless**; policy read per-request |
| `occludra-policy` | **ConfigMap** (mounted at `/conf`, watched per-request) | `security-gateways` | `manifests/occludra-deployment.yaml` | policy source of truth (etcd) |
| Vigil scanner | **Deployment** `vigil` (2 replicas, PDB) + **Service** `vigil-service` (ClusterIP 5000) + **Service** `vigil-np` (NodePort 30500) | `security-gateways` | dev: `images/vigil-stub/server.py` (Python); prod pin `deadbits/vigil-llm:latest` | **stub: zero state**; real: ChromaDB vector DB (§5.2) |
| `vigil-server-conf` | **ConfigMap** (`server.conf`, scanner enable/disable) | `security-gateways` | `manifests/vigil-deployment.yaml` | scanner profile (etcd) |
| NetworkPolicies | **NetworkPolicy** ×5 static + **1 generated per run** (`<run>-evaluate-egress`) | `security-gateways` / `mcp-evals` | `manifests/occludra-deployment.yaml`, `workstation-nodeport.yaml`, controller §4 | — |
| LLM credentials | **Secret** `llm-provider-credentials` (key `OPENCODE_API_KEY`) — exists in **both** `mcp-evals` (evaluator passes it to its own gateway calls' config; real key upstream lives in the gateway) and `security-gateways` (decoded only by occludra) | both ns | created by `deploy.sh` | etcd |
| netbird auth | **Secret** `netbird-auth` (setup key) | `security-gateways` | `deploy.sh` | etcd |
| workstation | **Docker container** `opencode-programmer` (NOT a Kubernetes resource) on docker network `kind` | host Docker | `images/opencode-workstation/` | config in `$HOME/.config/opencode` |
| local registry | **Docker container** `kind-registry` (`registry:2`, `localhost:5001`) | host Docker | kind setup | image layers on volume |
| kind cluster | **kind** `mcp-test` (node `mcp-test-control-plane`, k8s v1.33.1, CNI kindnet — **does enforce** NetworkPolicy via nftables NFQUEUE) | host Docker | — | etcd on node disk |

There is **no application database, no SQL, no object store** in this platform
by design; §8 is the complete data-store inventory.

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
  - `backoffLimit: 0` (one attempt — runs fail loudly, cron retries),
    `ttlSecondsAfterFinished: 600` (Job + Pod garbage-collected 10 min after
    terminal), `activeDeadlineSeconds: spec.timeoutSeconds`;
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
  manager.yaml args; Deployment replicas: 1, HA-ready to scale N with 1 active).

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
| `evaluator.ts` | main() flow, agent orchestration, OpenCode boot (`bootOpencode`: `createOpencode` spawns `opencode serve` on 127.0.0.1:4096+ with config `{model, permission:"deny", autoupdate:false, share:"disabled", snapshot:false, provider.opencode.options.baseURL = OCCLUDRA_BASE_URL}`), structured-output recovery from plain text, report writing |
| `k8s.ts` | status writer: **merge-patch on the status subresource** (`patchNamespacedCustomObjectStatus`), retry w/ backoff, never throws; dry-run mode reads `${OUTPUT_DIR}/server.json` + `agents/<name>.json` instead of the API |
| `vigil.ts` | VigilClient: POST `/analyze {prompt}` with timeout + retry/backoff; verdict parsing across all response shapes; `VigilUnavailableError` classification (caller decides strict fail-closed vs monitor); `excerptOf` for logs |
| `meshhttp.ts` | NetBird transport: SOCKS5 (RFC 1928) client with user/pass auth staging; `fetch-over-SOCKS5` for the evaluator's own Vigil/Occludra calls; local **HTTP↔SOCKS5 bridge** listener on `127.0.0.1:18080` exported as `HTTP_PROXY`/`HTTPS_PROXY` so the OpenCode child process (cannot be taught SOCKS5) rides the mesh too |
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
**Kind**: Deployment ×2 (PDB minAvailable 1, rolling maxUnavailable 0) +
ClusterIP `occludra-service:8080` + NodePort `occludra-np:30080`. Stateless
Go service (`images/occludra-gateway/main.go`); the only LLM egress point of
the platform.

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
`GET /health`. Content is never logged (`log_payloads: false`).

**Deployed implementation today is the test double** (`images/vigil-stub/server.py`,
Alpine Python, UID 10004, read-only rootfs): deterministic regex heuristics,
score = 0.6 per hit (cap 1.0), detection at `VIGIL_STUB_THRESHOLD` ≥ 0.5,
`VIGIL_STUB_ALWAYS_BLOCK=1` forces detection for abort-path drills.

| Scanner (stub) | Pattern (abridged) |
|---|---|
| `ignore-instructions` | `(ignore\|forget\|disregard\|drop\|override\|bypass)` … ≤40 chars … `(instructions\|prompts\|rules\|directives)` |
| `reveal-system-prompt` | `(reveal\|print\|output\|repeat\|show\|display\|expose\|disclose\|leak\|dump)` … `(system prompt\|your prompt\|initial/hidden/operating instructions)` |
| `role-hijack` | `you are now a/an …` |
| `disregard-safety` | `disregard (all\|any) (safety\|content) …` |
| `exfiltration` | `curl/wget/fetch/POST http…` + env/HOME/PATH/TOKEN/KEY |
| `exfil-marker` | `send (all\|the) (data\|content\|files) to http…` |
| `hidden-instruction` | `[system]`, `(system note)`, `<\|im_start\|>` |
| `credential-harvest` | `api key\|password\|secret\|token [:=] ≥8 chars` (requires the separator — "password is X" passes here; that path is Occludra's job on egress) |

**The production image (`deadbits/vigil-llm`) is a scanner *library* over
several detection engines** — what the stub replaces:
- heuristic regex + **YARA** rule scanning (offline, fast);
- a **canonical prompt-injection classifier** (BERT-family, model download);
- **embedding-similarity scanning backed by a real vector database**:
  inputs are embedded with sentence-transformers (or OpenAI ada-002-style
  embeddings) and queried against a persistent on-disk **ChromaDB**
  collection pre-loaded with corpora of known jailbreak /
  instruction-bypass prompts (e.g. HF dataset
  `deadbits/vigil-instruction-bypass-ada-002`); a similarity/distance
  below threshold flags the input as injection;
- optional response-side scanners (sentiment, canary/leaked-secret detection).

In the shipped ConfigMap (`vigil-server-conf`) the ML scanners
(`canonical`, `transformer`, `vector`) are **commented out** so the container
boots offline and stays fast — enabling them requires model/corpus download
and, for ChromaDB persistence, a **PersistentVolume** (the current Pod only
mounts a 256Mi `emptyDir` at `/tmp`; the vector DB is on-disk inside the
container and would be lost on pod reschedule unless a PV is mounted). The
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
   after **each** agent (partial results survive later failures) →
   `findings` → `finalScore` + `scoring` → `phase: Completed`. On error:
   `phase: Failed` + `message` (stage/agent + error class). Survives pod
   deletion, TTL, cluster restarts; visible via `kubectl get mcprun -o yaml`.
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
| 9 | **Vigil vector DB** | **ChromaDB, on-disk, persistent** — real `deadbits/vigil-llm` only (sentence-transformers/ada-002 embeddings vs known-jailbreak corpora, e.g. HF `deadbits/vigil-instruction-bypass-ada-002`) | inside vigil container (needs a **PV** if ML scanners are enabled; **absent today**: stub has no DB, ML scanners disabled) | pod lifetime today | embedded corpus of known-bad prompts |
| 10 | LLM upstream keys | **Secret** `llm-provider-credentials` (etcd) | `mcp-evals` + mirrored `security-gateways` | permanent | decoded **only** by occludra containers; evaluator's copy only ever configures the dummy-key path |
| 11 | NetBird identity | Secret `netbird-auth` + emptyDir `/var/lib/netbird` | sidecars/daemonset | emptyDir: pod lifetime (re-enroll on restart) | setup key, peer state, WireGuard keys |
| 12 | OpenCode session store | files under `$XDG_DATA_HOME` | evaluator container `/tmp` emptyDir; workstation container fs | ephemeral | session transcripts/messages — deliberately throwaway |
| 13 | Container images | `registry:2` on docker volume | host, `localhost:5001` (kind node has certs.d mirror config) | volume lifetime | occludra-gateway, vigil-stub, mcp-cloner, mcp-target-sandbox, mcp-evaluator (`:local`) |
| 14 | Host test evidence | git-tracked files | `dlp-test-results/` in this repo | permanent | round-1 baseline, forensics captures, round-2 verification |

Non-goals (explicit): no SQL/NoSQL database, no message queue, no object
storage. Anything that must survive a pod is a Kubernetes object; everything
else is engineered to be disposable.

---

## 9. Distribution & HA model — natively distributed vs not

| Capability | Mechanism | Natively distributed? |
|---|---|---|
| Cluster state | etcd Raft (kind = single node here; the repo history targets k0s multi-master too) | **yes** (replicated protocol; single instance in this dev cluster) |
| Operator | Deployment, `--leader-elect` enabled, replicas 1 (scale-out safe: N replicas, 1 active) | HA-ready |
| Scheduling correctness | cron math vs etcd timestamps every reconcile | survives failover/restarts, no timers |
| Evaluation workloads | independent batch Jobs per run | **yes** — embarrassingly parallel across servers |
| Occludra | 2 stateless replicas, shared ConfigMap policy, PDB, rolling maxUnavailable 0, ClusterIP random spread | **yes** |
| Vigil | 2 stateless (stub) replicas, PDB | **yes** (real image: ChromaDB makes a replica *eventually* self-contained after corpus load; PV needed for durability) |
| Mesh data plane | NetBird WireGuard peer-to-peer | **yes** — no central data chokepoint (management plane is external/SPOF) |
| Policy distribution | kubelet ConfigMap sync (~1 min) + per-request re-read | eventually consistent, atomic per request |
| Workstation | single Docker container | **no** — single-user dev tool by design |
| Accepted SPOFs | kind node, local registry, external NetBird management, OpenCode Zen | documented residuals |

Consistency notes: per-run NetworkPolicy exists **before** the Job (no
uncovered label-flip window); net-phase flips exactly once; evaluator status
patches are optimistic merge-patches (conflicts → retry/backoff, controller
re-reconcile confirms).

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
pushes, applies CRDs+manager (`make deploy`), security layers, samples,
secret, triggers first run.

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
  (ChromaDB persistent vector store; sentence-transformers embeddings;
  corpora e.g. https://huggingface.co/datasets/deadbits/vigil-instruction-bypass-ada-002)
- OpenCode Zen: https://opencode.ai/zen/v1/models
- NetBird: https://docs.netbird.io/
- MCP: https://modelcontextprotocol.io/
