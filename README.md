# mcp-eval-operator

Distributed tracing, metrics, centralized logs, dashboards, and access
instructions are covered in [Observability](#observability).

Automated static + dynamic security evaluation of Model Context Protocol (MCP)
servers on Kubernetes. Point an `MCPServer` resource at a GitHub repository and
the operator periodically clones it, runs it inside a locked-down sandbox, and
drives an ensemble of OpenCode agents (SAST, protocol fuzzing, rogue-behaviour
probing, synthesis) against it, writing a structured verdict back into the CR.

```
MCPServer ──schedule──▶ MCPEvaluationRun ──▶ batch/v1 Job (one Pod)
                                               ├─ init  cloner     shallow clone + toolchain detect → /workspace
                                               ├─ side  netbird    userspace WireGuard + local SOCKS5 (127.0.0.1:1080)
                                               ├─ ctr   target     untrusted MCP server, jailed, stdio ⇄ /ipc FIFOs
                                               └─ ctr   evaluator  @opencode-ai/sdk runner, patches status
OpenCodeAgent ×4 ─── referenced by agentSuite ──▶ fetched by the evaluator at run time

evaluator ──Vigil /analyze/prompt──▶ vigil   (security-gateways, WireGuard mesh)
evaluator ──LLM calls──────▶ occludra┐ (security-gateways, WireGuard mesh)
                            └─PII scrub──▶ upstream LLM
```

## Layout

| Path | Contents |
|---|---|
| `api/v1alpha1/` | CRD Go types (`OpenCodeAgent`, `MCPServer`, `MCPEvaluationRun`) + deepcopy |
| `internal/controller/` | `MCPServer` (cron scheduler) and `MCPEvaluationRun` (Job builder / status) reconcilers |
| `cmd/main.go` | controller-manager entrypoint |
| `internal/observability/` | OpenTelemetry setup and persisted trace-context propagation |
| `config/crd/bases/` | generated-equivalent CRD manifests |
| `config/rbac/` | manager ClusterRole, leader-election Role, runner ServiceAccount/Role |
| `config/manager/` | operator Deployment (namespace `mcp-eval-system`) |
| `config/samples/` | namespace, NetworkPolicies, reference sandbox Pod, four agent personas, `MCPServer` sample |
| `manifests/` | Vigil-LLM, Occludra and NetBird deployments (namespace `security-gateways`) — the three security layers |
| `manifests/chroma/` | Distributed Chroma vector database over MinIO (namespace `chroma`): vendored official chart, values, worker configs, MinIO/Postgres/OTel substrate, NetworkPolicies and the Vigil corpus-loader Job |
| `manifests/observability/` | Grafana, Alloy, Prometheus, Loki, Tempo, dashboards, alert rules, RBAC and NetworkPolicies |
| `runner/` | TypeScript evaluator (`@opencode-ai/sdk` + `@kubernetes/client-node`) |
| `images/cloner/` | init-container image: git + npm/uv/go toolchain detection |
| `images/target/` | sandbox image: supervisor that binds the server's stdio to the IPC FIFOs |

## Install

> **Local end-to-end test** (kind cluster, benign + malicious MCP fixtures,
> SSH workstation, `(proxy)` response marker): see [TESTING.md](TESTING.md)
> and `test/run-local-e2e.sh`.

Prerequisites on the deploying machine: `kubectl` (configured for the target
cluster), `docker` with push access to a registry the cluster can pull from.

## What you must provide (not in this repo)

The platform ships **no credentials** — these are yours to supply:

| Value | What | When required |
|---|---|---|
| `OPENCODE_API_KEY` | OpenCode Zen API key (free tier works with `*-free` models) | **required for any run to produce results.** `deploy.sh` writes it into `mcp-evals/llm-provider-credentials` unless `SKIP_SECRET=1`. Missing key or no credits → evaluations fail at the LLM stage (auth/CreditsError); cloning, sandboxing and the Vigil scan still run, so the plumbing is testable, but `finalScore` stays 0/Failed. A key set by a previous deploy survives in the secret; **fresh clusters must set it**. |
| `IMG_REGISTRY` | a registry the cluster can pull from: `ghcr.io/<you>` (after `docker login`) or ephemeral `ttl.sh/<name>` for local tests — ttl.sh images expire after 24 h | always |
| `NETBIRD_SETUP_KEY` (+ `NETBIRD_MANAGEMENT_URL`) | NetBird enrollment key for the WireGuard mesh | mesh mode only — `deploy.sh` hard-fails without it; not needed with `MESH_ENFORCE=false` |
| `NETBIRD_OIDC_CONFIG_ENDPOINT` | IdP well-known URL | only for `DEPLOY_NETBIRD_CP=1` |
| `OS_*` variables | OpenStack credentials | only for `DEPLOY_AUTOSCALER=openstack` |

Local bring-up without mesh or a Zen key (existing secret reused if present):

```bash
IMG_REGISTRY=ttl.sh/midd-$(date +%s) MESH_ENFORCE=false SKIP_SECRET=1 ./deploy.sh
```


## What you must provide (not in this repo)

The platform ships **no credentials**. Before (or at) deploy time you supply:

| Value | What | When required |
|---|---|---|
| `OPENCODE_API_KEY` | OpenCode Zen API key (free tier works with `*-free` models) | **required for any run to produce results.** `deploy.sh` writes it into `mcp-evals/llm-provider-credentials` unless `SKIP_SECRET=1`. Without it (or without credits) evaluations fail at the LLM stage with an auth/CreditsError — cloning, sandboxing and the Vigil scan still work, so you can validate the plumbing, but `finalScore` stays `0`/`Failed`. A key from a previous deploy survives in the secret; fresh clusters must set it. |
| `IMG_REGISTRY` | a registry the cluster can pull from (`ghcr.io/<you>` after `docker login`, or an ephemeral `ttl.sh/<name>` for local testing — images expire after 24 h) | always |
| `NETBIRD_SETUP_KEY` (+ `NETBIRD_MANAGEMENT_URL`) | NetBird enrollment key for the WireGuard mesh | mesh mode only (`deploy.sh` hard-fails without it); not needed with `MESH_ENFORCE=false` |
| `NETBIRD_OIDC_CONFIG_ENDPOINT` | IdP well-known URL | only for `DEPLOY_NETBIRD_CP=1` |
| `OS_*` variables | OpenStack credentials | only for `DEPLOY_AUTOSCALER=openstack` |

For a quick local bring-up without mesh or a Zen key:

```bash
IMG_REGISTRY=ttl.sh/midd-$(date +%s) MESH_ENFORCE=false SKIP_SECRET=1 ./deploy.sh
```


### Fast path

```bash
git clone <this repo> && cd Middlewares
IMG_REGISTRY=ghcr.io/<you> OPENCODE_API_KEY=<zen-key> ./deploy.sh
kubectl -n mcp-evals get mcprun -w
```

`deploy.sh` builds and pushes the four images, installs CRDs + operator into
`mcp-eval-system`, applies the `mcp-evals` namespace / NetworkPolicies / agent
personas / sample `MCPServer`, creates the LLM secret, and triggers the first
run. `SKIP_BUILD=1` reuses already-pushed images; `SKIP_SECRET=1` leaves an
existing secret untouched.

### Manual path

```bash
# 1. Images
export IMG_REGISTRY=ghcr.io/<you>
make docker-build-all docker-push \
  IMG=$IMG_REGISTRY/mcp-eval-operator:20260930 \
  CLONER_IMG=$IMG_REGISTRY/mcp-cloner:20260930 \
  TARGET_IMG=$IMG_REGISTRY/mcp-target-sandbox:20260930 \
  EVALUATOR_IMG=$IMG_REGISTRY/mcp-evaluator:20260930
docker push $IMG_REGISTRY/mcp-cloner:20260930 \
  && docker push $IMG_REGISTRY/mcp-target-sandbox:20260930 \
  && docker push $IMG_REGISTRY/mcp-evaluator:20260930
# point the operator at your images
sed -i "s|ghcr.io/security-eval|$IMG_REGISTRY|g" config/manager/manager.yaml

# 2. CRDs + operator (namespace mcp-eval-system) + runner RBAC (namespace mcp-evals)
make deploy            # = kubectl kustomize config/default | kubectl apply -f - ; kubectl apply -f config/rbac/runner_role.yaml

# 3. Evaluation namespace, NetworkPolicies, agent personas, sample server
#    (no CIDR editing needed — the operator resolves the API-server endpoint IPs per-run)
make samples           # = kubectl apply -k config/samples
kubectl -n mcp-evals create secret generic llm-provider-credentials --from-literal=OPENCODE_API_KEY=<zen-key>

# 4. Trigger a run immediately instead of waiting for the cron schedule
kubectl -n mcp-evals annotate mcpserver filesystem-mcp security.eval.io/trigger-now=true
kubectl -n mcp-evals get mcprun -w
```

The operator's Deployment reads the image names from `CLONER_IMAGE`,
`TARGET_IMAGE`, `EVALUATOR_IMAGE`, the runner ServiceAccount from
`RUNNER_SERVICE_ACCOUNT` (`mcp-eval-runner`), and the LLM credential secret
from `LLM_SECRET_NAME` / `LLM_SECRET_KEY` (`llm-provider-credentials` /
`ANTHROPIC_API_KEY`), plus the `OPENCODE_API_KEY` key of the same secret for
OpenCode Zen (`opencode/*` models).

**Models / billing:** any model id from `https://opencode.ai/zen/v1/models` can be
used. Paid models (e.g. `claude-sonnet-4-6`) require Zen credits; `*-free` models
work without billing. All personas run tool-free (their providers reject the
`tool_choice` OpenCode's structured-output mechanism emits once other tools are
advertised), and the evaluator restates the JSON schema in the message and
recovers JSON from plain-text replies when a model does not honour the
structured-output tool call — so both paid and free tiers produce results.
Switch models by editing the four
`config/samples/security.eval.io_v1alpha1_opencodeagent_*.yaml` files.

## Security layers (Vigil / Occludra / NetBird)

Three centralized services (namespace `security-gateways`) wrap the
evaluation data path. Deployed by `deploy.sh`, or individually with
`kubectl apply -f manifests/…`.

* **Vigil-LLM** (inbound) — before any untrusted MCP payload (initialize
  instructions, tool descriptions, fuzz/probe responses) enters a prompt, the
  evaluator POSTs it to `vigil-service:5000/analyze/prompt`. A verdict of
  *injection detected* aborts the run, scores it `0` with
  `riskCategory=Malicious`, records a `Critical` finding and surfaces through
  the CRD status/termination message. `VIGIL_ENFORCE=monitor` downgrades
  detections to log+finding; in the default `strict` mode an *unreachable*
  scanner also fails the run (fail-closed). Set `VIGIL_ENABLED=0` to disable.
  The deployment runs the real **vigil-llm** image — `VIGIL_IMG`, built by
  `deploy.sh` from the pinned upstream source (`VIGIL_SRC_REPO`@
  `VIGIL_SRC_REF`, commit `f2b4c134d0…`) into
  `$IMG_REGISTRY/vigil-llm:$IMG_TAG`; upstream publishes no image of its
  own, only a Dockerfile. Override `VIGIL_IMG` to run a prebuilt/mirrored
  image your cluster can pull (`SKIP_BUILD=1` + `VIGIL_IMG` is the air-gap
  path); models download from HuggingFace at boot. The `vigil-server-conf`
  ConfigMap follows the pinned commit's INI config schema (mounted at
  `/app/conf/server.conf`) with the **transformer** prompt-injection
  classifier (`laiyer/deberta-v3-base-prompt-injection`), **YARA** rules
  (bundled with the image) and the **vectordb** similarity scanner enabled;
  response-side scanners stay off the evaluation path — the runner feeds raw
  untrusted payloads, not model responses. The vector plane is the **distributed Chroma cluster**
  (`manifests/chroma/`, namespace `chroma`: SysDB coordinator + log-service
  WAL + 2 query nodes + 2 compactors over **MinIO**, with the Vigil corpora
  `deadbits/*-all-MiniLM-L6-v2`, 8 900+ vectors, loaded by the
  `vigil-corpus-loader` Job), queried through `chroma-gateway` with a
  read-only token (`manifests/chroma/README.md`). Pods scale via HPA (CPU 70 %,
  `VIGIL_HPA_MIN`→8) with a PDB at 50 %; classifier replicas are
  memory-hungry, so laptop-class nodes should deploy with
  `VIGIL_REPLICAS=1 VIGIL_HPA_MIN=1 VIGIL_MAX_UNAVAILABLE=1`.
* **Occludra** (outbound) — every OpenCode provider is pinned to
  `occludra-service:8080/v1` (`OCCLUDRA_BASE_URL`): the gateway regex-scrubs
  PII (emails, SSNs, phone numbers, IBANs) and credential-looking strings from
  every completion request before forwarding upstream. Upstream provider keys
  live in `security-gateways/llm-provider-credentials`; the policy ships as
  ConfigMap `occludra-policy`. `OCCLUDRA_ENABLED=0` restores direct provider
  calls (dev only).
* **NetBird** (transport) — evaluation pods enroll in a WireGuard mesh via a
  **userspace** sidecar (`NETBIRD_USERSPACE_HOSTWIRESOCK=yes`: no capabilities,
  PodSecurity-restricted-safe) that exposes a local SOCKS5 proxy on
  `127.0.0.1:1080`. The evaluator routes Vigil/Occludra calls through it and
  exports a local HTTP-proxy bridge as `HTTP_PROXY`/`HTTPS_PROXY` so the
  OpenCode child process rides the mesh too. Vigil and Occludra run TUN-mode
  netbird sidecars (hence the `privileged`-PSA `security-gateways` namespace —
  trusted first-party images only). `MESH_ENFORCE=false` on the operator
  disables the sidecar, the mesh env vars and the per-run policy.

Runner knobs (all injected by the operator, all overridable per Deployment):
`MESH_PROXY` (default `socks5://127.0.0.1:1080`, empty = direct),
`MESH_BRIDGE_PORT` (18080), `MESH_READY_TIMEOUT_MS` (60000),
`VIGIL_URL` (derived, ends in `/analyze/prompt`), `OCCLUDRA_BASE_URL`, plus
optional pass-throughs read from the operator Deployment's env and forwarded
verbatim only when set (the runner applies its own defaults otherwise):
`VIGIL_ENABLED`, `VIGIL_ENFORCE` (`monitor` downgrades detections to
log+finding), `VIGIL_TIMEOUT_MS`, `VIGIL_MAX_PAYLOAD_BYTES`,
`OCCLUDRA_ENABLED`, and `RUNTIME_CLASS_NAME` — pin the evaluation pods to a
sandbox runtime such as gVisor (the RuntimeClass object must exist in the
cluster; see *Security model*). The operator derives `VIGIL_URL` /
`OCCLUDRA_BASE_URL` from the mode: in mesh mode they become the NetBird peer
names under `NETBIRD_DNS_DOMAIN` (default `netbird.selfhosted` — must match
your management server's DNS domain, since the per-run policy blocks the
cluster-local service path); with `MESH_ENFORCE=false` they fall back to the
in-cluster `*.security-gateways.svc.cluster.local` services.

## Run lifecycle

| Phase | Set by | Meaning |
|---|---|---|
| `Pending` | run controller | CR accepted, Job being created |
| `Cloning` | run controller | init container cloning + installing deps (`net-phase=clone`) |
| `Running` | run controller | main containers started (`net-phase=evaluate`) |
| `Evaluating` | evaluator | an agent is executing; `status.currentAgent` says which |
| `Completed` | evaluator, confirmed by run controller | `finalScore`, `scoring`, `findings`, `agentResults` populated |
| `Failed` | either | `status.message` names the stage/agent and the error class |

The evaluator patches `status.agentResults[<agent>]` after each agent, so
partial results survive a later failure. The full report is written to
`/output/evaluation-report.json` inside the Pod, summarised in the
container's termination message, and **persisted to a ConfigMap
`<run>-report`** (owner-referenced to the run, so it is garbage-collected
with it):

```bash
kubectl -n mcp-evals get configmap <run>-report -o jsonpath='{.data.report\.json}' | jq .
```

Reports above ~900 KiB fall back to `summary.json` + `report.truncated.json`
keys (ConfigMaps cap at ~1 MiB).

**Degraded continuation:** a persona that fails (LLM timeout, structured-output
exhaustion, target unavailable) no longer aborts the run — its error is
recorded in `agentResults[<agent>]` and the remaining agents still execute.
The run completes with a `degraded: N/M agent(s) failed (…)` message when at
least one agent produced results, and fails only if every agent failed.
The exception is a **strict-mode Vigil detection**, which remains a hard abort
(security semantics).

## Resilience model

| Failure | Recovery |
|---|---|
| Operator pod loss | 2 replicas with leader election (1 active + hot standby), PDB `minAvailable: 1`, topology spread, `PriorityClass mcp-eval-critical` |
| Transient API/etcd error creating a Job | controller-runtime backoff-retry (only validation errors fail the run) |
| Pod evicted / node lost / image-pull flake / OOM kill | run controller recreates the Job, bounded by `status.retries ≤ 2`; evaluation-verdict failures are never retried |
| Pod stuck Pending (pull/scheduling) | detected after 5 min without container progress → same bounded retry instead of burning the whole deadline |
| Vigil/Occludra replica loss | 2 replicas each, PDB, node spread, HTTP health probes with startupProbe; netbird TUN sidecars liveness-probed |
| Evaluator crash (uncaught exception / rejection) | process-level handler patches `phase: Failed` + termination message before exit |
| Terminal status patch lost to an API outage | terminal patches get extended backoff + one final `flushTerminalPatch()` from the shutdown path; the termination message is the last-resort copy the run controller reads back |
| NetBird sidecar slow to enroll | evaluator waits for the SOCKS5 proxy to accept connections (`MESH_READY_TIMEOUT_MS`, default 60s) before the first security-gateway call |
| Registry flake during clone/deps install | cloner wraps git/npm/uv/go ops in 300s timeout × 3 attempts |
| Stale per-run NetworkPolicies | deleted when the run reaches a terminal phase (owner-ref GC remains the backstop) |
| Deploying mesh mode without a setup key | `deploy.sh` hard-fails instead of shipping a platform whose runs cannot reach the gateways |
| Many runs due at once | run reconciler uses 8 concurrent workers (4 for the cron scheduler) — no serialization at the control plane |
| Gateway saturation (too many concurrent runs) | Vigil and Occludra autoscale via HPA (CPU 70 %, 2→8 replicas); at per-replica capacity limits they answer 503 + Retry-After and the evaluator backs off and retries |
| Cluster out of node capacity (OpenStack) | Cluster Autoscaler (`DEPLOY_AUTOSCALER=openstack`) boots an ephemeral Nova VM into the worker group for the pending run/gateway pods and deletes it again ~5 min after it goes idle; running evaluations are never preempted for scale-in |

### Scaling knobs

```bash
# HPA metrics backend (needed for the gateways' HorizontalPodAutoscalers):
AUTOSCALE_METRICS=1 ./deploy.sh ...

# Ephemeral-VM node autoscaling on a real OpenStack cluster (ignored on kind):
DEPLOY_AUTOSCALER=openstack \
  OS_AUTH_URL=https://keystone:5000/v3 OS_USERNAME=... OS_PASSWORD=... \
  OS_PROJECT_NAME=... OS_REGION_NAME=RegionOne \
  AUTOSCALER_NODE_GROUP=eval-workers AUTOSCALER_MIN=1 AUTOSCALER_MAX=10 \
  ./deploy.sh ...

# SPOF elimination for the external dependencies:
IN_CLUSTER_REGISTRY=1 ./deploy.sh ...        # registry inside the cluster (PVC-backed)
DEPLOY_NETBIRD_CP=1 NETBIRD_OIDC_CONFIG_ENDPOINT=<idp-wellknown-url> ./deploy.sh ...
                                             # self-hosted NetBird mgmt/signal/relay
# LLM upstream redundancy: point Occludra at a secondary provider
kubectl -n security-gateways set env deploy/occludra \
  OCCLUDRA_FALLBACK_UPSTREAM_BASE_URL=https://api.anthropic.com/v1 \
  OCCLUDRA_FALLBACK_API_KEY=<secondary-key>
```

## Observability

OpenTelemetry instruments the Go operator, TypeScript evaluator and Occludra.
Grafana Alloy collects their telemetry; Prometheus stores metrics, Loki stores
logs, and Tempo stores traces. Grafana provisions all three data sources and
**Dashboards → MCP evaluation → MCP evaluation platform**, a 14-panel dashboard
that refreshes every 30 seconds.

### What you can inspect

* **Evaluations:** retained runs by phase, latest terminal failure per server,
  oldest active evaluation, evaluator duration and controller reconciliation
  errors. Run counts are gauges over retained CR history; queries take `max`
  across manager replicas before aggregating to avoid double counting.
* **Gateway:** requests by route/status, P95 duration including the complete SSE
  stream, DLP redactions by detector, policy blocks and upstream failovers.
  Active-request metrics are also available in Explore → Prometheus.
* **Kubernetes:** desired/available deployment replicas, container restarts and
  telemetry scrape health.
* **Logs and traces:** correlate an evaluation across scheduling, Job execution,
  static evidence collection, agents, fuzzing, adversarial probes, MCP RPCs,
  Vigil client calls and Occludra. Prometheus loads six alert rules for failed
  or stuck evaluations, unavailable metrics/workloads, gateway errors and
  repeated restarts. Notification routing requires an Alertmanager destination.

The operator persists W3C context in `security.eval.io/traceparent` on the run
CR and passes it to the evaluator as `TRACEPARENT`. Runner logs include `run`,
`namespace`, `trace_id` and `span_id`; controller run logs and gateway completion
logs include trace IDs. In Grafana, **View trace** opens a log's trace in Tempo.
Traces cover stages actually executed after instrumentation was enabled.

In **Explore → Loki**, select a run:

```logql
{namespace="mcp-evals", container="evaluator"} | json | run="YOUR_RUN"
```

In **Explore → Tempo**, find its trace:

```traceql
{ span.mcp.run = "YOUR_RUN" }
```

In **Explore → Prometheus**, inspect firing alerts:

```promql
ALERTS{alertstate="firing"}
```

Vigil has client-side spans; its external server image is not instrumented here.
The helper connects an existing Chroma collector through
`manifests/chroma/otel-collector-observability.yaml`; joining Chroma traces to
Vigil requests requires propagation inside Vigil. OpenCode inference calls
appear under agent spans through Occludra. Untrusted target/cloner logs are
excluded from the shared log store.

### Deploy and access

Install monitoring with `make observability`, or enable it during a full deploy
with `DEPLOY_OBSERVABILITY=1`. Build and push/import versioned first-party images
before rolling out instrumentation. For an existing deployment:

```bash
OPERATOR_IMG="$IMG_REGISTRY/mcp-eval-operator:$IMG_TAG" \
EVALUATOR_IMG="$IMG_REGISTRY/mcp-evaluator:$IMG_TAG" \
OCCLUDRA_IMG="$IMG_REGISTRY/occludra-gateway:$IMG_TAG" \
./hack/deploy-observability.sh
kubectl -n mcp-eval-system rollout status deploy/mcp-eval-controller-manager
kubectl -n security-gateways rollout status deploy/occludra
```

The helper preserves provider, credential and mesh settings and saves previous
Deployments under `/tmp/mcp-observability-rollback.*`. The image import helper
registers images with containerd CRI so `IfNotPresent` can use them locally.
Check monitoring with `kubectl -n observability get pods,pvc`.

Run each port-forward in a separate terminal and leave it open:

```bash
kubectl -n observability port-forward svc/grafana 3000:3000
kubectl -n observability port-forward svc/prometheus 9090:9090
kubectl -n observability port-forward svc/otel-collector 12345:12345
```

| Interface | Local URL | Purpose |
|---|---|---|
| Grafana | http://localhost:3000 | Dashboard and Explore for metrics, logs and traces |
| Prometheus | http://localhost:9090 | PromQL queries, `/alerts` for rules and `/targets` for scrape health |
| Alloy | http://localhost:12345 | Collector components, configuration and pipeline health |

Grafana's username is `admin`. Retrieve the generated password in another
terminal; the same Secret is retained on redeployment:

```bash
kubectl -n observability get secret grafana-admin -o jsonpath='{.data.password}' | base64 -d
```

Loki (3100) and Tempo (3200) provide backend APIs and `/ready` endpoints; their
visual exploration is in Grafana. kube-state-metrics exposes `/metrics` on 8080.
Alloy receives OTLP over gRPC on 4317 and HTTP on 4318. Operator metrics use HTTPS
on 8443; Occludra exposes `/metrics` on 8080.

### Retention, isolation and rollback

Prometheus retains 15 days or 8 GB; Loki and Tempo retain seven days. Five PVCs
use 32 GiB in the default StorageClass. Resource requests total 500m CPU and
1,216 MiB RAM. The backends are single instances with persistent storage;
monitoring can pause during node loss or volume reattachment. Alloy outages
longer than Job retention can leave gaps in logs.

All services use ClusterIP and restricted NetworkPolicies. Monitoring accounts
cannot read Kubernetes Secrets. Application metadata is traced; runner logging
redacts sensitive evidence/credential fields, and Alloy sanitizes legacy log
text. Metric labels exclude run/trace IDs and arbitrary request content. Job
metrics have a distinct service instance and flush before process exit; exporter
failure does not change an evaluation's result.

An evaluation Pod's target shares its evaluator's network namespace and can
reach the allowed telemetry ingestion port. Telemetry is diagnostic evidence;
CR status and reports remain the authoritative security verdict.

Set `OTEL_SDK_DISABLED=true` or remove `OTEL_EXPORTER_OTLP_ENDPOINT` on the manager
and gateway to disable export; new Jobs inherit the manager's configuration.
Use the saved Deployment manifests or Kubernetes rollout history to roll back.
Removing workloads preserves StatefulSet PVCs by default; deleting the namespace
or PVCs discards stored telemetry.

## Security model

The untrusted MCP server is the threat. Controls, from outermost in:

1. **Namespace** — PodSecurity `restricted` is *enforced* on `mcp-evals`; a
   Pod that loosens any securityContext field is rejected by the API server.
2. **NetworkPolicy** — default-deny ingress+egress for the namespace.
   Kubernetes network policy is Pod-scoped and the sandbox is one Pod, so the
   run controller phases the allowed egress via the Pod label
   `security.eval.io/net-phase`:
   * `clone` — only while init containers run (target not yet started):
     egress to git hosts / package registries on 443.
   * `evaluate` — flipped as soon as all init containers terminate: a
     **per-run policy generated by the operator** (`<run>-evaluate-egress`)
     takes over. In mesh mode it allows ONLY DNS, the API server (endpoint
     IPs resolved at reconcile time) and the NetBird control/data planes; in
     legacy mode (`MESH_ENFORCE=false`) it allows the gateways' service ports
     and public 443 as well. See *Security layers* below.
   When observability is enabled, an additive policy also allows the evaluation
   Pod to reach the Alloy collector on TCP/4318.
   `networkpolicy-cilium.yaml` pins the clone-phase rules to exact FQDNs on
   Cilium.
3. **Pod** — `automountServiceAccountToken: false`; the evaluator alone mounts
   a 1-hour projected token; `hostNetwork/PID/IPC` off; `activeDeadlineSeconds`
   from `spec.timeoutSeconds`; Job `backoffLimit: 0`, `ttlSecondsAfterFinished: 600`.
4. **Target container** — `runAsNonRoot`, UID 10002 (≠ evaluator 10001),
   `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all
   capabilities dropped, `RuntimeDefault` seccomp, no secrets, no token, no CA
   bundle in the image, `/workspace` mounted read-only; only `/tmp` and the
   `/tmp` and the `/ipc` emptyDir are writable. Its only I/O is stdio bound to
   `/ipc/stdin` + `/ipc/stdout` FIFOs (or `127.0.0.1:<port>` for SSE), which
   never leaves the Pod's network namespace.
5. **Evaluator container** — same locked securityContext; the OpenCode
   personas run tool-free (every tool permission denied), so an injected
   instruction in the target's source or output cannot make the evaluator act
   on the cluster or filesystem.

Residual risk to be aware of: because the target shares the Pod's network
namespace, during the `evaluate` phase it can reach the same endpoints the
evaluator can — DNS, the API server, the NetBird ports (WireGuard drops
unauthenticated packets, so this is inert), and the loopback listeners: the
netbird SOCKS5 proxy (`127.0.0.1:1080`), the mesh bridge (`127.0.0.1:18080`)
and the OpenCode server (`127.0.0.1:4096`). It holds no credentials for any of
them, and the NetBird ACLs attached to the evaluation setup key's group are
the enforcement layer for the proxy paths — scope that group to `vigil` +
`occludra` only. If loopback reachability is unacceptable for your threat
model, run with a RuntimeClass such as gVisor (`runtimeClassName` on the Job
template) or deploy the target as a separate Pod labelled
`security.eval.io/role=target`, which the shipped `target-deny-all` policy
blocks completely.

## Adding or changing an agent

Agent personas are data, not code:

```bash
kubectl -n mcp-evals edit opencodeagent mcp-rogue-detector   # tweak prompt/schema/model
kubectl -n mcp-evals annotate mcpserver filesystem-mcp security.eval.io/trigger-now=true
```

The evaluator resolves agents by `spec.role` (`StaticSecurityAuditor`,
`DynamicProtocolFuzzer`, `RogueBehaviorProbe`, `SynthesisScorer`) to decide
which evidence to collect for them; any other role receives all prior agents'
outputs as context and runs as a generic structured-output pass.

## Development

```bash
make manifests generate   # regenerate CRDs / deepcopy with controller-gen
make build                # go build
make run                  # run the manager against the current kubeconfig
cd runner && npm ci && npm run typecheck && npm run build
DRY_RUN=1 OUTPUT_DIR=/tmp/out node runner/dist/evaluator.js   # offline runner smoke test
```
