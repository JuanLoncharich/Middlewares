# mcp-eval-operator

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

evaluator ──Vigil /analyze──▶ vigil   (security-gateways, WireGuard mesh)
evaluator ──LLM calls──────▶ occludra┐ (security-gateways, WireGuard mesh)
                            └─PII scrub──▶ upstream LLM
```

## Layout

| Path | Contents |
|---|---|
| `api/v1alpha1/` | CRD Go types (`OpenCodeAgent`, `MCPServer`, `MCPEvaluationRun`) + deepcopy |
| `internal/controller/` | `MCPServer` (cron scheduler) and `MCPEvaluationRun` (Job builder / status) reconcilers |
| `cmd/main.go` | controller-manager entrypoint |
| `config/crd/bases/` | generated-equivalent CRD manifests |
| `config/rbac/` | manager ClusterRole, leader-election Role, runner ServiceAccount/Role |
| `config/manager/` | operator Deployment (namespace `mcp-eval-system`) |
| `config/samples/` | namespace, NetworkPolicies, reference sandbox Pod, four agent personas, `MCPServer` sample |
| `manifests/` | Vigil-LLM, Occludra and NetBird deployments (namespace `security-gateways`) — the three security layers |
| `runner/` | TypeScript evaluator (`@opencode-ai/sdk` + `@kubernetes/client-node`) |
| `images/cloner/` | init-container image: git + npm/uv/go toolchain detection |
| `images/target/` | sandbox image: supervisor that binds the server's stdio to the IPC FIFOs |

## Install

Prerequisites on the deploying machine: `kubectl` (configured for the target
cluster), `docker` with push access to a registry the cluster can pull from.

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
  IMG=$IMG_REGISTRY/mcp-eval-operator:latest \
  CLONER_IMG=$IMG_REGISTRY/mcp-cloner:latest \
  TARGET_IMG=$IMG_REGISTRY/mcp-target-sandbox:latest \
  EVALUATOR_IMG=$IMG_REGISTRY/mcp-evaluator:latest
docker push $IMG_REGISTRY/mcp-cloner:latest \
  && docker push $IMG_REGISTRY/mcp-target-sandbox:latest \
  && docker push $IMG_REGISTRY/mcp-evaluator:latest
# point the operator at your images
sed -i "s|ghcr.io/security-eval|$IMG_REGISTRY|g" config/manager/manager.yaml

# 2. CRDs + operator (namespace mcp-eval-system) + runner RBAC (namespace mcp-evals)
make deploy            # = kubectl kustomize config/default | kubectl apply -f - ; kubectl apply -f config/rbac/runner_role.yaml

# 3. Evaluation namespace, NetworkPolicies, agent personas, sample server
#    (edit the 10.96.0.1/32 API-server CIDR in config/samples/networkpolicy.yaml first)
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
  evaluator POSTs it to `vigil-service:5000/analyze`. A verdict of
  *injection detected* aborts the run, scores it `0` with
  `riskCategory=Malicious`, records a `Critical` finding and surfaces through
  the CRD status/termination message. `VIGIL_ENFORCE=monitor` downgrades
  detections to log+finding; in the default `strict` mode an *unreachable*
  scanner also fails the run (fail-closed). Set `VIGIL_ENABLED=0` to disable.
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
`MESH_BRIDGE_PORT` (18080), `VIGIL_URL`, `VIGIL_ENABLED`, `VIGIL_ENFORCE`,
`VIGIL_TIMEOUT_MS`, `VIGIL_MAX_PAYLOAD_BYTES`, `OCCLUDRA_BASE_URL`,
`OCCLUDRA_ENABLED`. The operator derives `VIGIL_URL` / `OCCLUDRA_BASE_URL`
from the mode: in mesh mode they become the NetBird peer names under
`NETBIRD_DNS_DOMAIN` (default `netbird.selfhosted` — must match your
management server's DNS domain, since the per-run policy blocks the
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
partial results survive a later failure. The full report is also written to
`/output/evaluation-report.json` inside the Pod and summarised in the
container's termination message.

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
     **per-run policy generated by the operator** (`<run>-mesh-egress`) allows
     ONLY DNS, the API server (endpoint IPs resolved at reconcile time) and
     the NetBird control/data planes. Direct LLM-provider egress does not
     exist in this mode; see *Security layers* below.
   `networkpolicy-cilium.yaml` pins the clone-phase rules to exact FQDNs on
   Cilium. Set `MESH_ENFORCE=false` on the operator to restore the legacy
   direct-to-provider mode (and re-add a static evaluate-phase policy).
3. **Pod** — `automountServiceAccountToken: false`; the evaluator alone mounts
   a 1-hour projected token; `hostNetwork/PID/IPC` off; `activeDeadlineSeconds`
   from `spec.timeoutSeconds`; Job `backoffLimit: 0`, `ttlSecondsAfterFinished: 600`.
4. **Target container** — `runAsNonRoot`, UID 10002 (≠ evaluator 10001),
   `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all
   capabilities dropped, `RuntimeDefault` seccomp, no secrets, no token, no CA
   bundle in the image, `/workspace` mounted read-only; only `/tmp` and the
   memory-backed `/ipc` are writable. Its only I/O is stdio bound to
   `/ipc/stdin` + `/ipc/stdout` FIFOs (or `127.0.0.1:<port>` for SSE), which
   never leaves the Pod's network namespace.
5. **Evaluator container** — same locked securityContext; the OpenCode agents
   are given read-only file tools (`edit`/`bash`/`webfetch` denied) so an
   injected instruction in the target's source or output cannot make the
   evaluator act on the cluster or filesystem.

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
