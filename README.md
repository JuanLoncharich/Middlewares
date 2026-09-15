# mcp-eval-operator

Automated static + dynamic security evaluation of Model Context Protocol (MCP)
servers on Kubernetes. Point an `MCPServer` resource at a GitHub repository and
the operator periodically clones it, runs it inside a locked-down sandbox, and
drives an ensemble of OpenCode agents (SAST, protocol fuzzing, rogue-behaviour
probing, synthesis) against it, writing a structured verdict back into the CR.

```
MCPServer ──schedule──▶ MCPEvaluationRun ──▶ batch/v1 Job (one Pod)
                                               ├─ init  cloner     shallow clone + toolchain detect → /workspace
                                               ├─ ctr   target     untrusted MCP server, jailed, stdio ⇄ /ipc FIFOs
                                               └─ ctr   evaluator  @opencode-ai/sdk runner, patches status
OpenCodeAgent ×4 ─── referenced by agentSuite ──▶ fetched by the evaluator at run time
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
| `runner/` | TypeScript evaluator (`@opencode-ai/sdk` + `@kubernetes/client-node`) |
| `images/cloner/` | init-container image: git + npm/uv/go toolchain detection |
| `images/target/` | sandbox image: supervisor that binds the server's stdio to the IPC FIFOs |

## Install

Prerequisites on the deploying machine: `kubectl` (configured for the target
cluster), `docker` with push access to a registry the cluster can pull from.

### Fast path

```bash
git clone <this repo> && cd Middlewares
IMG_REGISTRY=ghcr.io/<you> ANTHROPIC_API_KEY=sk-ant-... ./deploy.sh
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
kubectl -n mcp-evals create secret generic llm-provider-credentials --from-literal=ANTHROPIC_API_KEY=sk-ant-...

# 4. Trigger a run immediately instead of waiting for the cron schedule
kubectl -n mcp-evals annotate mcpserver filesystem-mcp security.eval.io/trigger-now=true
kubectl -n mcp-evals get mcprun -w
```

The operator's Deployment reads the image names from `CLONER_IMAGE`,
`TARGET_IMAGE`, `EVALUATOR_IMAGE`, the runner ServiceAccount from
`RUNNER_SERVICE_ACCOUNT` (`mcp-eval-runner`), and the LLM credential secret
from `LLM_SECRET_NAME` / `LLM_SECRET_KEY` (`llm-provider-credentials` /
`ANTHROPIC_API_KEY`).

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
   * `evaluate` — flipped as soon as all init containers terminate: egress
     only to DNS, the API server, and the LLM endpoint on 443.
   `networkpolicy-cilium.yaml` pins the same rules to exact FQDNs
   (`api.anthropic.com`, `github.com`, …) on Cilium. With the vanilla
   `NetworkPolicy` file, replace the `10.96.0.1/32` API-server CIDR with your
   cluster's value.
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
namespace, during the `evaluate` phase it can open *unauthenticated* TCP
connections to the same hosts the evaluator can (LLM API, apiserver). It holds
no credentials for either. If that is unacceptable for your threat model, run
with a RuntimeClass such as gVisor (`runtimeClassName` on the Job template) or
deploy the target as a separate Pod labelled `security.eval.io/role=target`,
which the shipped `target-deny-all` policy blocks completely.

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
