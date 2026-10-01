# gpu-node — this PC as an on-demand GPU worker

Attaches a personal machine (RTX GPU) to the k0s cluster **only when you run
`gpu-node up`**, runs the GPU build of the Vigil scanner on it, and removes
every trace with `gpu-node down`. Nothing starts at boot.

## What runs on the GPU: the full Vigil, scaled to zero when idle

```
              operator (mcp-eval-system)
              GET :8082/active-runs -> {"activeRuns": N}   (non-terminal MCPEvaluationRuns)
                         │ polled every 15 s
                         ▼
   KEDA (ns keda) ── ScaledObject vigil-gpu: N>0 -> 1 replica, idle 10 min -> 0
                         │
                         ▼
   vigil-gpu (security-gateways) ── pinned to this PC (required nodeAffinity + toleration)
        full vigil-llm: transformer on CUDA, yara, vectordb; HF cache on the PC's disk
                         ▲
   evaluator ── VIGIL_GPU_URL first ──┘   falls back to ──► vigil-service (in-cluster)
```

| Piece | File |
|---|---|
| GPU image: same pinned vigil-llm source, CUDA torch 2.7 (Blackwell), transformer pipeline on GPU | `images/vigil-gpu/Dockerfile`, `build-vigil-gpu.sh` |
| ConfigMap + Deployment (replicas owned by KEDA) + Service + ScaledObject | `manifests/vigil-gpu.yaml` |
| Operator `/active-runs` (KEDA metrics-api trigger) | `internal/controller/activity.go`, Service `mcp-eval-operator-activity` |
| KEDA install values (small, no webhooks, never on the PC) | `manifests/keda/values-mcp-eval.yaml` |
| Evaluator prefers the GPU Vigil, falls back to the CPU one | `runner/src/vigil.ts` (`VIGIL_GPU_URL`) |

Why a custom metric and not KEDA's pod-count trigger: `kubernetes-workload`
only counts pods in the ScaledObject's own namespace, and evaluation pods
(`mcp-evals`) and the scanner (`security-gateways`) live apart.

States:

| Situation | GPU Vigil | Who scans |
|---|---|---|
| PC detached (`gpu-node down`) | ScaledObject **paused at 0** | in-cluster Vigil |
| PC attached, no evaluation for 10 min | **0** (GPU + RAM free) | — |
| Evaluation starts | 0 -> 1; ready during the run's clone phase | GPU Vigil (CPU Vigil until it is Ready) |

`VIGIL_PROFILE=lite` (deploy.sh) shrinks the in-cluster fallback to YARA only,
for when the full scanner should live on this PC. The evaluation report records
which endpoint answered each scan.

Lessons that still hold (measured with the earlier ONNX stub, commit e61b9fc):
only big transformer forward passes benefit from the GPU; similarity search
over ~9k vectors is microseconds on CPU; whole-payload windowed scoring with
prompt-trained classifiers false-alarms on code/JSON; the PC is ~26 ms away,
so the gain is offloading the small nodes, not latency.

## Network (already done)

ZeroTier network `565799d8f675597b`, pool `10.147.17.0/24`: this PC + the three
nodes, all links DIRECT. Two things make VXLAN work across it, both verified
with UDP/4789 tests:

* "Allow Ethernet Bridging" is ticked for the **three nodes** in ZeroTier
  Central (Calico sends VXLAN with the node's `10.66.50.x` source; ZeroTier
  drops that otherwise).
* `gpu-node up` adds `ufw` allow rules for UDP/4789 on the ZeroTier interface
  and host routes `10.66.50.x/32 via <node ZeroTier IP>` so replies return over
  ZeroTier instead of the NAT gateway. `gpu-node down` removes both.

## Limits (gpu-node.conf)

| Resource | Limit | How it is enforced |
|---|---|---|
| CPU | 4 cores | `CPUQuota=400%` on `k0s-gpu.slice`; kubelet `--system-reserved` so the scheduler sees 4 |
| RAM | 4 GiB | `MemoryMax=4G` (+`MemoryHigh`, swap off) on the slice; kubelet sees ~3 GiB allocatable |
| VRAM | 8 GiB | **soft** cap: onnxruntime `gpu_mem_limit`. NVIDIA consumer GPUs have no hard per-container VRAM limit |

The kubelet runs with `--cgroup-root=/k0s-gpu.slice`, so pods fall under the
same limits as k0s itself.

## Order of operations

```
gpu-node preflight                 # read-only; shows what is missing
gpu-node install                   # sudo: k0s binary (sha256-verified), unit+slice,
                                   #       containerd NVIDIA runtime, join token          [done]
gpu-node cluster-prep              # RuntimeClass, device plugin, 2 DaemonSets kept off the node  [done]
hack/gpu-node/build-vigil-gpu.sh   # build vigil-llm-gpu:local (same pinned source, CUDA torch)
DEPLOY_KEDA=1 VIGIL_GPU=1 [VIGIL_PROFILE=lite] ./deploy.sh ...   # KEDA + paused GPU Vigil + VIGIL_GPU_URL
#   Calico must advertise the ZeroTier address for the PC — see "Calico" below            [pending]
#   the platform (deploy.sh) must exist: security-gateways namespace, vigil SA, vigil-service [pending]
gpu-node up                        # attach: firewall+routes, k0s, Ready, GPU advertised,
                                   #         image import (first time), scanner scaled to 1
gpu-node smoke                     # nvidia-smi in a pod on the node
gpu-node down                      # detach
```

## Calico (needs a cluster-wide decision)

Calico uses `IP=autodetect` (first interface found). On this PC that would pick
the home LAN address `10.0.0.135`, not ZeroTier. Fix on the controller, in the
k0s config: `spec.network.calico.envVars`:
`IP_AUTODETECTION_METHOD=can-reach=10.66.50.59`. Applying it restarts
`calico-node` once on every node. **Not applied by any script here.**

## Safety properties

* The systemd unit has no `[Install]` section — it cannot be enabled at boot.
* Evaluation Jobs have no toleration for `nvidia.com/gpu=present:NoSchedule`,
  so untrusted MCP code is never scheduled on this PC.
* `up` rolls back (`down`) on any failure; `down` deletes the Node object, so
  the cluster never shows a stale NotReady node or Pending GPU pods.
* The join token is fetched through the jump host straight into a mode-0600
  file; it is never printed.

## Status

Verified: the GPU code on this PC (venv and container, production-like limits),
the runner fallback logic (8 cases), the operator change (build, vet, tests),
all manifests (dry-run), `preflight` 13/13, `install`, `cluster-prep`.

**Not yet executed:** `up`/`down` themselves — the k0s worker joining over
ZeroTier, the cgroup layout (`--cgroup-root`, delegated slice) and the NVIDIA
runtime wrapper on Arch are the parts most likely to need adjusting on the
first run; `preflight` and `smoke` exist to show exactly where.
