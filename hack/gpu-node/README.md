# gpu-node — this PC as an on-demand GPU worker

Attaches a personal machine (RTX GPU) to the k0s cluster **only when you run
`gpu-node up`**, runs the GPU build of the Vigil scanner on it, and removes
every trace with `gpu-node down`. Nothing starts at boot.

## What runs on the GPU

Only the two deberta classifiers inside Vigil run on CUDA (measured on an
RTX 5060 Ti: 28 ms -> 3 ms per full 256-token window, verdicts identical to
CPU). MiniLM stays on CPU: its int8 export is *slower* on CUDA and its
embeddings would drift from what the Chroma thresholds were calibrated on.
The cosine/HNSW search stays in Chroma (CPU, 8.9k vectors). The CPU `vigil`
Deployment stays as the always-on fallback, and the GPU scanner returns the
**same verdicts** as the CPU one.

| Piece | File |
|---|---|
| Provider selection (`cpu`/`auto`/`cuda`, per-model override, VRAM soft cap, startup warm-up) | `images/vigil-stub/ortutil.py` |
| GPU image | `images/vigil-stub/Dockerfile.gpu` |
| GPU scanner Deployment + its own Service (required nodeAffinity) | `manifests/vigil-gpu-deployment.yaml` |
| Evaluator prefers the GPU scanner, falls back to CPU | `runner/src/vigil.ts` (`VIGIL_GPU_URL`), operator env `VIGIL_GPU_URL` |
| Node on/off | `gpu-node` (+ `gpu-node.conf`) |
| CPU vs CUDA correctness + latency | `bench-onnx.py` |

Latency caveat: the PC is ~26 ms from the cluster, so a scan through it is not
faster end to end than a local CPU pod; the gain is CPU/RAM moved off the
cluster's small nodes and headroom for heavier detectors.

## Whole-payload scanning: measured, and why it is report-only

The deberta models read the first 256 tokens and MiniLM the first 128 of each
payload; the evaluator sends up to 64 KiB (~16-26k tokens). `windowing.py` can
classify the whole payload as one batch (`VIGIL_MAX_WINDOWS`,
`VIGIL_VECTOR_MAX_WINDOWS`; ~1.5 s per 55 KiB payload on the GPU; CPU is ~185 ms
per window, i.e. ~20 s — not feasible). **It never changes a verdict**, because
on real data it does not help:

* `calibrate-windows.py` (8 benign repo payloads x 8 planted injections):
  worst-window score is >= 0.99 on 2-6 of 8 *benign* payloads (Go source,
  `go.sum`, Python, shell, JSON) for the two deberta models; `transformer`
  detects essentially none of the planted injections.
* `calibrate-vector.py` (MiniLM -> real Vigil corpora): 0 false alarms but
  0/192 detections; alone, only 1 of 8 paraphrased injections is within 0.45
  of the corpus.

So today no ML/vector engine reliably finds a paraphrased injection buried in
a large structured payload; the regex/YARA engines already scan the whole
text. Windowed scores (`window_score`, `window_distance`, `windows`,
`truncated`) are emitted when enabled, for calibrating on real platform
traffic. Needs a model trained on tool output / natural-language-field
extraction before it can be enforced.

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
#   Calico must advertise the ZeroTier address for the PC — see "Calico" below            [pending]
#   the platform (deploy.sh) must exist: security-gateways namespace, vigil SA, vigil-service [pending]
gpu-node deploy-gpu                # vigil-gpu Deployment (replicas 0) + vigil-gpu-service
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
