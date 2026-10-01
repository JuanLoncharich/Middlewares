# gpu-node — this PC as an on-demand GPU worker

Attaches a personal machine (RTX GPU) to the k0s cluster **only when you run
`gpu-node up`**, runs the GPU build of the Vigil scanner on it, and removes
every trace with `gpu-node down`. Nothing starts at boot.

## What runs on the GPU — being redone for the real Vigil

The first GPU workload was the ONNX-based Vigil *stub* (deberta forward passes
on CUDA, 8-10x faster, identical verdicts). Commit 1173676 replaced the stub
with the real `vigil-llm` (torch/transformers), so that scanner and its
measurements were removed from the tree; they remain in commit e61b9fc
(`images/vigil-stub/{ortutil,windowing}.py`, `Dockerfile.gpu`,
`hack/gpu-node/{bench-onnx,calibrate-windows,calibrate-vector}.py`).

Findings that still hold for any detector placed here:
* only big transformer forward passes benefit from the GPU; similarity search
  over ~9k vectors is microseconds on CPU and does not;
* whole-payload windowed scoring with prompt-trained classifiers false-alarms
  on code/JSON/config — never let it decide verdicts without calibration;
* the PC is ~26 ms from the cluster: the gain is offloading the small nodes,
  not end-to-end latency.

Next step: a CUDA build of the real vigil-llm (torch device selection), pinned
here with the same required nodeAffinity + toleration, behind `VIGIL_GPU_URL`
(the evaluator already prefers it and falls back to the CPU Vigil).

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
