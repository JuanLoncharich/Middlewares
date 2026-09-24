# Vendored chart — distributed Chroma

Copied verbatim from **chroma-core/chroma** `main`, path `k8s/distributed-chroma`,
commit `30d701a4367c8dd8adb50d4ff144e10c4b4fbf36` (2026-09-23), Apache-2.0.

Changes vs upstream: dropped the upstream dev values overlays
(`values.dev.yaml`, `values2*.yaml`) — this repo ships its own values file
(`../values-mcp-eval.yaml`) and its own worker/frontend configuration files
(`../worker-config.yaml`, `../frontend-config.yaml`) passed via `helm
template --set-file`, exactly like chroma's own Tiltfile does.

Do not hand-edit templates here; re-vendor from upstream instead. The chart
must always match the image tag pinned in `values-mcp-eval.yaml`: the
component images are built per-commit by chroma's CI (Docker Hub org
`chromadb`, tag = short commit SHA), so mixing chart and images from wildly
different commits can break the internal gRPC protocols.
