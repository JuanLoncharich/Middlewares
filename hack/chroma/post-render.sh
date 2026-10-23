#!/usr/bin/env bash
# Patches the vendored Chroma chart's rendered output without editing the
# chart (manifests/chroma/chart is re-vendored verbatim from upstream):
#   helm template ... | hack/chroma/post-render.sh | kubectl apply -f -
# Each manifests/chroma/patches/*.yaml is a strategic-merge patch, applied
# with kustomize (kubectl kustomize, no extra tool).
set -euo pipefail
patches="$(cd "$(dirname "$0")/../../manifests/chroma/patches" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/chart.yaml"
{
  echo "resources: [chart.yaml]"
  echo "patches:"
  for p in "$patches"/*.yaml; do
    cp "$p" "$work/"
    echo "  - path: $(basename "$p")"
  done
} > "$work/kustomization.yaml"
kubectl kustomize "$work"
