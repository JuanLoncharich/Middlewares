#!/usr/bin/env bash
# Render what deploy.sh would apply into plain YAML that Flux syncs.
#
#   hack/gitops/render.sh deploy/k0s           # uses deploy/k0s/render.env
#   IMG_TAG=sha-abc1234 hack/gitops/render.sh deploy/k0s
#
# deploy.sh stays the single description of the platform. This script runs it
# with a stand-in `kubectl` first on PATH that applies nothing: every manifest
# it would `apply` is collected, `set env` calls become env changes on the
# collected Deployments, and read-only lookups get the values in render.env.
# Nothing here talks to a cluster, so CI runs it too.
#
# Output: <dir>/generated/*.yaml, one file per namespace (cluster-scoped
# objects in _cluster.yaml). Secrets are DROPPED: they never go to git. Create
# them once per cluster with hack/gitops/secrets.sh.
#
# <dir>/render.env holds the deploy.sh settings for that cluster (no secrets),
# plus RENDER_API_PEERS / RENDER_API_PORT: the API server's real endpoints,
# which Chroma's egress policy needs (kubectl get endpointslices -n default
# -l kubernetes.io/service-name=kubernetes).
set -euo pipefail
cd "$(dirname "$0")/../.."

dir="${1:?usage: render.sh <cluster dir, e.g. deploy/k0s>}"
[ -f "$dir/render.env" ] || { echo "missing $dir/render.env" >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo "render.sh needs PyYAML (pip install pyyaml)" >&2; exit 1; }
REAL_KUBECTL="$(command -v kubectl)" || { echo "render.sh needs kubectl (for kustomize and --dry-run=client)" >&2; exit 1; }
command -v helm >/dev/null || { echo "render.sh needs helm (helm template)" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cp hack/gitops/fake-kubectl.py "$work/bin/kubectl"
chmod +x "$work/bin/kubectl"

# render.env is sourced for its variables, then the caller's IMG_TAG (CI) wins.
caller_tag="${IMG_TAG:-}"
set -a
# shellcheck disable=SC1090
. "$dir/render.env"
set +a
[ -z "$caller_tag" ] || IMG_TAG="$caller_tag"
export IMG_TAG

# Fixed for rendering: nothing is built, no Secret is written, no run is
# triggered (Flux applies; a cluster's Secrets come from secrets.sh).
REAL_KUBECTL="$REAL_KUBECTL" RENDER_OUT="$work/stream" PATH="$work/bin:$PATH" \
  SKIP_BUILD=1 SKIP_SECRET=1 TRIGGER=0 DEPLOY_OBSERVABILITY=0 \
  ./deploy.sh > "$work/deploy.log" 2>&1 \
  || { cat "$work/deploy.log" >&2; echo "deploy.sh failed while rendering (log above)" >&2; exit 1; }

python3 hack/gitops/collect.py "$work/stream" "$dir/generated"
echo "rendered $dir/generated (IMG_TAG=$IMG_TAG):"
ls -1 "$dir/generated"
