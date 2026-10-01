#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Air-gap image import for clusters WITHOUT a reachable registry (e.g. a
# fresh OpenStack k0s cluster managed from a workstation with no push
# credentials).
#
# Mechanism: a privileged DaemonSet (ubuntu + containerd's ctr) mounts each
# node's k0s containerd socket; every image is `docker save`d locally,
# streamed over `kubectl exec -i`, and imported with the node's own
# containerd. Kubelet then finds the images in its local store — deploy the
# platform with IMAGE_PULL_POLICY=IfNotPresent (deploy.sh) so nothing tries
# to reach a registry.
#
#   [NODES="nodo-g1-1 nodo-g1-3"] hack/import-images-to-nodes.sh [image ...]
#
# Requires: node internet for the first containerd apt install; docker and
# kubectl (cluster-admin) locally.
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/.."

CONTEXT="${CONTEXT:-}"
DS_NS="kube-system"
DS_NAME="image-importer"
CTR_SOCKET="/run/k0s/containerd.sock"
CTR_BIN="/usr/bin/ctr"

IMAGES=("$@")
if [ ${#IMAGES[@]} -eq 0 ]; then
  IMAGES=(
    ghcr.io/security-eval/mcp-eval-operator:latest
    ghcr.io/security-eval/mcp-cloner:latest
    ghcr.io/security-eval/mcp-target-sandbox:latest
    ghcr.io/security-eval/mcp-evaluator:latest
    ghcr.io/security-eval/occludra-gateway:latest
    ghcr.io/security-eval/vigil-stub:latest
    ghcr.io/security-eval/vigil-corpus-loader:latest
    # Vector DB plane (see manifests/chroma/): keep CHROMA_IMG_TAG in sync
    # with deploy.sh / manifests/chroma/values-mcp-eval.yaml.
    chromadb/sysdb-service:dff1d8a
    chromadb/sysdb-migration:dff1d8a
    chromadb/rust-sysdb-service:dff1d8a
    chromadb/rust-frontend-service-oss:dff1d8a
    chromadb/rust-log-service:dff1d8a
    chromadb/query-service:dff1d8a
    chromadb/compactor-service:dff1d8a
    chromadb/work-queue-service:dff1d8a
    chromadb/fn-consumer-service:dff1d8a
    chromadb/garbage-collector-service:dff1d8a
    quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e
    postgres:15
    otel/opentelemetry-collector:0.107.0
  )
fi

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

kubectl() { if [ -n "$CONTEXT" ]; then command kubectl --context "$CONTEXT" "$@"; else command kubectl "$@"; fi; }

log "Deploying privileged importer DaemonSet (ubuntu + containerd/ctr)"
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: $DS_NAME
  namespace: $DS_NS
  labels:
    app: image-importer
spec:
  selector:
    matchLabels:
      app: image-importer
  template:
    metadata:
      labels:
        app: image-importer
    spec:
      tolerations:
      - operator: Exists
      containers:
      - name: importer
        image: ubuntu:24.04
        command: ["bash", "-c", "apt-get update -qq && apt-get install -y -qq containerd >/dev/null 2>&1 && sleep infinity"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: socket
          mountPath: /run/k0s
        resources:
          requests: {cpu: 10m, memory: 64Mi}
      volumes:
      - name: socket
        hostPath: {path: /run/k0s, type: Directory}
EOF
kubectl -n "$DS_NS" rollout status "ds/$DS_NAME" --timeout=420s

# NODES="nodo-g1-1 nodo-g1-3" limits the import to those nodes (e.g. skip the
# tainted control-plane node, which can never run these workloads).
PODS=""
while read -r pod node; do
  [ -n "$pod" ] || continue
  if [ -z "${NODES:-}" ] || [[ " $NODES " == *" $node "* ]]; then PODS="$PODS $pod"; fi
done < <(kubectl get pods -n "$DS_NS" -l app=image-importer -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}')
PODS="${PODS# }"
[ -n "$PODS" ] || { echo "no importer pods matched NODES='${NODES:-}'" >&2; exit 1; }
echo "importer pods: $PODS"

# The importer image ships a containerd CLIENT that can be newer than the
# node's containerd (ubuntu:24.04 -> 2.x vs k0s 1.7.x). A 2.x `ctr` imports via
# the transfer service and reports success, but the node's CRI (kubelet) then
# cannot see the image ("not present with pull policy Never"). So every pod
# gets a `ctr` matching the node's server version, downloaded from the
# containerd release.
CTR_MATCHED=/usr/local/bin/ctr-matched
setup_matched_ctr() {
  local pod="$1"
  kubectl exec -n "$DS_NS" "$pod" -- bash -c '
    set -e
    [ -x /usr/local/bin/ctr-matched ] && exit 0
    apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
    SRV=$(ctr -a '"$CTR_SOCKET"' version 2>/dev/null | awk "/Server:/{s=1} s && /Version:/{print \$2; exit}")
    V=${SRV#v}; [ -n "$V" ] || { echo "cannot detect containerd server version" >&2; exit 1; }
    curl -fsSL -o /tmp/ctr.tgz https://github.com/containerd/containerd/releases/download/v$V/containerd-$V-linux-amd64.tar.gz
    tar -xzf /tmp/ctr.tgz -C /tmp bin/ctr && install -m0755 /tmp/bin/ctr /usr/local/bin/ctr-matched && rm -rf /tmp/ctr.tgz /tmp/bin'
}
for pod in $PODS; do setup_matched_ctr "$pod" || { echo "matched ctr setup failed on $pod"; exit 1; }; done
CTR="$CTR_MATCHED -a $CTR_SOCKET -n k8s.io"

# Save every image once, then stream to all selected nodes IN PARALLEL.
declare -A TARS
for image in "${IMAGES[@]}"; do
  tarfile="$(mktemp "${TMPDIR:-/tmp}/import.XXXXXX.tar.gz")"
  log "Saving $image"
  docker save "$image" | gzip -1 > "$tarfile"
  TARS["$image"]="$tarfile"
done

import_to_pod() {
  local pod="$1" image tarfile verified
  for image in "${IMAGES[@]}"; do
    tarfile="${TARS[$image]}"
    echo "  -> $pod: $image ($(du -h "$tarfile" | cut -f1))"
    kubectl exec -n "$DS_NS" "$pod" -- bash -c "$CTR images rm '$image' >/dev/null 2>&1 || true"
    gzip -dc "$tarfile" | kubectl exec -i -n "$DS_NS" "$pod" -- \
      bash -c "cat > /tmp/img.tar && $CTR images import /tmp/img.tar >/dev/null && rm /tmp/img.tar" \
      || { echo "     IMPORT FAILED on $pod: $image"; return 1; }
    verified=$(kubectl exec -n "$DS_NS" "$pod" -- bash -c "$CTR images ls -q | grep -Fx '$image' | head -1" || true)
    echo "     $pod verified: ${verified:-MISSING}"
  done
}
pids=()
for pod in $PODS; do import_to_pod "$pod" & pids+=($!); done
rc=0; for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
for image in "${IMAGES[@]}"; do rm -f "${TARS[$image]}"; done
[ "$rc" = 0 ] || { echo "one or more imports failed" >&2; exit 1; }

log "Done. Deploy with: IMAGE_PULL_POLICY=IfNotPresent SKIP_BUILD=1 IMG_REGISTRY=ghcr.io/security-eval ./deploy.sh ..."
