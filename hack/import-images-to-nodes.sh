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
#   hack/import-images-to-nodes.sh [image ...]
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

PODS=$(kubectl get pods -n "$DS_NS" -l app=image-importer -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')
echo "importer pods: $PODS"

for image in "${IMAGES[@]}"; do
  log "Importing $image"
  tarfile="$(mktemp /tmp/import.XXXXXX.tar.gz)"
  docker save "$image" | gzip -1 > "$tarfile"
  size=$(du -h "$tarfile" | cut -f1)
  for pod in $PODS; do
    echo "  -> $pod ($size)"
    gzip -dc "$tarfile" | kubectl exec -i -n "$DS_NS" "$pod" -- \
      bash -c "cat > /tmp/img.tar && $CTR_BIN -a $CTR_SOCKET -n k8s.io images import /tmp/img.tar >/dev/null && rm /tmp/img.tar" \
      || { echo "     IMPORT FAILED on $pod"; exit 1; }
    verified=$(kubectl exec -n "$DS_NS" "$pod" -- \
      bash -c "$CTR_BIN -a $CTR_SOCKET -n k8s.io images ls -q | grep -F '$image' | head -1" || true)
    echo "     verified: ${verified:-MISSING}"
  done
  rm -f "$tarfile"
done

log "Done. Deploy with: IMAGE_PULL_POLICY=IfNotPresent SKIP_BUILD=1 IMG_REGISTRY=ghcr.io/security-eval ./deploy.sh ..."
