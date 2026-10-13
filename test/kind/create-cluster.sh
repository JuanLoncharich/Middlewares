#!/usr/bin/env bash
# Create a throwaway kind cluster wired to a local image registry on
# localhost:5001 (the layout run-local-e2e.sh and TESTING.md assume).
#
#   test/kind/create-cluster.sh            # cluster "mcp-e2e"
#   KIND_CLUSTER=foo test/kind/create-cluster.sh
#
# kind writes the new context into $KUBECONFIG (default ~/.kube/config) and
# makes it current. To keep your everyday kubeconfig untouched:
#   KUBECONFIG=/tmp/kind-mcp-e2e.kubeconfig test/kind/create-cluster.sh
#
# Idempotent: reuses the registry container and an existing cluster.
# Follows kind's "local registry" recipe (kind.sigs.k8s.io/docs/user/local-registry).
set -euo pipefail
CLUSTER="${KIND_CLUSTER:-mcp-e2e}"
REG_NAME="${REG_NAME:-kind-registry}"
REG_PORT="${REG_PORT:-5001}"
REG_IMAGE="${REG_IMAGE:-registry:2.8.3}"

if [ "$(docker inspect -f '{{.State.Running}}' "$REG_NAME" 2>/dev/null || true)" != true ]; then
  docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
  docker run -d --restart=unless-stopped -p "127.0.0.1:${REG_PORT}:5000" \
    --network bridge --name "$REG_NAME" "$REG_IMAGE" >/dev/null
fi

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  cat <<KIND | kind create cluster --name "$CLUSTER" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
KIND
fi

# Tell each node's containerd that localhost:5001 is the registry container.
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/localhost:${REG_PORT}"
  printf '[host."http://%s:5000"]\n' "$REG_NAME" | \
    docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/localhost:${REG_PORT}/hosts.toml"
done

if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "$REG_NAME")" = null ]; then
  docker network connect kind "$REG_NAME"
fi

# Documented discovery hint for tooling (KEP-1755).
kubectl --context "kind-$CLUSTER" apply -f - >/dev/null <<CM
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REG_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
CM
echo "kind cluster '$CLUSTER' ready (context kind-$CLUSTER), registry localhost:${REG_PORT}"
