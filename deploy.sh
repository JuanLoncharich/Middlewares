#!/usr/bin/env bash
# One-shot build + deploy for the MCP evaluation platform.
#
#   IMG_REGISTRY=ghcr.io/<you> OPENCODE_API_KEY=<zen-key> ./deploy.sh
#
# Steps: build & push the four images, install CRDs + operator (mcp-eval-system),
# apply the evaluation namespace / NetworkPolicies / agent personas / sample
# server (mcp-evals), create the LLM secret, and trigger the first run.
#
# Env:
#   IMG_REGISTRY       registry prefix for the images (required)
#   IMG_TAG            image tag (default: 20260930 — frozen; never ship :latest)
#   OPENCODE_API_KEY   written into Secret mcp-evals/llm-provider-credentials (required unless SKIP_SECRET=1)
#   ANTHROPIC_API_KEY  optionally added to the same Secret when using provider `anthropic`
#   SKIP_BUILD=1       skip docker build/push
#   SKIP_SECRET=1      do not (re)create the LLM secret
#   TRIGGER=0          do not trigger a run at the end
#   ---- security layers (Vigil / Occludra / NetBird) ----
#   DEPLOY_SECURITY_GATEWAYS=0   skip the security-gateways namespace (default: deploy it)
#   MESH_ENFORCE=false           legacy mode: strip the NetBird sidecars and let the evaluator
#                                reach the gateways via in-cluster ClusterIP services
#                                (default: true — every run's egress is mesh-only)
#   IMAGE_PULL_POLICY            when set, forces this pull policy on the operator, gateways and
#                                run images — e.g. IfNotPresent for air-gap deploys whose images
#                                were imported straight into the nodes (hack/import-images-to-nodes.sh)
#   VIGIL_SRC_REPO               vigil-llm upstream repo built by this script (default
#                                https://github.com/deadbits/vigil-llm)
#   VIGIL_SRC_REF                vigil-llm commit pinned for the build (default
#                                f2b4c134d060bae81d29fad07003f3c657e63fc8)
#   VIGIL_IMG                    Vigil scanner image (default $IMG_REGISTRY/vigil-llm:$IMG_TAG,
#                                built here from VIGIL_SRC_REPO@VIGIL_SRC_REF — upstream
#                                publishes no image, only a Dockerfile). Override for a
#                                prebuilt/mirrored image; SKIP_BUILD=1 + VIGIL_IMG is the
#                                air-gap path. Upstream semantics: classifier/embedding
#                                models download from HuggingFace at boot; the
#                                vigil-server-conf ConfigMap is mounted at
#                                /app/conf/server.conf (the baked entrypoint runs
#                                `python vigil-server.py -c conf/server.conf` with
#                                WORKDIR /app); REST API on port 5000, POST
#                                /analyze/prompt.
#   NETBIRD_MANAGEMENT_URL       your NetBird management server (default placeholder is substituted)
#   NETBIRD_SETUP_KEY            setup key written into Secret netbird-auth (both namespaces)
#   ---- workstation exposure (opt-in) ----
#   WORKSTATION_NODEPORT=1       publish Occludra (30080) and Vigil (30500) as NodePorts plus an
#                                ingress NetworkPolicy, so docker containers on the programmer's
#                                workstation reach the gateways (TESTING.md §3-4). Default: off —
#                                the security perimeter stays ClusterIP/mesh-only.
#   WORKSTATION_CIDR             source CIDR allowed to those NodePorts (default: 172.21.0.0/16,
#                                the `kind` docker bridge — adjust to your docker network)
#   ---- scaling ----
#   AUTOSCALE_METRICS=1          install metrics-server (required by the gateways' HPAs; kind needs this)
#   DEPLOY_AUTOSCALER=openstack  deploy Cluster Autoscaler (ephemeral Nova VMs). Requires OS_* env vars:
#                                OS_AUTH_URL OS_USERNAME OS_PASSWORD OS_PROJECT_NAME OS_USER_DOMAIN_NAME
#                                OS_REGION_NAME AUTOSCALER_NODE_GROUP (+ optional AUTOSCALER_MIN/AUTOSCALER_MAX)
#   ---- SPOF elimination ----
#   IN_CLUSTER_REGISTRY=1        deploy the in-cluster registry (manifests/registry.yaml)
#   DEPLOY_NETBIRD_CP=1          self-host the NetBird control plane in-cluster (requires an OIDC IdP;
#                                see manifests/netbird-controlplane.yaml). Also generates the CP secrets.
#   ---- vector DB (distributed Chroma over MinIO) ----
#   DEPLOY_VECTOR_DB=1           deploy the distributed Chroma cluster (namespace `chroma`):
#                                SysDB coordinator + Rust SysDB + Log Service (WAL) + Query Nodes
#                                + Compactors + Work Queue + Garbage Collector, with MinIO object
#                                storage and a Postgres-backed catalog. Vigil's vector scanner
#                                queries its frontend for prompt-injection similarity.
#   CHROMA_IMG_TAG               chroma component image tag (short commit SHA from the `chromadb`
#                                Docker Hub org; keep in vintage with the vendored chart).
#   SKIP_CORPUS_LOAD=1           do not load the Vigil embedding corpora after the stack is up.
set -euo pipefail
cd "$(dirname "$0")"

: "${IMG_REGISTRY:?set IMG_REGISTRY, e.g. ghcr.io/myorg}"
# Frozen default — never ship :latest.
IMG_TAG="${IMG_TAG:-20260930}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_SECRET="${SKIP_SECRET:-0}"
TRIGGER="${TRIGGER:-1}"
DEPLOY_SECURITY_GATEWAYS="${DEPLOY_SECURITY_GATEWAYS:-1}"
MESH_ENFORCE="${MESH_ENFORCE:-true}"
AUTOSCALE_METRICS="${AUTOSCALE_METRICS:-0}"
DEPLOY_AUTOSCALER="${DEPLOY_AUTOSCALER:-0}"
IN_CLUSTER_REGISTRY="${IN_CLUSTER_REGISTRY:-0}"
DEPLOY_NETBIRD_CP="${DEPLOY_NETBIRD_CP:-0}"
DEPLOY_VECTOR_DB="${DEPLOY_VECTOR_DB:-1}"
CHROMA_IMG_TAG="${CHROMA_IMG_TAG:-dff1d8a}"
SKIP_CORPUS_LOAD="${SKIP_CORPUS_LOAD:-0}"
LOADER_IMG="$IMG_REGISTRY/vigil-corpus-loader:$IMG_TAG"
WORKSTATION_NODEPORT="${WORKSTATION_NODEPORT:-0}"
WORKSTATION_CIDR="${WORKSTATION_CIDR:-172.21.0.0/16}"
# Vigil sizing: defaults fit multi-node production. The real vigil-llm image
# loads its classifier models at boot and is memory-hungry per replica — on
# laptop-class single nodes set VIGIL_REPLICAS=1 VIGIL_HPA_MIN=1
# VIGIL_MAX_UNAVAILABLE=1 or a surge replica can OOM the node during
# rollouts.
VIGIL_REPLICAS="${VIGIL_REPLICAS:-2}"
VIGIL_HPA_MIN="${VIGIL_HPA_MIN:-2}"
VIGIL_MAX_UNAVAILABLE="${VIGIL_MAX_UNAVAILABLE:-0}"
NETBIRD_MANAGEMENT_URL="${NETBIRD_MANAGEMENT_URL:-https://netbird.example.com:443}"
OCCLUDRA_IMG="${OCCLUDRA_IMG:-$IMG_REGISTRY/occludra-gateway:$IMG_TAG}"
VIGIL_SRC_REPO="${VIGIL_SRC_REPO:-https://github.com/deadbits/vigil-llm}"
VIGIL_SRC_REF="${VIGIL_SRC_REF:-f2b4c134d060bae81d29fad07003f3c657e63fc8}"
VIGIL_IMG="${VIGIL_IMG:-$IMG_REGISTRY/vigil-llm:$IMG_TAG}"

IMG="$IMG_REGISTRY/mcp-eval-operator:$IMG_TAG"
CLONER_IMG="$IMG_REGISTRY/mcp-cloner:$IMG_TAG"
TARGET_IMG="$IMG_REGISTRY/mcp-target-sandbox:$IMG_TAG"
EVALUATOR_IMG="$IMG_REGISTRY/mcp-evaluator:$IMG_TAG"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

if [ "$SKIP_BUILD" != "1" ]; then
  log "Building images"
  docker build -t "$IMG" .
  docker build -t "$CLONER_IMG" images/cloner
  docker build -t "$TARGET_IMG" images/target
  docker build -t "$EVALUATOR_IMG" runner
  log "Pushing images"
  docker push "$IMG"; docker push "$CLONER_IMG"; docker push "$TARGET_IMG"; docker push "$EVALUATOR_IMG"
  if [ "$DEPLOY_SECURITY_GATEWAYS" = "1" ]; then
    log "Building Occludra gateway image"
    docker build -t "$OCCLUDRA_IMG" images/occludra-gateway
    docker push "$OCCLUDRA_IMG"
    # Vigil: upstream (deadbits/vigil-llm) publishes no image — only a
    # Dockerfile — so build it from the pinned source commit
    # (VIGIL_SRC_REPO@VIGIL_SRC_REF). VIGIL_IMG overrides the destination tag;
    # with SKIP_BUILD=1 it points at a prebuilt/mirrored image (air-gap path).
    log "Building Vigil gateway image from pinned upstream source"
    VIGIL_SRC_DIR="$(mktemp -d)"
    git init -q "$VIGIL_SRC_DIR"
    git -C "$VIGIL_SRC_DIR" remote add origin "$VIGIL_SRC_REPO"
    git -C "$VIGIL_SRC_DIR" fetch --depth 1 origin "$VIGIL_SRC_REF"
    git -C "$VIGIL_SRC_DIR" checkout --quiet FETCH_HEAD
    docker build -t "$VIGIL_IMG" "$VIGIL_SRC_DIR"
    rm -rf "$VIGIL_SRC_DIR"
    docker push "$VIGIL_IMG"
  fi
  if [ "$DEPLOY_VECTOR_DB" = "1" ]; then
    log "Building Vigil corpus loader image"
    docker build -t "$LOADER_IMG" images/vigil-corpus-loader
    docker push "$LOADER_IMG"
  fi
fi

log "Installing CRDs, RBAC and operator (namespace mcp-eval-system)"
# The PriorityClass is referenced by the operator pod spec — it must exist
# before the Deployment is applied (fresh-cluster ordering bug).
kubectl apply -f manifests/priorityclass.yaml
kubectl kustomize config/default \
  | sed -e "s|ghcr.io/security-eval/mcp-eval-operator:20260930|$IMG|g" \
        -e "s|ghcr.io/security-eval/mcp-cloner:20260930|$CLONER_IMG|g" \
        -e "s|ghcr.io/security-eval/mcp-target-sandbox:20260930|$TARGET_IMG|g" \
        -e "s|ghcr.io/security-eval/mcp-evaluator:20260930|$EVALUATOR_IMG|g" \
        -e "s|https://netbird.example.com:443|$NETBIRD_MANAGEMENT_URL|g" \
  | kubectl apply -f -
kubectl -n mcp-eval-system set env deploy/mcp-eval-controller-manager MESH_ENFORCE="$MESH_ENFORCE" >/dev/null
# Air-gap deploys (images imported straight into the nodes' containerd store,
# hack/import-images-to-nodes.sh) must set IMAGE_PULL_POLICY=IfNotPresent:
# with Always the kubelet still dials the registry and ImagePullBackOffs.
if [ -n "${IMAGE_PULL_POLICY:-}" ]; then
  kubectl -n mcp-eval-system set env deploy/mcp-eval-controller-manager IMAGE_PULL_POLICY="$IMAGE_PULL_POLICY" >/dev/null
  kubectl -n mcp-eval-system patch deploy/mcp-eval-controller-manager --type=json \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"'"$IMAGE_PULL_POLICY"'"}]'
fi
kubectl -n mcp-eval-system rollout status deploy/mcp-eval-controller-manager --timeout=180s

log "Applying evaluation namespace, NetworkPolicies, agent personas and sample MCPServer (namespace mcp-evals)"
# The evaluate-phase egress policy is generated per-run by the operator with
# the API-server endpoint IPs resolved at reconcile time — config/samples
# needs no CIDR/endpoint substitution here.
kubectl kustomize config/samples | kubectl apply -f -
kubectl apply -f config/rbac/runner_role.yaml

if [ "$SKIP_SECRET" != "1" ]; then
  : "${OPENCODE_API_KEY:?set OPENCODE_API_KEY (OpenCode Zen key) or SKIP_SECRET=1}"
  log "Creating LLM credentials secret"
  if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    kubectl -n mcp-evals create secret generic llm-provider-credentials \
      --from-literal=OPENCODE_API_KEY="$OPENCODE_API_KEY" \
      --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
      --dry-run=client -o yaml | kubectl apply -f -
  else
    kubectl -n mcp-evals create secret generic llm-provider-credentials \
      --from-literal=OPENCODE_API_KEY="$OPENCODE_API_KEY" \
      --dry-run=client -o yaml | kubectl apply -f -
  fi
fi

# Rewrite the gateway image references for this deployment (stdin → stdout).
# With IMAGE_PULL_POLICY set (air-gap), gateways must not pull either.
substitute_gateway_images() {
  sed -e "s|ghcr.io/security-eval/occludra-gateway:20260930|$OCCLUDRA_IMG|g" \
      -e "s|image: ghcr.io/security-eval/vigil-llm:20260930|image: $VIGIL_IMG|g" \
      -e "s|__VIGIL_REPLICAS__|$VIGIL_REPLICAS|g" \
      -e "s|__VIGIL_HPA_MIN__|$VIGIL_HPA_MIN|g" \
      -e "s|__VIGIL_MAX_UNAVAILABLE__|$VIGIL_MAX_UNAVAILABLE|g" \
      ${IMAGE_PULL_POLICY:+-e "s|imagePullPolicy: Always|imagePullPolicy: $IMAGE_PULL_POLICY|g"}
}
apply_gateway_manifest() {
  substitute_gateway_images < "$1" | kubectl apply -f -
}

# Vigil deploys the vigil-llm image (VIGIL_IMG): built here from the pinned
# upstream source by default, or a mirrored image via VIGIL_IMG override. The
# vigil-server-conf ConfigMap ships the config the pinned upstream expects, so
# the manifest needs no stub-vs-real filtering.

# With MESH_ENFORCE=false the gateways are ordinary in-cluster services:
#  - netbird sidecars are stripped (no management server → crashloop →
#    endpoint flapping), along with their volumes;
#  - the mesh-mode ingress isolation is relaxed so pods in mcp-evals can
#    reach the service ports (in mesh mode that path is intentionally
#    closed — enforcement stays on the evaluator-side per-run policy).
# Operates on stdin → stdout.
filter_mesh_sidecars() {
  python3 -c "
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
for doc in docs:
    if doc.get('kind') == 'Deployment':
        pod = doc['spec']['template']['spec']
        pod['containers'] = [c for c in pod.get('containers', []) if c.get('name') != 'netbird']
        kept = {m.get('name') for c in pod['containers'] for m in c.get('volumeMounts', [])}
        pod['volumes'] = [v for v in pod.get('volumes', []) if v.get('name') in kept]
    if doc.get('kind') == 'NetworkPolicy' and doc.get('metadata', {}).get('name') == 'allow-service-ports-in-namespace':
        doc['spec']['ingress'][0]['from'].append(
            {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'mcp-evals'}}})
    print(yaml.safe_dump(doc, sort_keys=False), end='')
    print('---')
"
}

# ---------------------------------------------------------------------------
# Vector DB: distributed Chroma (SysDB coordinator + Rust SysDB + Log Service
# WAL + Compactors + Query Nodes + Work Queue + GC) over MinIO object storage.
# Vigil's vector scanner queries the frontend; topology docs in ARCHITECTURE.md,
# manifests in manifests/chroma/.
# ---------------------------------------------------------------------------
if [ "$DEPLOY_VECTOR_DB" = "1" ]; then
  log "Deploying vector-DB substrate (MinIO, Postgres, OTel) into namespace chroma"
  # The substrate manifests and the chart both target namespace `chroma`;
  # create it up front so apply order never matters. The PriorityClass is
  # referenced by MinIO/Postgres (and the gateways further down).
  kubectl create namespace chroma --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f manifests/priorityclass.yaml
  kubectl apply -f manifests/chroma/minio.yaml \
                 -f manifests/chroma/postgres.yaml \
                 -f manifests/chroma/otel-collector.yaml \
                 -f manifests/chroma/networkpolicy.yaml
  for dep in minio postgres otel-collector; do
    kubectl -n chroma rollout status "deploy/$dep" --timeout=300s
  done

  log "Rendering + applying distributed Chroma (component images chromadb/*:$CHROMA_IMG_TAG)"
  # CRDs first: the MemberList custom resources in the chart cannot be
  # applied until the chroma.cluster CRD is established.
  kubectl apply -f manifests/chroma/chart/crds/
  helm template distributed-chroma manifests/chroma/chart \
    -f manifests/chroma/values-mcp-eval.yaml \
    --set-file rustFrontendService.configuration=manifests/chroma/frontend-config.yaml \
    --set-file rustLogService.configuration=manifests/chroma/worker-config.yaml \
    --set-file queryService.configuration=manifests/chroma/worker-config.yaml \
    --set-file compactionService.configuration=manifests/chroma/worker-config.yaml \
    --set-file garbageCollector.configuration=manifests/chroma/worker-config.yaml \
    --set-file rustSysdbService.configuration=manifests/chroma/worker-config.yaml \
    --set-file workQueueService.configuration=manifests/chroma/worker-config.yaml \
    --set-file fnConsumer.configuration=manifests/chroma/worker-config.yaml \
    | sed "s|__CHROMA_IMG_TAG__|$CHROMA_IMG_TAG|g" \
    | kubectl apply -f -
  for dep in sysdb rust-sysdb-service rust-frontend-service work-queue-service fn-consumer; do
    kubectl -n chroma rollout status "deploy/$dep" --timeout=600s
  done
  for sts in rust-log-service query-service compaction-service garbage-collector; do
    kubectl -n chroma rollout status "statefulset/$sts" --timeout=600s
  done

  if [ "$SKIP_CORPUS_LOAD" != "1" ]; then
    log "Loading Vigil embedding corpora into Chroma (Job vigil-corpus-loader)"
    sed "s|__LOADER_IMG__|$LOADER_IMG|g" manifests/chroma/corpus-loader-job.yaml \
      | kubectl apply -f -
    # First (cold) run downloads the datasets from HuggingFace.
    kubectl -n chroma wait --for=condition=complete job/vigil-corpus-loader --timeout=900s \
      || { echo "ERROR: corpus loader did not complete — logs: kubectl -n chroma logs job/vigil-corpus-loader" >&2; exit 1; }
  fi
  echo "Vector DB up: http://rust-frontend-service.chroma.svc.cluster.local:8000 (namespace chroma)"
fi

if [ "$DEPLOY_SECURITY_GATEWAYS" = "1" ]; then
  log "Deploying security gateways (Occludra, Vigil, NetBird) into security-gateways (mesh=$MESH_ENFORCE)"
  # PriorityClass shared by the operator and both gateways (node-pressure
  # evictions must not take out the control plane or the security perimeter).
  kubectl apply -f manifests/priorityclass.yaml
  if [ "$MESH_ENFORCE" = "true" ]; then
    apply_gateway_manifest manifests/occludra-deployment.yaml
    apply_gateway_manifest manifests/netbird-daemonset.yaml
    apply_gateway_manifest manifests/vigil-deployment.yaml
  else
    substitute_gateway_images < manifests/occludra-deployment.yaml | filter_mesh_sidecars | kubectl apply -f -
    substitute_gateway_images < manifests/vigil-deployment.yaml | filter_mesh_sidecars | kubectl apply -f -
  fi
  if [ "$MESH_ENFORCE" != "true" ]; then
    echo "NOTE: MESH_ENFORCE=false — NetBird enrollment secrets skipped." >&2
  elif [ -n "${NETBIRD_SETUP_KEY:-}" ]; then
    log "Creating NetBird enrollment secrets (setup key)"
    for ns in security-gateways mcp-evals; do
      kubectl -n "$ns" create secret generic netbird-auth \
        --from-literal=setup-key="$NETBIRD_SETUP_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
    done
  else
    # In mesh mode EVERY run's egress is NetBird-only: without a setup key no
    # sidecar can enroll and every evaluation dies on its first Vigil scan.
    # Fail loudly here instead of deploying a platform that cannot evaluate.
    echo "ERROR: MESH_ENFORCE=true but NETBIRD_SETUP_KEY is unset — evaluation pods will fail to enroll in the mesh." >&2
    echo "       Set NETBIRD_SETUP_KEY=<key>, or pass MESH_ENFORCE=false for the legacy direct-to-provider mode." >&2
    exit 1
  fi
  if [ "$SKIP_SECRET" != "1" ]; then
    log "Mirroring LLM credentials into security-gateways (Occludra is the upstream egress point)"
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
      kubectl -n security-gateways create secret generic llm-provider-credentials \
        --from-literal=OPENCODE_API_KEY="$OPENCODE_API_KEY" \
        --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
    else
      kubectl -n security-gateways create secret generic llm-provider-credentials \
        --from-literal=OPENCODE_API_KEY="$OPENCODE_API_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
    fi
  else
    echo "WARNING: SKIP_SECRET=1 — security-gateways/llm-provider-credentials not (re)created." >&2
  fi
fi

# ---------------------------------------------------------------------------
# Workstation exposure (opt-in): NodePort Services for Occludra/Vigil plus an
# ingress NetworkPolicy for the host docker bridge, so containers on the
# programmer's workstation reach the gateways directly (TESTING.md §3-4).
# Off by default — the security perimeter stays ClusterIP/mesh-only.
# ---------------------------------------------------------------------------
if [ "$WORKSTATION_NODEPORT" = "1" ]; then
  if [ "$DEPLOY_SECURITY_GATEWAYS" != "1" ]; then
    echo "WARNING: WORKSTATION_NODEPORT=1 but DEPLOY_SECURITY_GATEWAYS=0 — no gateways to expose, skipping." >&2
  else
    log "Exposing gateway NodePorts to workstation subnet $WORKSTATION_CIDR"
    sed "s|__WORKSTATION_CIDR__|$WORKSTATION_CIDR|g" manifests/workstation-nodeport.yaml | kubectl apply -f -
  fi
fi

# ---------------------------------------------------------------------------
# SPOF elimination: in-cluster registry and self-hosted NetBird control plane.
# ---------------------------------------------------------------------------
if [ "$IN_CLUSTER_REGISTRY" = "1" ]; then
  log "Deploying in-cluster registry (namespace registry)"
  kubectl apply -f manifests/registry.yaml
  kubectl -n registry rollout status deploy/registry --timeout=180s || true
  echo "Registry: http://registry.registry.svc.cluster.local:5000 — configure containerd on each worker"
  echo "  [host.\"http://registry.registry.svc.cluster.local:5000\"]"
  echo "    capability = [\"pull\", \"resolve\"]"
  echo "    skip_verify = true"
  echo "then push images with: IMG_REGISTRY=registry.registry.svc.cluster.local:5000 ./deploy.sh (from inside the cluster)"
fi

if [ "$DEPLOY_NETBIRD_CP" = "1" ]; then
  log "Deploying NetBird control plane (self-hosted, in-cluster)"
  if kubectl -n security-gateways get secret netbird-cp-secrets >/dev/null 2>&1; then
    echo "netbird-cp-secrets exists; keeping existing secrets"
  else
    kubectl -n security-gateways create secret generic netbird-cp-secrets \
      --from-literal=datastore-encryption-key="$(head -c 32 /dev/urandom | base64 | tr -d '\n')" \
      --from-literal=relay-secret="$(head -c 24 /dev/urandom | base64 | tr -d '\n')" \
      --dry-run=client -o yaml | kubectl apply -f -
  fi
  # Render the generated relay secret into the management config so the two
  # always match, regardless of who created the Secret.
  RELAY_SECRET="$(kubectl -n security-gateways get secret netbird-cp-secrets -o jsonpath='{.data.relay-secret}' | base64 -d)"
  ENCKEY="$(kubectl -n security-gateways get secret netbird-cp-secrets -o jsonpath='{.data.datastore-encryption-key}' | base64 -d)"
  OIDC_ENDPOINT="${NETBIRD_OIDC_CONFIG_ENDPOINT:?set NETBIRD_OIDC_CONFIG_ENDPOINT to the IdP well-known openid-configuration URL}"
  sed -e "s|CHANGE_ME_relay_shared_secret_xxx|${RELAY_SECRET}|g" \
      -e "s|CHANGE_ME_32_BYTES_BASE64xxxxxxxxxxxxx|${ENCKEY}|g" \
      -e "s|https://your-idp.example.com/.well-known/openid-configuration|${OIDC_ENDPOINT}|g" \
      manifests/netbird-controlplane.yaml | kubectl apply -f -
  echo "NetBird CP deployed. Next: create the evaluation setup key (dashboard/CLI),"
  echo "then run the platform deploy with NETBIRD_MANAGEMENT_URL=http://netbird-management.security-gateways.svc.cluster.local"
fi

if [ "$TRIGGER" = "1" ]; then
  log "Triggering first evaluation of filesystem-mcp"
  kubectl -n mcp-evals annotate mcpserver filesystem-mcp security.eval.io/trigger-now=true --overwrite
fi

# ---------------------------------------------------------------------------
# Scaling: metrics-server (HPA backend) and, on OpenStack, the Cluster
# Autoscaler that adds/removes ephemeral Nova VMs as run and gateway load
# demands.
# ---------------------------------------------------------------------------
if [ "$AUTOSCALE_METRICS" = "1" ] && ! kubectl get deploy metrics-server -n kube-system >/dev/null 2>&1; then
  log "Installing metrics-server (HPA metrics backend)"
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
  # kind/k0s nodes serve kubelet metrics with self-signed certs.
  kubectl -n kube-system patch deploy metrics-server --type=json \
    -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
  kubectl -n kube-system rollout status deploy/metrics-server --timeout=180s
fi

if [ "$DEPLOY_AUTOSCALER" = "openstack" ]; then
  log "Deploying Cluster Autoscaler (OpenStack provider, ephemeral VM workers)"
  : "${OS_AUTH_URL:?set OS_AUTH_URL, e.g. https://keystone.example.com:5000/v3}"
  : "${OS_USERNAME:?set OS_USERNAME}"
  : "${OS_PASSWORD:?set OS_PASSWORD}"
  : "${OS_PROJECT_NAME:?set OS_PROJECT_NAME}"
  : "${OS_USER_DOMAIN_NAME:=Default}"
  : "${OS_REGION_NAME:?set OS_REGION_NAME}"
  : "${AUTOSCALER_NODE_GROUP:?set AUTOSCALER_NODE_GROUP to the scalable worker node-group name}"
  AUTOSCALER_MIN="${AUTOSCALER_MIN:-1}"
  AUTOSCALER_MAX="${AUTOSCALER_MAX:-10}"
  kubectl -n kube-system create secret generic openstack-cloud-config \
    --from-literal=cloud.conf="[Global]
auth-url = $OS_AUTH_URL
username = $OS_USERNAME
password = $OS_PASSWORD
project-name = $OS_PROJECT_NAME
user-domain-name = $OS_USER_DOMAIN_NAME
region = $OS_REGION_NAME" \
    --dry-run=client -o yaml | kubectl apply -f -
  sed -e "s|__AUTOSCALER_MIN__|$AUTOSCALER_MIN|g" \
      -e "s|__AUTOSCALER_MAX__|$AUTOSCALER_MAX|g" \
      -e "s|__AUTOSCALER_NODE_GROUP__|$AUTOSCALER_NODE_GROUP|g" \
      manifests/cluster-autoscaler-openstack.yaml | kubectl apply -f -
  echo "Autoscaler: workers scale $AUTOSCALER_MIN..$AUTOSCALER_MAX in node group '$AUTOSCALER_NODE_GROUP'; idle VMs are deleted after 5m."
fi

log "Done. Watch progress with:"
echo "  kubectl -n mcp-evals get mcprun -w"
echo "  kubectl -n mcp-evals get mcprun -o jsonpath='{.items[-1].status}' | jq ."
echo "  kubectl -n mcp-eval-system logs deploy/mcp-eval-controller-manager -f"
