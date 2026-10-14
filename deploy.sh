#!/usr/bin/env bash
# One-shot build + deploy for the MCP evaluation platform.
#
#   IMG_REGISTRY=ghcr.io/<you> OPENCODE_API_KEY=<zen-key> ./deploy.sh
#   IMG_REGISTRY=ghcr.io/<you> LLM_PROVIDER=nvidia NVIDIA_API_KEY=<nvapi-key> ./deploy.sh
#   IMG_REGISTRY=ghcr.io/<you> LLM_PROVIDER=local LOCAL_LLM_URL=http://172.18.0.1:8080/v1 LLM_MODEL=<id> ./deploy.sh
#
# Steps: build & push the four images, install CRDs + operator (mcp-eval-system),
# apply the evaluation namespace / NetworkPolicies / agent personas / sample
# server (mcp-evals), create the LLM secret, and trigger the first run.
#
# Env:
#   IMG_REGISTRY       registry prefix for the images (required)
#   IMG_TAG            image tag (default: 20260930 — frozen; never ship :latest)
#   LLM_PROVIDER       upstream LLM provider behind Occludra: zen (default, OpenCode Zen), nvidia
#                      (NVIDIA NIM) or local (an OpenAI-compatible server such as llama-server,
#                      reached by IP). Sets Occludra's upstream URL and the four agent personas' model.
#   LLM_MODEL          model id for the personas (default: zen -> muse-spark-1.3-contributor-free,
#                      nvidia -> z-ai/glm-5.3; required for local, and added verbatim to
#                      Occludra's model allowlist)
#   LOCAL_LLM_URL      local: base URL of the server as http(s)://<IPv4>:<port>/v1, e.g.
#                      http://172.18.0.1:8080/v1 (kind: the `kind` docker network gateway).
#                      Opens an egress rule Occludra -> exactly that IP/32 and port
#                      (occludra-egress-local-llm); any other provider deletes the rule.
#   LOCAL_LLM_API_KEY  local: optional, the server's --api-key; written ONLY into
#                      security-gateways/llm-provider-credentials (UPSTREAM_API_KEY)
#   OPENCODE_API_KEY   zen: written into Secret llm-provider-credentials in mcp-evals and
#                      security-gateways (required unless SKIP_SECRET=1)
#   ANTHROPIC_API_KEY  zen: optionally added to the same Secrets when using provider `anthropic`
#   NVIDIA_API_KEY     nvidia: written ONLY into security-gateways/llm-provider-credentials
#                      (key UPSTREAM_API_KEY); the evaluation namespace gets a placeholder
#                      (required unless SKIP_SECRET=1)
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
#   ---- GPU node: scale-to-zero GPU Vigil (hack/gpu-node) ----
#   DEPLOY_KEDA=1                install KEDA (chart kedacore/keda@KEDA_CHART_VERSION, namespace keda,
#                                values manifests/keda/values-mcp-eval.yaml)
#   VIGIL_GPU=1                  deploy the GPU Vigil (hack/gpu-node/manifests/vigil-gpu.yaml) pinned to the
#                                on-demand GPU node, scaled 0<->1 by KEDA from the operator's /active-runs,
#                                and point the evaluator at it (VIGIL_GPU_URL, CPU Vigil stays the fallback).
#                                Requires KEDA. Build the image with hack/gpu-node/build-vigil-gpu.sh.
#   VIGIL_GPU_IMG                GPU Vigil image (default $IMG_REGISTRY/vigil-llm-gpu:$IMG_TAG)
#   VIGIL_GPU_MEM_LIMIT          GPU Vigil host-RAM limit (default 4Gi; measured ~3.4 GiB; must fit gpu-node's MEM_LIMIT_GIB)
#   VIGIL_PROFILE=lite           in-cluster CPU Vigil runs only the YARA scanner (much less RAM); meant as
#                                the fallback when the full scanner lives on the GPU node. Default: full.
#   ---- SPOF elimination ----
#   IN_CLUSTER_REGISTRY=1        deploy the in-cluster registry (manifests/registry.yaml)
#   DEPLOY_NETBIRD_CP=1          self-host the NetBird control plane in-cluster (requires an OIDC IdP;
#                                see manifests/netbird-controlplane.yaml). Also generates the CP secrets.
#   DEPLOY_OBSERVABILITY=1      install Grafana/Alloy/Tempo/Prometheus/Loki and enable first-party telemetry
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
DEPLOY_KEDA="${DEPLOY_KEDA:-0}"
KEDA_CHART_VERSION="${KEDA_CHART_VERSION:-2.21.0}"
VIGIL_GPU="${VIGIL_GPU:-0}"
VIGIL_GPU_IMG="${VIGIL_GPU_IMG:-$IMG_REGISTRY/vigil-llm-gpu:$IMG_TAG}"
VIGIL_GPU_MEM_LIMIT="${VIGIL_GPU_MEM_LIMIT:-4Gi}"
VIGIL_PROFILE="${VIGIL_PROFILE:-full}"
case "$VIGIL_PROFILE" in full|lite) ;; *) echo "VIGIL_PROFILE must be full or lite" >&2; exit 1 ;; esac
# LLM provider: the personas in config/samples and Occludra's manifest are
# written for OpenCode Zen; other providers are rendered in at apply time.
LLM_PROVIDER="${LLM_PROVIDER:-zen}"
case "$LLM_PROVIDER" in
  zen)
    LLM_PROVIDER_ID=opencode
    LLM_MODEL="${LLM_MODEL:-muse-spark-1.3-contributor-free}"
    LLM_UPSTREAM_BASE_URL="" ;;   # empty: Occludra's built-in Zen default
  nvidia)
    LLM_PROVIDER_ID=nvidia
    LLM_MODEL="${LLM_MODEL:-z-ai/glm-5.3}"
    LLM_UPSTREAM_BASE_URL="https://integrate.api.nvidia.com/v1" ;;
  local)
    LLM_PROVIDER_ID=local
    : "${LLM_MODEL:?set LLM_MODEL (the model id the local server answers to)}"
    : "${LOCAL_LLM_URL:?set LOCAL_LLM_URL, e.g. http://172.18.0.1:8080/v1}"
    LLM_UPSTREAM_BASE_URL="$LOCAL_LLM_URL"
    # NetworkPolicy ipBlocks take addresses, not names: require an IPv4
    # literal so the egress rule opens exactly one host and port.
    if [[ "$LOCAL_LLM_URL" =~ ^(https?)://([0-9]{1,3}(\.[0-9]{1,3}){3})(:([0-9]{1,5}))?(/.*)?$ ]]; then
      LOCAL_LLM_IP="${BASH_REMATCH[2]}"
      LOCAL_LLM_PORT="${BASH_REMATCH[5]}"
      if [ -z "$LOCAL_LLM_PORT" ]; then
        if [ "${BASH_REMATCH[1]}" = https ]; then LOCAL_LLM_PORT=443; else LOCAL_LLM_PORT=80; fi
      fi
    else
      echo "LOCAL_LLM_URL must be http(s)://<IPv4>[:port][/path], got '$LOCAL_LLM_URL':" >&2
      echo "  the egress rule needs an IP address, not a hostname" >&2
      exit 1
    fi ;;
  *) echo "LLM_PROVIDER must be zen, nvidia or local" >&2; exit 1 ;;
esac
# Check the key up front, before anything is applied to the cluster.
if [ "$SKIP_SECRET" != "1" ]; then
  if [ "$LLM_PROVIDER" = nvidia ]; then
    : "${NVIDIA_API_KEY:?set NVIDIA_API_KEY (LLM_PROVIDER=nvidia) or SKIP_SECRET=1}"
  elif [ "$LLM_PROVIDER" = local ]; then
    :   # LOCAL_LLM_API_KEY is optional (llama-server without --api-key)
  else
    : "${OPENCODE_API_KEY:?set OPENCODE_API_KEY (OpenCode Zen key) or SKIP_SECRET=1}"
  fi
fi

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
    # Built with images/vigil-llm/Dockerfile (CPU variant), not upstream's own
    # Dockerfile: at the pinned commit an upstream-style build crashes at boot
    # (unpinned huggingface_hub vs sentence-transformers 2.2.2, and a NameError
    # in VectorDB). See the Dockerfile header for every change.
    docker build -t "$VIGIL_IMG" -f images/vigil-llm/Dockerfile \
      --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cpu --build-arg EXPECT_CUDA=0 \
      "$VIGIL_SRC_DIR"
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
# Personas ship with the Zen model; point them at the chosen provider/model.
render_personas() {
  # Quote-agnostic: kustomize re-emits the YAML without the source's quotes.
  sed -e "s|providerID: \"\\?opencode\"\\?\$|providerID: \"$LLM_PROVIDER_ID\"|" \
      -e "s|modelID: \"\\?muse-spark-1.3-contributor-free\"\\?\$|modelID: \"$LLM_MODEL\"|"
}
kubectl kustomize config/samples | render_personas | kubectl apply -f -
kubectl apply -f config/rbac/runner_role.yaml

# llm-provider-credentials for namespace $1. Values go through an env-file on a
# pipe (printf is a shell builtin), so keys never appear on any process argv
# and are never echoed.
#  zen:    OPENCODE_API_KEY (+ ANTHROPIC_API_KEY) in both namespaces, as before.
#  nvidia: the real key only in security-gateways (UPSTREAM_API_KEY, read by
#          Occludra); mcp-evals gets a placeholder because the evaluator's
#          custom provider never sends a real key (Occludra swaps it).
#  local:  same shape; the gateway Secret is empty without LOCAL_LLM_API_KEY.
llm_secret_env() {
  local ns="$1"
  if [ "$LLM_PROVIDER" = nvidia ] || [ "$LLM_PROVIDER" = local ]; then
    if [ "$ns" = security-gateways ]; then
      if [ "$LLM_PROVIDER" = nvidia ]; then
        printf 'UPSTREAM_API_KEY=%s\n' "$NVIDIA_API_KEY"
      elif [ -n "${LOCAL_LLM_API_KEY:-}" ]; then
        printf 'UPSTREAM_API_KEY=%s\n' "$LOCAL_LLM_API_KEY"
      fi
    else
      printf 'OPENCODE_API_KEY=%s\n' egress-via-occludra
    fi
  else
    printf 'OPENCODE_API_KEY=%s\n' "$OPENCODE_API_KEY"
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY"; fi
  fi
}
apply_llm_secret() {
  kubectl -n "$1" create secret generic llm-provider-credentials \
    --from-env-file=<(llm_secret_env "$1") \
    --dry-run=client -o yaml | kubectl apply -f -
}

if [ "$SKIP_SECRET" != "1" ]; then
  log "Creating LLM credentials secret (provider $LLM_PROVIDER)"
  apply_llm_secret mcp-evals
fi

# Rewrite the gateway image references for this deployment (stdin → stdout).
# With IMAGE_PULL_POLICY set (air-gap), gateways must not pull either.
substitute_gateway_images() {
  # VIGIL_PROFILE=lite: the in-cluster Vigil keeps only the YARA scanner (the
  # full transformer/vectordb set runs on the GPU node, see VIGIL_GPU).
  local profile_args=()
  if [ "$VIGIL_PROFILE" = lite ]; then
    profile_args=(-e "s|input_scanners = transformer,yara,vectordb|input_scanners = yara|")
  fi
  sed -e "s|ghcr.io/security-eval/occludra-gateway:20260930|$OCCLUDRA_IMG|g" \
      -e "s|image: ghcr.io/security-eval/vigil-llm:20260930|image: $VIGIL_IMG|g" \
      -e "s|__VIGIL_REPLICAS__|$VIGIL_REPLICAS|g" \
      -e "s|__VIGIL_HPA_MIN__|$VIGIL_HPA_MIN|g" \
      -e "s|__VIGIL_MAX_UNAVAILABLE__|$VIGIL_MAX_UNAVAILABLE|g" \
      -e "/name: OCCLUDRA_UPSTREAM_BASE_URL\$/{n;s|value: \"\"|value: \"$LLM_UPSTREAM_BASE_URL\"|;}" \
      ${profile_args[@]+"${profile_args[@]}"} \
      ${IMAGE_PULL_POLICY:+-e "s|imagePullPolicy: Always|imagePullPolicy: $IMAGE_PULL_POLICY|g"} \
    | allow_local_model
}
# LLM_PROVIDER=local: add exactly the configured model id (anchored, regex-
# escaped) to Occludra's model allowlist rather than widening the shared
# patterns. A no-op for other providers and for manifests without the list.
allow_local_model() {
  if [ "$LLM_PROVIDER" != local ]; then cat; return; fi
  LLM_MODEL="$LLM_MODEL" python3 -c '
import json, os, re, sys
entry = json.dumps("^" + re.escape(os.environ["LLM_MODEL"]) + "$")
for line in sys.stdin:
    sys.stdout.write(line)
    if line.rstrip("\n") == "      allow:":
        sys.stdout.write("        - " + entry + "   # LLM_PROVIDER=local (deploy.sh)\n")
'
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
  # gateway-egress lets Occludra reach private addresses only on NetBird
  # ports, so a local LLM server (a private IP) needs its own rule: exactly
  # that IP and port, only while LLM_PROVIDER=local. Every other provider
  # deletes it, so switching back leaves no opening behind.
  if [ "$LLM_PROVIDER" = local ]; then
    log "Allowing Occludra -> local LLM $LOCAL_LLM_IP:$LOCAL_LLM_PORT (NetworkPolicy occludra-egress-local-llm)"
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: occludra-egress-local-llm
  namespace: security-gateways
  labels:
    app.kubernetes.io/part-of: mcp-eval-platform
  annotations:
    security.eval.io/reason: "LLM_PROVIDER=local: Occludra's upstream is $LOCAL_LLM_URL"
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: occludra
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: $LOCAL_LLM_IP/32
      ports:
        - protocol: TCP
          port: $LOCAL_LLM_PORT
EOF
  else
    kubectl -n security-gateways delete networkpolicy occludra-egress-local-llm --ignore-not-found
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
    log "Writing LLM credentials into security-gateways (Occludra is the upstream egress point)"
    apply_llm_secret security-gateways
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

# Enable telemetry before triggering the first evaluation.
if [[ "${DEPLOY_OBSERVABILITY:-0}" == "1" ]]; then
  OPERATOR_IMG="$IMG" EVALUATOR_IMG="$EVALUATOR_IMG" OCCLUDRA_IMG="$OCCLUDRA_IMG" ./hack/deploy-observability.sh
  kubectl -n mcp-eval-system rollout status deploy/mcp-eval-controller-manager --timeout=180s
  if [[ "$DEPLOY_SECURITY_GATEWAYS" == "1" ]]; then
    kubectl -n security-gateways rollout status deploy/occludra --timeout=180s
  fi
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

# ---------------------------------------------------------------------------
# GPU node: KEDA + scale-to-zero GPU Vigil (see hack/gpu-node/README.md).
# ---------------------------------------------------------------------------
if [ "$DEPLOY_KEDA" = "1" ]; then
  log "Installing KEDA $KEDA_CHART_VERSION (namespace keda)"
  helm upgrade --install keda keda --repo https://kedacore.github.io/charts \
    --version "$KEDA_CHART_VERSION" -n keda --create-namespace \
    -f manifests/keda/values-mcp-eval.yaml --wait --timeout 5m
fi

if [ "$VIGIL_GPU" = "1" ]; then
  kubectl get crd scaledobjects.keda.sh >/dev/null 2>&1 \
    || { echo "ERROR: VIGIL_GPU=1 needs KEDA (DEPLOY_KEDA=1)" >&2; exit 1; }
  log "Deploying the scale-to-zero GPU Vigil ($VIGIL_GPU_IMG)"
  # Keep the ScaledObject's current pause state: a re-deploy must not pause a
  # GPU Vigil that `gpu-node up` has already released (new objects start paused).
  was_paused="$(kubectl -n security-gateways get scaledobject vigil-gpu \
    -o jsonpath='{.metadata.annotations.autoscaling\.keda\.sh/paused-replicas}' 2>/dev/null || echo 0)"
  existed="$(kubectl -n security-gateways get scaledobject vigil-gpu -o name 2>/dev/null || true)"
  sed -e "s|__VIGIL_GPU_IMG__|$VIGIL_GPU_IMG|g" -e "s|__VIGIL_GPU_MEM_LIMIT__|$VIGIL_GPU_MEM_LIMIT|g" \
    hack/gpu-node/manifests/vigil-gpu.yaml | kubectl apply -f -
  if [ -n "$existed" ] && [ -z "$was_paused" ]; then
    kubectl -n security-gateways annotate scaledobject vigil-gpu autoscaling.keda.sh/paused-replicas- >/dev/null
  fi
  kubectl -n mcp-eval-system set env deploy/mcp-eval-controller-manager \
    VIGIL_GPU_URL="http://vigil-gpu-service.security-gateways.svc.cluster.local:5000/analyze/prompt" >/dev/null
fi

log "Done. Watch progress with:"
echo "  kubectl -n mcp-evals get mcprun -w"
echo "  kubectl -n mcp-evals get mcprun -o jsonpath='{.items[-1].status}' | jq ."
echo "  kubectl -n mcp-eval-system logs deploy/mcp-eval-controller-manager -f"
