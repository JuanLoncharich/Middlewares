#!/usr/bin/env bash
# Deploy Chroma (namespace `chroma`) behind chroma-gateway, create its tokens,
# and load the Vigil corpus. deploy.sh calls this when DEPLOY_VECTOR_DB=1; it
# also runs on its own:
#
#   CONTEXT=kind-mcp-e2e VECTOR_DB_MODE=single hack/chroma/deploy.sh
#   CONTEXT=k0s CHROMA_QUERY_REPLICAS=1 CHROMA_COMPACTION_REPLICAS=1 hack/chroma/deploy.sh
#
# Settings (environment):
#   CONTEXT                      kubectl context (default: the current one)
#   VECTOR_DB_MODE               distributed (default): the full distributed Chroma over MinIO
#                                (manifests/chroma/chart + values-mcp-eval.yaml);
#                                single: one chroma pod with an emptyDir, for kind tests only
#   CHROMA_IMG_TAG               distributed component image tag (default dff1d8a)
#   CHROMA_QUERY_REPLICAS        query-service replicas (default 1)
#   CHROMA_COMPACTION_REPLICAS   compaction-service replicas (default 1)
#   SKIP_CORPUS_LOAD=1           do not run the loader Job
#   VIGIL_CORPUS_IMG             image carrying the calibrated corpus file (deploy.sh builds it:
#                                images/vigil-corpus-loader/Dockerfile.corpus); required unless
#                                SKIP_CORPUS_LOAD=1
#   VIGIL_CORPUS_LOCK            lock file pinning that corpus (default
#                                hack/vigil-corpus/vigil-corpus-e5s-v3.lock.json): file name + sha256
#   CHROMA_ROTATE_TOKENS=1       replace both tokens (gateway and Vigil pods are restarted)
#
# Tokens: Secret chroma-auth (namespace chroma: reader-token, writer-token)
# is generated once, randomly, and never printed; Secret chroma-reader
# (namespace security-gateways: token) is a copy of the reader token for the
# Vigil pods. The writer token never leaves namespace chroma.
set -euo pipefail
cd "$(dirname "$0")/../.."

VECTOR_DB_MODE="${VECTOR_DB_MODE:-distributed}"
CHROMA_IMG_TAG="${CHROMA_IMG_TAG:-dff1d8a}"
CHROMA_QUERY_REPLICAS="${CHROMA_QUERY_REPLICAS:-1}"
CHROMA_COMPACTION_REPLICAS="${CHROMA_COMPACTION_REPLICAS:-1}"
SKIP_CORPUS_LOAD="${SKIP_CORPUS_LOAD:-0}"
VIGIL_CORPUS_LOCK="${VIGIL_CORPUS_LOCK:-hack/vigil-corpus/vigil-corpus-e5s-v3.lock.json}"
CHROMA_ROTATE_TOKENS="${CHROMA_ROTATE_TOKENS:-0}"

k() { kubectl ${CONTEXT:+--context "$CONTEXT"} "$@"; }
log() { printf '\n==> [chroma] %s\n' "$*"; }
case "$VECTOR_DB_MODE" in
  distributed) UPSTREAM=rust-frontend-service:8000 ;;
  single) UPSTREAM=chroma-single:8000 ;;
  *) echo "VECTOR_DB_MODE must be distributed or single (got '$VECTOR_DB_MODE')" >&2; exit 2 ;;
esac

k create namespace chroma --dry-run=client -o yaml | k apply -f -
k create namespace security-gateways --dry-run=client -o yaml | k apply -f -
k apply -f manifests/chroma/networkpolicy.yaml
# Renamed to allow-vigil-to-gateway: the frontend takes no outside clients now.
k -n chroma delete networkpolicy allow-vigil-to-frontend --ignore-not-found

# ---- tokens (values travel only through pipes, never argv or output) ----
rotated=0
if [ "$CHROMA_ROTATE_TOKENS" = "1" ] || ! k -n chroma get secret chroma-auth >/dev/null 2>&1; then
  log "Generating chroma-auth tokens"
  python3 -c '
import secrets, sys
r, w = secrets.token_hex(32), secrets.token_hex(32)
sys.stdout.write(f"""apiVersion: v1
kind: Secret
metadata:
  name: chroma-auth
  namespace: chroma
  labels: {{app.kubernetes.io/part-of: chroma-distributed}}
type: Opaque
stringData:
  reader-token: "{r}"
  writer-token: "{w}"
""")' | k apply -f - >/dev/null
  rotated=1
fi
k -n chroma get secret chroma-auth -o jsonpath='{.data.reader-token}' | python3 -c '
import sys
tok = sys.stdin.read().strip()
if not tok:
    sys.exit("chroma-auth has no reader-token")
sys.stdout.write(f"""apiVersion: v1
kind: Secret
metadata:
  name: chroma-reader
  namespace: security-gateways
  labels: {{app.kubernetes.io/part-of: mcp-eval-platform}}
type: Opaque
data:
  token: "{tok}"
""")' | k apply -f - >/dev/null

# ---- Chroma itself ----
# PriorityClasses referenced by MinIO/Postgres (critical) and the corpus
# loader (batch).
k apply -f manifests/priorityclass.yaml
# Container defaults for anything without its own requests/limits.
k -n chroma apply -f manifests/limitrange.yaml
if [ "$VECTOR_DB_MODE" = single ]; then
  log "Deploying single-node Chroma (test only: data lives in an emptyDir)"
  k apply -f manifests/chroma/single.yaml
  k -n chroma rollout status deploy/chroma-single --timeout=300s
else
  log "Deploying vector-DB substrate (MinIO, Postgres, OTel)"
  k apply -f manifests/chroma/minio.yaml -f manifests/chroma/postgres.yaml -f manifests/chroma/otel-collector.yaml
  for dep in minio postgres otel-collector; do
    k -n chroma rollout status "deploy/$dep" --timeout=300s
  done
  log "Rendering + applying distributed Chroma (chromadb/*:$CHROMA_IMG_TAG, query x$CHROMA_QUERY_REPLICAS, compaction x$CHROMA_COMPACTION_REPLICAS)"
  # CRDs first: the MemberList custom resources in the chart cannot be
  # applied until the chroma.cluster CRD is established.
  k apply -f manifests/chroma/chart/crds/
  helm template distributed-chroma manifests/chroma/chart \
    -f manifests/chroma/values-mcp-eval.yaml \
    --set queryService.replicaCount="$CHROMA_QUERY_REPLICAS" \
    --set compactionService.replicaCount="$CHROMA_COMPACTION_REPLICAS" \
    --set-file rustFrontendService.configuration=manifests/chroma/frontend-config.yaml \
    --set-file rustLogService.configuration=manifests/chroma/worker-config.yaml \
    --set-file queryService.configuration=manifests/chroma/worker-config.yaml \
    --set-file compactionService.configuration=manifests/chroma/worker-config.yaml \
    --set-file garbageCollector.configuration=manifests/chroma/worker-config.yaml \
    --set-file rustSysdbService.configuration=manifests/chroma/worker-config.yaml \
    --set-file workQueueService.configuration=manifests/chroma/worker-config.yaml \
    --set-file fnConsumer.configuration=manifests/chroma/worker-config.yaml \
    | sed "s|__CHROMA_IMG_TAG__|$CHROMA_IMG_TAG|g" \
    | k apply -f -
  # The components find each other through MemberList custom resources and
  # leases, i.e. they call the Kubernetes API, which default-deny-all blocks
  # (seen on k0s/Calico: "Error acquiring memberlist ... deadline has elapsed",
  # frontend stuck at 503). NetworkPolicies match the API server's real
  # endpoint (after the Service DNAT), which differs per cluster, so the
  # policy is rendered from this cluster's endpoints.
  api_peers="$(k get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{range .items[*]}{range .endpoints[*]}{.addresses[0]}{" "}{end}{end}')"
  api_port="$(k get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[0].ports[0].port}')"
  [ -n "$api_peers" ] && [ -n "$api_port" ] || { echo "cannot read the API server endpoints" >&2; exit 1; }
  {
    cat <<'POLICY'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-kube-api-egress
  namespace: chroma
  labels: {app.kubernetes.io/part-of: chroma-distributed}
spec:
  # The chart's components (memberlist, leases); not MinIO, Postgres, the
  # gateway or the loader.
  podSelector:
    matchExpressions:
      - {key: app, operator: In, values: [sysdb, rust-sysdb-service, rust-frontend-service, rust-log-service,
          query-service, compaction-service, work-queue-service, fn-consumer, garbage-collector]}
  policyTypes: [Egress]
  egress:
    - to:
POLICY
    for ip in $api_peers; do printf '        - ipBlock: {cidr: %s/32}\n' "$ip"; done
    printf '      ports:\n        - {protocol: TCP, port: %s}\n' "$api_port"
  } | k apply -f -
  for dep in sysdb rust-sysdb-service rust-frontend-service fn-consumer; do
    k -n chroma rollout status "deploy/$dep" --timeout=600s
  done
  for sts in rust-log-service query-service compaction-service garbage-collector work-queue-service; do
    k -n chroma rollout status "statefulset/$sts" --timeout=600s
  done
fi

# ---- the gateway: the only door in ----
log "Deploying chroma-gateway (upstream $UPSTREAM)"
sed "s|__CHROMA_UPSTREAM__|$UPSTREAM|g" manifests/chroma/gateway.yaml | k apply -f -
if [ "$rotated" = 1 ]; then
  # New tokens: pods read them from env at start.
  k -n chroma rollout restart deploy/chroma-gateway
  for d in vigil vigil-gpu; do
    k -n security-gateways get deploy "$d" >/dev/null 2>&1 && k -n security-gateways rollout restart "deploy/$d"
  done
fi
k -n chroma rollout status deploy/chroma-gateway --timeout=180s

# ---- corpus ----
if [ "$SKIP_CORPUS_LOAD" != "1" ]; then
  : "${VIGIL_CORPUS_IMG:?set VIGIL_CORPUS_IMG (the corpus image deploy.sh builds), or SKIP_CORPUS_LOAD=1}"
  read -r CORPUS_FILE CORPUS_SHA256 < <(python3 -c 'import json,sys; l=json.load(open(sys.argv[1])); print(l["file"], l["sha256"])' "$VIGIL_CORPUS_LOCK")
  log "Loading Vigil corpus $CORPUS_FILE (sha256 ${CORPUS_SHA256:0:12}…) from $VIGIL_CORPUS_IMG (Job vigil-corpus-loader)"
  k -n chroma create configmap vigil-corpus-loader \
    --from-file=load_corpus.py=images/vigil-corpus-loader/load_corpus.py --dry-run=client -o yaml | k apply -f -
  # A Job's pod template is immutable: replace it so a new run happens.
  k -n chroma delete job vigil-corpus-loader --ignore-not-found --wait=true
  sed -e "s|__VIGIL_CORPUS_IMG__|$VIGIL_CORPUS_IMG|" -e "s|__CORPUS_FILE__|$CORPUS_FILE|" \
      -e "s|__CORPUS_SHA256__|$CORPUS_SHA256|" manifests/chroma/corpus-loader-job.yaml | k apply -f -
  # ~200k vectors through the gateway: minutes on a laptop, longer on the distributed Chroma.
  k -n chroma wait --for=condition=complete job/vigil-corpus-loader --timeout=1800s \
    || { echo "ERROR: corpus loader did not complete — logs: kubectl -n chroma logs job/vigil-corpus-loader" >&2; exit 1; }
fi
echo "Chroma ($VECTOR_DB_MODE) up behind http://chroma-gateway.chroma.svc.cluster.local:8080"
