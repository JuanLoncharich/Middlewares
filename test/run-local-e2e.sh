#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Local end-to-end evaluation test: deploys the in-cluster HTTPS git server
# with the two fixture MCP servers (benign + malicious), registers them as
# MCPServer resources and triggers immediate evaluations.
#
#   ./test/run-local-e2e.sh              # uses localhost:5001 (kind registry)
#   IMG_REGISTRY=ghcr.io/me ./test/run-local-e2e.sh
#
# Prerequisites: the platform already deployed (deploy.sh), the four agent
# personas present (config/samples), and MESH_ENFORCE=false for the local
# kind cluster (no NetBird management server).
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/.."

REGISTRY="${IMG_REGISTRY:-localhost:5001}"
GIT_IMAGE="$REGISTRY/git-test-server:local"
NAMESPACE="mcp-evals"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

# ---- 1. throwaway CA + server cert for git-test.mcp-evals.svc.cluster.local
log "Generating throwaway CA and server certificate"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" \
  -subj "/CN=mcp-eval-test-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$WORK/tls.key" -out "$WORK/tls.csr" \
  -subj "/CN=git-test.$NAMESPACE.svc.cluster.local" >/dev/null 2>&1
openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -out "$WORK/tls.crt" -days 7 \
  -extfile <(printf "subjectAltName=DNS:git-test.%s.svc.cluster.local" "$NAMESPACE") \
  >/dev/null 2>&1

log "Creating TLS + CA secrets in namespace $NAMESPACE"
kubectl -n "$NAMESPACE" create secret generic git-test-tls \
  --from-file=tls.crt="$WORK/tls.crt" --from-file=tls.key="$WORK/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -
# credentialsSecretRef for the fixture MCPServers: the operator forwards the
# ca.crt key to the cloner as GIT_SSL_CAINFO (git reads it natively).
kubectl -n "$NAMESPACE" create secret generic mcp-git-test-ca \
  --from-literal=ca.crt="$(cat "$WORK/ca.crt")" \
  --dry-run=client -o yaml | kubectl apply -f -

# ---- 2. build + push the git server image (fixtures baked in)
log "Building git-test-server image ($GIT_IMAGE)"
docker build -f test/git-server/Dockerfile -t "$GIT_IMAGE" test
docker push "$GIT_IMAGE"

# ---- 3. deploy the git server + fixture NetworkPolicies
log "Deploying git-test into $NAMESPACE"
sed "s|localhost:5001/git-test-server:local|$GIT_IMAGE|" test/git-server.yaml | kubectl apply -f -
kubectl -n "$NAMESPACE" rollout status deploy/git-test --timeout=120s

log "Verifying the fixture repos are served"
GIT_POD="$(kubectl -n "$NAMESPACE" get pod -l app=git-test -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NAMESPACE" exec "$GIT_POD" -- \
  wget -q -O - --no-check-certificate "https://127.0.0.1:5443/mcp-benign-demo.git/info/refs?service=git-upload-pack" | head -c 40 >/dev/null
kubectl -n "$NAMESPACE" exec "$GIT_POD" -- \
  wget -q -O - --no-check-certificate "https://127.0.0.1:5443/mcp-evil-demo.git/info/refs?service=git-upload-pack" | head -c 40 >/dev/null
echo "fixtures served OK"

# ---- 4. register the two fixture MCPServers and trigger immediate runs
log "Creating MCPServer fixtures (benign + malicious)"
cat <<EOF | kubectl apply -f -
apiVersion: security.eval.io/v1alpha1
kind: MCPServer
metadata:
  name: mcp-benign-demo
  namespace: $NAMESPACE
spec:
  repositoryUrl: https://git-test.$NAMESPACE.svc.cluster.local/mcp-benign-demo.git
  ref: main
  transport: stdio
  schedule: "0 0 * * *"
  active: true
  credentialsSecretRef: mcp-git-test-ca
  agentSuite:
    - name: mcp-sast-auditor
    - name: mcp-fuzz-tester
    - name: mcp-rogue-detector
    - name: mcp-synthesizer
  timeoutSeconds: 900
EOF
cat <<EOF | kubectl apply -f -
apiVersion: security.eval.io/v1alpha1
kind: MCPServer
metadata:
  name: mcp-evil-demo
  namespace: $NAMESPACE
spec:
  repositoryUrl: https://git-test.$NAMESPACE.svc.cluster.local/mcp-evil-demo.git
  ref: main
  transport: stdio
  schedule: "0 0 * * *"
  active: true
  credentialsSecretRef: mcp-git-test-ca
  agentSuite:
    - name: mcp-sast-auditor
    - name: mcp-fuzz-tester
    - name: mcp-rogue-detector
    - name: mcp-synthesizer
  timeoutSeconds: 900
EOF

log "Triggering immediate evaluations"
kubectl -n "$NAMESPACE" annotate mcpserver mcp-benign-demo security.eval.io/trigger-now=true --overwrite
kubectl -n "$NAMESPACE" annotate mcpserver mcp-evil-demo security.eval.io/trigger-now=true --overwrite

cat <<'EOT'

Fixtures deployed. Watch the runs:

  kubectl -n mcp-evals get mcprun -w

Expected outcomes
  mcp-benign-demo-run-*  → Completed, score, risk Safe/Caution
  mcp-evil-demo-run-*    → Failed, finalScore 0, riskCategory Malicious,
                           Critical finding from vigil-llm
                           (advertised-surface prompt-injection detection)

Drill into a run:
  kubectl -n mcp-evals get mcprun <name> -o yaml
  kubectl -n mcp-evals logs -l security.eval.io/run=<name> -c evaluator --tail=50
EOT
