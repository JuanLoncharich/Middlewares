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
#   IMG_TAG            image tag (default: latest)
#   OPENCODE_API_KEY   written into Secret mcp-evals/llm-provider-credentials (required unless SKIP_SECRET=1)
#   ANTHROPIC_API_KEY  optionally added to the same Secret when using provider `anthropic`
#   APISERVER_CIDR     ClusterIP of the kubernetes service, e.g. 10.96.0.1/32 (default: auto-detected)
#   APISERVER_ENDPOINTS  space-separated endpoint IPs of the kubernetes service (default: auto-detected; needed because the CNI sees post-DNAT addresses)
#   SKIP_BUILD=1       skip docker build/push
#   SKIP_SECRET=1      do not (re)create the LLM secret
#   TRIGGER=0          do not trigger a run at the end
#   ---- security layers (Vigil / Occludra / NetBird) ----
#   DEPLOY_SECURITY_GATEWAYS=0   skip the security-gateways namespace (default: deploy it)
#   NETBIRD_MANAGEMENT_URL       your NetBird management server (default placeholder is substituted)
#   NETBIRD_SETUP_KEY            setup key written into Secret netbird-auth (both namespaces)
set -euo pipefail
cd "$(dirname "$0")"

: "${IMG_REGISTRY:?set IMG_REGISTRY, e.g. ghcr.io/myorg}"
IMG_TAG="${IMG_TAG:-latest}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_SECRET="${SKIP_SECRET:-0}"
TRIGGER="${TRIGGER:-1}"
DEPLOY_SECURITY_GATEWAYS="${DEPLOY_SECURITY_GATEWAYS:-1}"
NETBIRD_MANAGEMENT_URL="${NETBIRD_MANAGEMENT_URL:-https://netbird.example.com:443}"

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
fi

log "Installing CRDs, RBAC and operator (namespace mcp-eval-system)"
kubectl kustomize config/default \
  | sed -e "s|ghcr.io/security-eval/mcp-eval-operator:latest|$IMG|g" \
        -e "s|ghcr.io/security-eval/mcp-cloner:latest|$CLONER_IMG|g" \
        -e "s|ghcr.io/security-eval/mcp-target-sandbox:latest|$TARGET_IMG|g" \
        -e "s|ghcr.io/security-eval/mcp-evaluator:latest|$EVALUATOR_IMG|g" \
        -e "s|https://netbird.example.com:443|$NETBIRD_MANAGEMENT_URL|g" \
  | kubectl apply -f -
kubectl -n mcp-eval-system rollout status deploy/mcp-eval-controller-manager --timeout=180s

log "Applying evaluation namespace, NetworkPolicies, agent personas and sample MCPServer (namespace mcp-evals)"
APISERVER_CIDR="${APISERVER_CIDR:-$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')/32}"
# Egress to the API server must also allow the real `default/kubernetes`
# endpoint IPs: kube-proxy DNATs ClusterIP traffic to them before the CNI
# evaluates policy (post-DNAT matching on Calico / kube-router). Rendered as
# ipBlock list items in place of the __APISERVER_ENDPOINTS__ marker (kept as
# a plain string so the manifest itself stays parseable by kustomize).
APISERVER_ENDPOINTS="${APISERVER_ENDPOINTS:-$(kubectl get endpoints kubernetes -n default -o jsonpath='{range .subsets[*].addresses[*]}{.ip}{" "}{end}' 2>/dev/null)}"
if [ -z "${APISERVER_ENDPOINTS// /}" ]; then
  APISERVER_ENDPOINTS="$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{range .items[*].endpoints[*]}{range .addresses[*]}{.address}{" "}{end}{end}')"
fi
if [ -z "${APISERVER_ENDPOINTS// /}" ]; then
  echo "ERROR: no kubernetes service endpoint IPs found; cannot build evaluate-phase policy" >&2
  exit 1
fi
kubectl kustomize config/samples \
  | APISERVER_CIDR="$APISERVER_CIDR" ENDPOINT_IPS="$APISERVER_ENDPOINTS" awk '
    {
      if (match($0, /^ *- __APISERVER_ENDPOINTS__$/)) {
        indent = substr($0, 1, RLENGTH - length("- __APISERVER_ENDPOINTS__"))
        n = split(ENVIRON["ENDPOINT_IPS"], ips, /[[:space:]]+/)
        printed = 0
        for (i = 1; i <= n; i++) {
          if (ips[i] == "") continue
          print indent "- ipBlock:"
          print indent "    cidr: " ips[i] "/32"
          printed = 1
        }
        if (!printed) { print "ERROR: empty endpoint IP list" > "/dev/stderr"; exit 1 }
        next
      }
      gsub(/10\.96\.0\.1\/32/, ENVIRON["APISERVER_CIDR"])
      print
    }' \
  | kubectl apply -f -
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

if [ "$DEPLOY_SECURITY_GATEWAYS" = "1" ]; then
  log "Deploying security gateways (Occludra, Vigil, NetBird) into security-gateways"
  kubectl apply -f manifests/occludra-deployment.yaml
  kubectl apply -f manifests/netbird-daemonset.yaml
  kubectl apply -f manifests/vigil-deployment.yaml
  if [ -n "${NETBIRD_SETUP_KEY:-}" ]; then
    log "Creating NetBird enrollment secrets (setup key)"
    for ns in security-gateways mcp-evals; do
      kubectl -n "$ns" create secret generic netbird-auth \
        --from-literal=setup-key="$NETBIRD_SETUP_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
    done
  else
    echo "WARNING: NETBIRD_SETUP_KEY unset — netbird-auth does not exist and mesh enrollment WILL fail." >&2
    echo "         Create it with: kubectl -n <ns> create secret generic netbird-auth --from-literal=setup-key=<key>" >&2
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

if [ "$TRIGGER" = "1" ]; then
  log "Triggering first evaluation of filesystem-mcp"
  kubectl -n mcp-evals annotate mcpserver filesystem-mcp security.eval.io/trigger-now=true --overwrite
fi

log "Done. Watch progress with:"
echo "  kubectl -n mcp-evals get mcprun -w"
echo "  kubectl -n mcp-evals get mcprun -o jsonpath='{.items[-1].status}' | jq ."
echo "  kubectl -n mcp-eval-system logs deploy/mcp-eval-controller-manager -f"
