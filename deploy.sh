#!/usr/bin/env bash
# One-shot build + deploy for the MCP evaluation platform.
#
#   IMG_REGISTRY=ghcr.io/<you> ANTHROPIC_API_KEY=sk-ant-... ./deploy.sh
#
# Steps: build & push the four images, install CRDs + operator (mcp-eval-system),
# apply the evaluation namespace / NetworkPolicies / agent personas / sample
# server (mcp-evals), create the LLM secret, and trigger the first run.
#
# Env:
#   IMG_REGISTRY       registry prefix for the images (required)
#   IMG_TAG            image tag (default: latest)
#   ANTHROPIC_API_KEY  written into Secret mcp-evals/llm-provider-credentials (required unless SKIP_SECRET=1)
#   APISERVER_CIDR     ClusterIP of the kubernetes service, e.g. 10.96.0.1/32 (default: auto-detected)
#   SKIP_BUILD=1       skip docker build/push
#   SKIP_SECRET=1      do not (re)create the LLM secret
#   TRIGGER=0          do not trigger a run at the end
set -euo pipefail
cd "$(dirname "$0")"

: "${IMG_REGISTRY:?set IMG_REGISTRY, e.g. ghcr.io/myorg}"
IMG_TAG="${IMG_TAG:-latest}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_SECRET="${SKIP_SECRET:-0}"
TRIGGER="${TRIGGER:-1}"

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
  | kubectl apply -f -
kubectl -n mcp-eval-system rollout status deploy/mcp-eval-controller-manager --timeout=180s

log "Applying evaluation namespace, NetworkPolicies, agent personas and sample MCPServer (namespace mcp-evals)"
APISERVER_CIDR="${APISERVER_CIDR:-$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')/32}"
kubectl kustomize config/samples \
  | sed -e "s|10.96.0.1/32|$APISERVER_CIDR|g" \
  | kubectl apply -f -
kubectl apply -f config/rbac/runner_role.yaml

if [ "$SKIP_SECRET" != "1" ]; then
  : "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY or SKIP_SECRET=1}"
  log "Creating LLM credentials secret"
  kubectl -n mcp-evals create secret generic llm-provider-credentials \
    --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

if [ "$TRIGGER" = "1" ]; then
  log "Triggering first evaluation of filesystem-mcp"
  kubectl -n mcp-evals annotate mcpserver filesystem-mcp security.eval.io/trigger-now=true --overwrite
fi

log "Done. Watch progress with:"
echo "  kubectl -n mcp-evals get mcprun -w"
echo "  kubectl -n mcp-evals get mcprun -o jsonpath='{.items[-1].status}' | jq ."
echo "  kubectl -n mcp-eval-system logs deploy/mcp-eval-controller-manager -f"
