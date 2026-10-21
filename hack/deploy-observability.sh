#!/usr/bin/env bash
# Install monitoring without rerunning deploy.sh or overwriting runtime settings.
# Images are optional: set all three to roll out the instrumented applications.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -n "${OPERATOR_IMG:-}${EVALUATOR_IMG:-}${OCCLUDRA_IMG:-}" ]]; then
  : "${OPERATOR_IMG:?Set all three versioned images}"
  : "${EVALUATOR_IMG:?Set all three versioned images}"
  : "${OCCLUDRA_IMG:?Set all three versioned images}"
fi

kubectl create namespace observability --dry-run=client -o yaml | kubectl apply -f -
if ! kubectl -n observability get secret grafana-admin >/dev/null 2>&1; then
  # Never put generated credentials on argv, in Git, or in the script output.
  python3 - <<'PY' | kubectl apply -f -
import base64, json, secrets
print(json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"name":"grafana-admin","namespace":"observability"},"type":"Opaque","data":{"password":base64.b64encode(secrets.token_urlsafe(32).encode()).decode()}}))
PY
fi
kubectl apply -k manifests/observability
for namespace in mcp-eval-system mcp-evals security-gateways; do
  # mcp-eval-system has no file: the operator bundle owns its Ingress policy.
  if [[ -f "manifests/observability/integrations/$namespace.yaml" ]] \
    && kubectl get namespace "$namespace" >/dev/null 2>&1; then
    kubectl apply -f "manifests/observability/integrations/$namespace.yaml"
  fi
done

if kubectl -n chroma get deployment otel-collector >/dev/null 2>&1; then
  kubectl apply -f manifests/chroma/otel-collector-observability.yaml
  kubectl -n chroma rollout restart deployment/otel-collector
fi

if [[ -n "${OPERATOR_IMG:-}${EVALUATOR_IMG:-}${OCCLUDRA_IMG:-}" ]]; then
  backup_dir="$(mktemp -d /tmp/mcp-observability-rollback.XXXXXX)"
  chmod 700 "$backup_dir"
  kubectl -n mcp-eval-system get deployment mcp-eval-controller-manager -o yaml > "$backup_dir/operator.yaml"
  if kubectl -n security-gateways get deployment occludra >/dev/null 2>&1; then
    kubectl -n security-gateways get deployment occludra -o yaml > "$backup_dir/occludra.yaml"
  fi
  chmod 600 "$backup_dir"/*.yaml
  export OPERATOR_IMG EVALUATOR_IMG OCCLUDRA_IMG
  patch_dir="$(mktemp -d /tmp/mcp-observability-patches.XXXXXX)"
  trap 'rm -rf "$patch_dir"' EXIT
  python3 - "$patch_dir" <<'PY'
import json, os, pathlib, sys
root=pathlib.Path(sys.argv[1])
endpoint="http://otel-collector.observability.svc.cluster.local:4318"
def patch(file,container,image,extra):
    env=[{"name":"OTEL_EXPORTER_OTLP_ENDPOINT","value":endpoint}]
    for name,field in [("POD_NAME","metadata.name"),("POD_NAMESPACE","metadata.namespace")]:
        env.append({"name":name,"valueFrom":{"fieldRef":{"fieldPath":field}}})
    env.extend(extra)
    root.joinpath(file).write_text(json.dumps({"spec":{"template":{"spec":{"containers":[{"name":container,"image":image,"imagePullPolicy":"IfNotPresent","env":env}]}}}}))
patch("operator.json","manager",os.environ["OPERATOR_IMG"],[{"name":"EVALUATOR_IMAGE","value":os.environ["EVALUATOR_IMG"]}])
patch("occludra.json","gateway",os.environ["OCCLUDRA_IMG"],[])
PY
  kubectl -n mcp-eval-system patch deployment mcp-eval-controller-manager --type strategic --patch-file "$patch_dir/operator.json"
  if kubectl -n security-gateways get deployment occludra >/dev/null 2>&1; then
    kubectl -n security-gateways patch deployment occludra --type strategic --patch-file "$patch_dir/occludra.json"
  fi
  printf 'Previous deployments saved in %s\n' "$backup_dir"
fi

printf '%s\n' 'Monitoring installed. Check: kubectl -n observability get pods,pvc' \
  'Grafana: kubectl -n observability port-forward svc/grafana 3000:3000' \
  'Username: admin. Password is stored in observability/grafana-admin.'
