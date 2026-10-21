#!/usr/bin/env bash
# Offline check of the operator's own Ingress NetworkPolicy as deploy.sh
# renders it (kubectl kustomize config/default): it selects the operator pods,
# lets only Prometheus reach :8443 and only KEDA reach :8082, and its client
# selectors survive kustomize's includeSelectors label injection (an injected
# app.kubernetes.io/part-of would make them match nothing).
#
#   test/deploy/operator-netpol-test.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PY=python3
if ! python3 -c 'import yaml' 2>/dev/null; then
  python3 -m venv "$WORK/venv" && "$WORK/venv/bin/pip" install -q pyyaml \
    || { echo "need PyYAML (python3 -m venv + pip failed)" >&2; exit 2; }
  PY="$WORK/venv/bin/python3"
fi
kubectl kustomize config/default > "$WORK/rendered.yaml" || exit 1
"$PY" - "$WORK/rendered.yaml" <<'PYEOF'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
fail = 0
def check(ok, msg):
    global fail
    print(("PASS " if ok else "FAIL ") + msg)
    fail += not ok

def matches(selector, labels):
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for e in selector.get("matchExpressions") or []:
        if e["operator"] != "In" or labels.get(e["key"]) not in e["values"]:
            return False
    return True

pols = [d for d in docs if d["kind"] == "NetworkPolicy"
        and d["metadata"]["namespace"] == "mcp-eval-system"]
check(len(pols) == 1, f"exactly one NetworkPolicy in mcp-eval-system (got {len(pols)})")
if not pols:
    sys.exit(1)
pol = pols[0]["spec"]
dep = next(d for d in docs if d["kind"] == "Deployment")
pod_labels = dep["spec"]["template"]["metadata"]["labels"]
check(matches(pol["podSelector"], pod_labels), "policy selects the operator pods")
check(pol["policyTypes"] == ["Ingress"], "Ingress only (operator egress untouched)")

# The labels the real clients carry (observability workloads.yaml, KEDA chart).
clients = {
    "prometheus": ("observability", {"app.kubernetes.io/name": "prometheus"}),
    "keda": ("keda", {"app.kubernetes.io/name": "keda-operator"}),
    "untrusted target": ("mcp-evals", {"security.eval.io/role": "evaluation-pod"}),
}
def allowed_ports(ns, labels):
    ports = set()
    for rule in pol.get("ingress", []):
        for peer in rule.get("from", []):
            nsl = (peer.get("namespaceSelector") or {}).get("matchLabels", {})
            if nsl.get("kubernetes.io/metadata.name") != ns:
                continue
            if matches(peer.get("podSelector") or {}, labels):
                ports |= {p["port"] for p in rule.get("ports", [])}
    return ports
check(allowed_ports(*clients["prometheus"]) == {8443}, "Prometheus -> 8443 only")
check(allowed_ports(*clients["keda"]) == {8082}, "KEDA -> 8082 only")
check(allowed_ports(*clients["untrusted target"]) == set(), "evaluation pods -> nothing")
sys.exit(1 if fail else 0)
PYEOF
