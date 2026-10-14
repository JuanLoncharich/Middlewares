#!/usr/bin/env bash
# Live check of who can reach the operator pods, on a cluster deployed with
# deploy.sh (kind: test/kind/create-cluster.sh). Starts throwaway curl pods
# that carry the labels of the real clients and probes the operator's three
# ports on a replica's pod IP:
#
#   client (namespace / app.kubernetes.io/name)   8443 metrics  8082 activity  8081 probes
#   observability / prometheus                    open          closed         closed
#   observability / grafana                       closed        closed         closed
#   keda / keda-operator                          closed        open           closed
#   default / (none)                              closed        closed         closed
#
# and that the operator stays Ready (kubelet probes come from the node, which
# NetworkPolicy always allows). Namespaces it has to create are deleted at
# the end; nothing else in the cluster is changed.
#
#   KUBECONFIG=... test/kind/operator-ingress-test.sh
set -uo pipefail
IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
NS_OP=mcp-eval-system
created_ns=()
cleanup() {
  kubectl delete pod -l op-ingress-test=1 -A --ignore-not-found --grace-period=0 >/dev/null 2>&1
  for ns in "${created_ns[@]}"; do kubectl delete ns "$ns" >/dev/null 2>&1; done
}
trap cleanup EXIT

op_ip="$(kubectl -n "$NS_OP" get pods -l control-plane=controller-manager \
  -o jsonpath='{.items[0].status.podIP}')"
[ -n "$op_ip" ] || { echo "no operator pod found" >&2; exit 2; }

client() { # client <namespace> <pod-name> <app-name or "">
  local ns=$1 name=$2 app=$3
  if ! kubectl get ns "$ns" >/dev/null 2>&1; then
    kubectl create ns "$ns" >/dev/null && created_ns+=("$ns")
  fi
  kubectl -n "$ns" run "$name" --image="$IMAGE" --restart=Never \
    --labels="op-ingress-test=1${app:+,app.kubernetes.io/name=$app}" \
    --command -- sleep 600 >/dev/null
}
client observability prom prometheus
client observability graf grafana
client keda keda keda-operator
client default intruder ""
for p in observability/prom observability/graf keda/keda default/intruder; do
  kubectl -n "${p%/*}" wait --for=condition=Ready "pod/${p#*/}" --timeout=120s >/dev/null || exit 2
done

probe() { # probe <ns> <pod> <port> -> "open" | "closed"
  local scheme=http; [ "$3" = 8443 ] && scheme=https
  # Any HTTP status (401/403 from the authenticated metrics endpoint
  # included) means the TCP connection got through.
  local code
  code="$(kubectl -n "$1" exec "$2" -- curl -sk -o /dev/null -w '%{http_code}' \
    --max-time 4 "$scheme://$op_ip:$3/" 2>/dev/null)"
  [ -n "$code" ] && [ "$code" != 000 ] && echo open || echo closed
}

fail=0
expect() { # expect <ns> <pod> <port> <open|closed>
  local got; got="$(probe "$1" "$2" "$3")"
  if [ "$got" = "$4" ]; then echo "PASS $1/$2 -> :$3 $got"
  else echo "FAIL $1/$2 -> :$3 $got (want $4)"; fail=1; fi
}
expect observability prom 8443 open
expect observability prom 8082 closed
expect observability prom 8081 closed
expect observability graf 8443 closed
expect keda keda 8082 open
expect keda keda 8443 closed
expect default intruder 8443 closed
expect default intruder 8082 closed
expect default intruder 8081 closed

if kubectl -n "$NS_OP" get pods -l control-plane=controller-manager \
  -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
  | grep -qv True; then
  echo "FAIL operator replicas not all Ready"; fail=1
else
  echo "PASS operator replicas Ready (kubelet probes still reach :8081)"
fi
exit $fail
