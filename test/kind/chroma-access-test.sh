#!/usr/bin/env bash
# Live check of who can reach Chroma, on a cluster deployed with
# hack/chroma/deploy.sh (kind with VECTOR_DB_MODE=single, or the real
# distributed one). Throwaway curl pods carry the labels of real clients:
#
#   client (namespace / app.kubernetes.io/name)   chroma-gateway:8080   Chroma itself :8000
#   security-gateways / vigil-llm                 open                   closed
#   security-gateways / occludra                  closed                 closed
#   mcp-evals / (none)                            closed                 closed
#   default / (none)                              closed                 closed
#
# Through the gateway, from the Vigil-labelled pod holding the reader token
# exactly as Vigil does (env from Secret chroma-reader — the token never
# passes through this script): no token -> 401, reader query -> 200, reader
# write/delete -> 403. Pods are deleted at the end; nothing else changes.
#
#   KUBECONFIG=... test/kind/chroma-access-test.sh       (or CONTEXT=k0s)
set -uo pipefail
IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
k() { kubectl ${CONTEXT:+--context "$CONTEXT"} "$@"; }
cleanup() { k delete pod -l chroma-access-test=1 -A --ignore-not-found --grace-period=0 --wait=true >/dev/null 2>&1; }
trap cleanup EXIT
cleanup

GW=chroma-gateway.chroma.svc.cluster.local:8080
if k -n chroma get svc chroma-single >/dev/null 2>&1; then UP=chroma-single.chroma.svc.cluster.local:8000
else UP=rust-frontend-service.chroma.svc.cluster.local:8000; fi
echo "gateway $GW, upstream $UP"

client() { # client <namespace> <pod-name> <app-name or ""> [with-token]
  # Pod Security "restricted" compliant (mcp-evals enforces it).
  local ns=$1 name=$2 app=$3 env='[]'
  [ "${4:-}" = with-token ] && env='[{"name":"CHROMA_TOKEN","valueFrom":{"secretKeyRef":{"name":"chroma-reader","key":"token"}}}]'
  k -n "$ns" run "$name" --image="$IMAGE" --restart=Never \
    --labels="chroma-access-test=1${app:+,app.kubernetes.io/name=$app}" \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":100,"seccompProfile":{"type":"RuntimeDefault"}},
      "containers":[{"name":"'"$name"'","image":"'"$IMAGE"'","command":["sleep","600"],"env":'"$env"',
      "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' >/dev/null
}
client security-gateways vigil vigil-llm with-token
client security-gateways occl occludra
client mcp-evals evalpod ""
client default intruder ""
for p in security-gateways/vigil security-gateways/occl mcp-evals/evalpod default/intruder; do
  k -n "${p%/*}" wait --for=condition=Ready "pod/${p#*/}" --timeout=180s >/dev/null || { echo "client $p not Ready"; exit 2; }
done

fail=0
probe() { # probe <ns> <pod> <host:port> -> open|closed
  local code
  code="$(k -n "$1" exec "$2" -- curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$3/api/v2/heartbeat" 2>/dev/null)"
  [ -n "$code" ] && [ "$code" != 000 ] && echo open || echo closed
}
expect() { # expect <ns> <pod> <host:port> <open|closed>
  local got; got="$(probe "$1" "$2" "$3")"
  if [ "$got" = "$4" ]; then echo "PASS $1/$2 -> ${3%%.*}:${3##*:} $got"
  else echo "FAIL $1/$2 -> ${3%%.*}:${3##*:} $got (want $4)"; fail=1; fi
}
expect security-gateways vigil "$GW" open
expect security-gateways vigil "$UP" closed
expect security-gateways occl "$GW" closed
expect security-gateways occl "$UP" closed
expect mcp-evals evalpod "$GW" closed
expect default intruder "$GW" closed
expect default intruder "$UP" closed

api() { # api <want-code> <description> <curl args after the URL path...>; runs in the vigil pod
  local want=$1 desc=$2 path=$3; shift 3
  local got
  got="$(k -n security-gateways exec vigil -- sh -c '
    p="$1"; shift
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" "http://'"$GW"'/api/v2/tenants/default_tenant/databases/default_database$p"
  ' sh "$path" "$@" 2>/dev/null)"
  if [ "$got" = "$want" ]; then echo "PASS $desc ($got)"; else echo "FAIL $desc (got $got, want $want)"; fail=1; fi
}
api_tok() { local want=$1 desc=$2 path=$3; shift 3
  local got
  got="$(k -n security-gateways exec vigil -- sh -c '
    p="$1"; shift
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Authorization: Bearer $CHROMA_TOKEN" "$@" \
      "http://'"$GW"'/api/v2/tenants/default_tenant/databases/default_database$p"
  ' sh "$path" "$@" 2>/dev/null)"
  if [ "$got" = "$want" ]; then echo "PASS $desc ($got)"; else echo "FAIL $desc (got $got, want $want)"; fail=1; fi
}
api 401 "no token: get collection" /collections/vigil_jailbreak
api_tok 200 "reader token: get collection (Vigil's call)" /collections/vigil_jailbreak
coll="$(k -n security-gateways exec vigil -- sh -c 'curl -s --max-time 10 -H "Authorization: Bearer $CHROMA_TOKEN" \
  "http://'"$GW"'/api/v2/tenants/default_tenant/databases/default_database/collections/vigil_jailbreak"' 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)"
[ -n "$coll" ] || { echo "FAIL could not resolve collection id"; fail=1; }
vec="[$(python3 -c 'print(",".join(["0.05"]*384))')]"
api_tok 200 "reader token: query (Vigil's call)" "/collections/$coll/query" -X POST -H 'Content-Type: application/json' \
  -d "{\"query_embeddings\":[$vec],\"n_results\":1}"
api_tok 403 "reader token: add" "/collections/$coll/add" -X POST -H 'Content-Type: application/json' \
  -d "{\"ids\":[\"x\"],\"embeddings\":[$vec],\"documents\":[\"x\"]}"
api_tok 403 "reader token: delete collection" /collections/vigil_jailbreak -X DELETE
api_tok 403 "reader token: list collections" /collections
echo "---"; [ "$fail" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$fail"
