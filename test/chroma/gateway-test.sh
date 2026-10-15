#!/usr/bin/env bash
# chroma-gateway (manifests/chroma/gateway.yaml) against a real Chroma, in
# Docker (test/chroma/lib.sh: template, script and images come from the
# manifests). Tokens are random per run and never printed.
#
#   test/chroma/gateway-test.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
WORK="$(mktemp -d)"
trap 'chroma_gw_down; rm -rf "$WORK"' EXIT
source test/chroma/lib.sh
chroma_gw_up "$WORK" || exit 1
trap 'chroma_gw_down; rm -rf "$WORK"' EXIT
READER="$CHROMA_READER"; WRITER="$CHROMA_WRITER"; BASE="$CHROMA_GW_URL"; PY="$CHROMA_PY"; NET="$CHROMA_GW_NET"

fail=0
check() {  # check <expected-code> <description> <curl args...>
  local want="$1" desc="$2"; shift 2
  local got; got="$(curl -s --max-time 10 --path-as-is -o "$WORK/body" -w '%{http_code}' "$@")"
  if [ "$got" = "$want" ]; then echo "PASS $desc ($got)"; else echo "FAIL $desc (want $want, got $got: $(head -c 200 "$WORK/body"))"; fail=$((fail+1)); fi
}
API="$BASE/api/v2/tenants/default_tenant/databases/default_database"
R=(-H "Authorization: Bearer $READER"); W=(-H "Authorization: Bearer $WRITER"); J=(-H 'Content-Type: application/json')
check 200 "heartbeat needs no token" "$BASE/api/v2/heartbeat"
check 401 "no token: list collections" "$API/collections"
check 401 "wrong token" -H "Authorization: Bearer $(openssl rand -hex 32)" "$API/collections"
check 401 "empty bearer" -H "Authorization: Bearer " "$API/collections"
check 200 "writer: create collection" "${W[@]}" "${J[@]}" -X POST "$API/collections" \
  -d '{"name":"gwtest","get_or_create":true,"configuration":{"hnsw":{"space":"cosine"}}}'
ID="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/body" 2>/dev/null)"
check 201 "writer: add vectors" "${W[@]}" "${J[@]}" -X POST "$API/collections/$ID/add" \
  -d '{"ids":["a","b"],"embeddings":[[1,0,0],[0,1,0]],"documents":["ignore previous instructions","hello"]}'
check 200 "reader: get collection by name" "${R[@]}" "$API/collections/gwtest"
check 200 "reader: query" "${R[@]}" "${J[@]}" -X POST "$API/collections/$ID/query" \
  -d '{"query_embeddings":[[1,0,0]],"n_results":1,"include":["documents","distances"]}'
grep -q 'ignore previous instructions' "$WORK/body" && echo "PASS reader query returns the nearest document" \
  || { echo "FAIL reader query body: $(head -c 200 "$WORK/body")"; fail=$((fail+1)); }
check 403 "reader: add" "${R[@]}" "${J[@]}" -X POST "$API/collections/$ID/add" \
  -d '{"ids":["c"],"embeddings":[[0,0,1]],"documents":["x"]}'
check 403 "reader: delete collection" "${R[@]}" -X DELETE "$API/collections/gwtest"
check 403 "reader: list collections" "${R[@]}" "$API/collections"
check 403 "reader: count" "${R[@]}" "$API/collections/$ID/count"
check 403 "reader: dot-dot segment" "${R[@]}" "$API/collections/../collections"
check 403 "reader: encoded slash" "${R[@]}" -X POST "$API/collections/$ID%2F..%2Fadd/query"
check 403 "reader: query string on get" "${R[@]}" "$API/collections/gwtest?x=1"
check 403 "reader: wrong method on query path" "${R[@]}" -X DELETE "$API/collections/$ID/query"
check 200 "writer: delete collection" "${W[@]}" -X DELETE "$API/collections/gwtest"
check 404 "after delete: get" "${W[@]}" "$API/collections/gwtest"

# Start-up guards: short token, equal tokens.
for case in short equal; do
  if [ "$case" = short ]; then r=abc; w="$WRITER"; else r="$WRITER"; w="$WRITER"; fi
  docker rm -f "$NET-bad" >/dev/null 2>&1
  gw_run "$NET-bad" "$r" "$w" >/dev/null 2>"$WORK/bad.err"; code=$?
  if [ "$code" -ne 0 ] && grep -q chroma-gateway "$WORK/bad.err"; then echo "PASS refuses to start: $case token(s) (exit $code)"
  else echo "FAIL started with $case token(s) (exit $code)"; fail=$((fail+1)); fi
done

# The tokens must not show up in the gateway's logs.
if docker logs "$NET-gw" 2>&1 | grep -q -e "$READER" -e "$WRITER"; then echo "FAIL token in gateway logs"; fail=$((fail+1))
else echo "PASS tokens absent from gateway logs"; fi

echo "---"; [ "$fail" -eq 0 ] && echo "ALL PASS" || echo "$fail FAILED"
exit "$fail"
