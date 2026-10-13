#!/usr/bin/env bash
# Cloner regression tests in plain Docker (no cluster): the real cloner image
# clones from the test git server over HTTPS with a private CA.
#
#   test/cloner/clone-test.sh
#
# Cases: (1) custom CA via GIT_CA_PEM -> clone + launch file;
#        (2) same server without the CA -> must fail (proves the CA matters);
#        (3) unreachable host -> must fail with a clone error, not report
#            success and crash later (bounded() swallowed failures).
set -uo pipefail
cd "$(dirname "$0")/../.."
CLONER_IMG="${CLONER_IMG:-mcp-cloner:test}"
GIT_IMG="${GIT_IMG:-git-test-server:test}"
NET="clone-test-$$"
HOST="git-test.clone-test"
WORK="$(mktemp -d)"
cleanup() { docker rm -f "$NET-git" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

docker build -q -t "$CLONER_IMG" images/cloner >/dev/null || { echo "cloner build failed"; exit 2; }
docker build -q -f test/git-server/Dockerfile -t "$GIT_IMG" test >/dev/null || { echo "git server build failed"; exit 2; }

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -subj "/CN=clone-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/tls.key" -out "$WORK/tls.csr" -subj "/CN=$HOST" 2>/dev/null
openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
  -out "$WORK/tls.crt" -days 1 -extfile <(printf 'subjectAltName=DNS:%s' "$HOST") 2>/dev/null
chmod 644 "$WORK"/*

docker network create "$NET" >/dev/null
docker run -d --name "$NET-git" --network "$NET" --network-alias "$HOST" --user 1000:1000 \
  -v "$WORK:/etc/git-server:ro" -e GIT_SERVER_TLS_CERT=/etc/git-server/tls.crt \
  -e GIT_SERVER_TLS_KEY=/etc/git-server/tls.key "$GIT_IMG" >/dev/null
sleep 2

clone() { # extra docker args...; prints cloner output, returns its exit code
  docker run --rm --network "$NET" --user 10001:10001 --read-only \
    --tmpfs /workspace:uid=10001,gid=10001 --tmpfs /ipc:uid=10001,gid=10001 \
    --tmpfs /tmp:uid=10001,gid=10001,mode=1777 \
    -e REPO_REF=main -e TRANSPORT=stdio -e OP_RETRIES=1 -e OP_TIMEOUT_SECONDS=20 \
    "$@" --entrypoint sh "$CLONER_IMG" -c '/usr/local/bin/clone.sh && cat /workspace/.mcp-launch.json' 2>&1
}

rc=0
echo "== (1) private CA via GIT_CA_PEM"
out="$(clone -e REPO_URL="https://$HOST:5443/mcp-benign-demo.git" -e GIT_CA_PEM="$(cat "$WORK/ca.crt")")"; code=$?
if [ "$code" = 0 ] && grep -q '"cmd"' <<<"$out"; then echo "  ok"; else echo "  FAIL (exit $code)"; tail -5 <<<"$out"; rc=1; fi

echo "== (2) same server without the CA must fail"
out="$(clone -e REPO_URL="https://$HOST:5443/mcp-benign-demo.git")"; code=$?
if [ "$code" != 0 ] && grep -qi 'certificate' <<<"$out"; then echo "  ok"; else echo "  FAIL (exit $code)"; tail -5 <<<"$out"; rc=1; fi

echo "== (3) unreachable host fails as a clone error"
out="$(clone -e REPO_URL="https://nonexistent.clone-test/x.git")"; code=$?
if [ "$code" != 0 ] && grep -q 'unable to fetch ref' <<<"$out" && ! grep -q 'cannot change to' <<<"$out"; then
  echo "  ok"
else echo "  FAIL (exit $code)"; tail -5 <<<"$out"; rc=1; fi

[ "$rc" = 0 ] && echo PASS || echo FAILED
exit "$rc"
