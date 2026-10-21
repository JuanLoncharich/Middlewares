# Sourced by tests that need a real Chroma behind the real chroma-gateway, in
# Docker. Images, nginx template and start-up script come from the manifests
# (manifests/chroma/gateway.yaml, single.yaml); containers run like the pods
# (read-only root, non-root uid).
#
#   source test/chroma/lib.sh
#   chroma_gw_up "$WORK"      # sets CHROMA_GW_URL, CHROMA_READER, CHROMA_WRITER (random, never print them)
#   gw_run <name> <reader> <writer> [docker run flags...]   # another gateway on the same network
#   chroma_gw_down            # also registered on EXIT by chroma_gw_up
#
# Needs docker, openssl, python3 with PyYAML (a venv is made if missing).

CHROMA_GW_NET="chroma-gw-test-$$"

chroma_gw_down() {
  docker rm -f "$CHROMA_GW_NET-chroma" "$CHROMA_GW_NET-gw" "$CHROMA_GW_NET-bad" >/dev/null 2>&1
  docker network rm "$CHROMA_GW_NET" >/dev/null 2>&1
  return 0
}

gw_run() {
  local name="$1" r="$2" w="$3"; shift 3
  CHROMA_READER_TOKEN="$r" CHROMA_WRITER_TOKEN="$w" docker run "$@" --name "$name" --network "$CHROMA_GW_NET" \
    --read-only --user 101:101 --tmpfs /etc/nginx/conf.d:uid=101 --tmpfs /tmp:uid=101 \
    -v "$CHROMA_GW_WORK/templates:/etc/nginx/templates:ro" \
    -e CHROMA_UPSTREAM=chroma-up:8000 -e CHROMA_READER_TOKEN -e CHROMA_WRITER_TOKEN \
    --entrypoint /bin/sh "$CHROMA_GW_IMAGE" -c "$(cat "$CHROMA_GW_WORK/gw-script")"
}

chroma_gw_up() {
  CHROMA_GW_WORK="$1"
  local root; root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  CHROMA_PY=python3
  if ! python3 -c 'import yaml' 2>/dev/null; then
    python3 -m venv "$CHROMA_GW_WORK/venv" && "$CHROMA_GW_WORK/venv/bin/pip" install -q pyyaml \
      || { echo "need PyYAML (python3 -m venv + pip failed)" >&2; return 2; }
    CHROMA_PY="$CHROMA_GW_WORK/venv/bin/python3"
  fi
  mkdir -p "$CHROMA_GW_WORK/templates"
  "$CHROMA_PY" - "$root/manifests/chroma/gateway.yaml" "$root/manifests/chroma/single.yaml" "$CHROMA_GW_WORK" <<'PYEOF' || return 1
import sys, yaml
gw = list(yaml.safe_load_all(open(sys.argv[1])))
single = list(yaml.safe_load_all(open(sys.argv[2])))
work = sys.argv[3]
cm = next(d for d in gw if d["kind"] == "ConfigMap")
open(f"{work}/templates/default.conf.template", "w").write(cm["data"]["default.conf.template"])
c = next(d for d in gw if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
open(f"{work}/gw-image", "w").write(c["image"])
open(f"{work}/gw-script", "w").write(c["args"][0])
s = next(d for d in single if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
open(f"{work}/chroma-image", "w").write(s["image"])
PYEOF
  CHROMA_GW_IMAGE="$(cat "$CHROMA_GW_WORK/gw-image")"
  chmod -R a+rX "$CHROMA_GW_WORK/templates"
  trap chroma_gw_down EXIT

  CHROMA_READER="$(openssl rand -hex 32)"; CHROMA_WRITER="$(openssl rand -hex 32)"
  docker network create "$CHROMA_GW_NET" >/dev/null || return 2
  docker run -d --name "$CHROMA_GW_NET-chroma" --network "$CHROMA_GW_NET" --network-alias chroma-up \
    --memory=512m --read-only --tmpfs /data:uid=65534 --tmpfs /tmp --user 65534:65534 \
    "$(cat "$CHROMA_GW_WORK/chroma-image")" run --path /data --host 0.0.0.0 --port 8000 >/dev/null || return 2
  gw_run "$CHROMA_GW_NET-gw" "$CHROMA_READER" "$CHROMA_WRITER" -d >/dev/null || return 2
  local ip; ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$CHROMA_GW_NET\").IPAddress}}" "$CHROMA_GW_NET-gw")"
  CHROMA_GW_URL="http://$ip:8080"
  for _ in $(seq 1 60); do
    [ "$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "$CHROMA_GW_URL/api/v2/heartbeat")" = 200 ] && return 0
    docker ps -q -f "name=^$CHROMA_GW_NET-gw$" | grep -q . || break
    sleep 1
  done
  docker logs "$CHROMA_GW_NET-gw" 2>&1 | tail -5 >&2
  echo "chroma-gateway did not come up" >&2
  return 1
}
