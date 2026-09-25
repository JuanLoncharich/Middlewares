#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Keep the kind cluster from auto-starting at boot.
#
# Why: docker.service is enabled on the host, so every container with a
# restart policy comes back when the daemon starts. kind creates its node
# containers with `--restart=on-failure` — and since a node container exits
# 137 (SIGKILL) at shutdown, the whole cluster silently boots with the
# machine. The local registry (kind docs convention) is usually created with
# `--restart=always`, same story.
#
# This sets every kind-managed container's policy to `no`: containers only
# run when you explicitly start them (docker start / kind create). The
# setting persists in Docker's own store, but re-run this after recreating
# the cluster (kind re-applies on-failure on creation).
#
#   hack/disable-cluster-autostart.sh
# ---------------------------------------------------------------------------
set -euo pipefail

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }

# Kind node containers carry the cluster label; the registry follows the
# kind docs naming convention.
TARGETS=$(docker ps -aq --filter "label=io.x-k8s.kind.cluster")
REGISTRY=$(docker ps -aq --filter "name=kind-registry")
ALL=$(printf '%s\n%s' "$TARGETS" "$REGISTRY" | sed '/^$/d' | sort -u)

if [ -z "$ALL" ]; then
  echo "No kind cluster or registry containers found — nothing to do."
  exit 0
fi

log "Setting restart policy to 'no' on:"
docker ps -a --filter "label=io.x-k8s.kind.cluster" --filter "name=kind-registry" \
  --format '  {{.Names}} (was: {{.Status}})'

# shellcheck disable=SC2086
docker update --restart=no $ALL >/dev/null

log "Result:"
for c in $ALL; do
  echo "  $(docker inspect -f '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}}' "$c")"
done
log "The cluster will only start when you start it (docker start <node>)."
