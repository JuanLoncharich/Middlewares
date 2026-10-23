#!/usr/bin/env bash
# Node memory protection for the university k0s cluster: kubelet reserves and
# eviction thresholds (worker-profiles.yaml), so Kubernetes evicts a pod
# before a VM runs out of memory and hangs.
#
#   deploy/k0s-nodes/apply.sh plan       # read-only: current state + validates the new config
#   deploy/k0s-nodes/apply.sh apply      # controller first, then each worker, one at a time
#   deploy/k0s-nodes/apply.sh rollback   # back to the k0s defaults
#
# Runs where the SSH key for ubuntu@<node> lives (the laptop). From another
# machine, hop through it: JUMP=10.147.19.139 deploy/k0s-nodes/apply.sh plan
#
# What apply changes, per node (all reversible with rollback):
#  - controller (nodo-g1-2): /etc/k0s/k0s.yaml gets spec.workerProfiles (a
#    backup is kept next to it), and a systemd drop-in starts k0s with
#    --profile=control-plane and its taint relaxed to PreferNoSchedule, so the
#    scheduler uses it only when the workers are full. The live taint is
#    switched too (taints are only read when a node registers).
#  - workers: a systemd drop-in starts k0s with --profile=protected.
# k0s units use KillMode=process: restarting k0s restarts the kubelet but not
# the running containers. Restarting the (single) controller makes the API
# unavailable for ~1 minute; workloads keep running.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

JUMP="${JUMP:-}"
SSH_USER="${SSH_USER:-ubuntu}"
CONTROLLER="${CONTROLLER:-nodo-g1-2=10.66.50.59}"
WORKERS="${WORKERS:-nodo-g1-1=10.66.50.249 nodo-g1-3=10.66.50.25}"
CP_TAINT=node-role.kubernetes.io/control-plane
DROPIN=10-mcp-eval-profile.conf

log()  { printf '\033[1;34m[k0s-nodes]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[k0s-nodes] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[k0s-nodes] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# The script that runs as root on a node, fed on stdin: remote <ip> <command> [args...]
read -r -d '' REMOTE <<'NODE' || true
set -Eeuo pipefail
cmd="$1"; shift
cfg=/etc/k0s/k0s.yaml

merged_config() {  # stdout: k0s.yaml with spec.workerProfiles replaced by $1 (base64)
  python3 - "$1" <<'PY'
import base64, sys, yaml
cfg = yaml.safe_load(open("/etc/k0s/k0s.yaml"))
cfg.setdefault("spec", {})["workerProfiles"] = yaml.safe_load(base64.b64decode(sys.argv[1]))
sys.stdout.write(yaml.safe_dump(cfg, sort_keys=False))
PY
}

base_execstart() {  # the unit's own ExecStart, without any drop-in
  grep -m1 '^ExecStart=' "/etc/systemd/system/$1.service" | sed 's/^ExecStart=//'
}

wait_api() {
  for _ in $(seq 60); do
    k0s kubectl get --raw /readyz >/dev/null 2>&1 && return 0
    sleep 5
  done
  echo "API server not ready after 5 minutes" >&2; return 1
}

case "$cmd" in
  show)
    unit="$1"
    echo "  host:      $(hostname)"
    echo "  ExecStart: $(base_execstart "$unit")"
    if [ -f "/etc/systemd/system/$unit.service.d/__DROPIN__" ]; then
      echo "  drop-in:   $(grep '^ExecStart=.' "/etc/systemd/system/$unit.service.d/__DROPIN__" | sed 's/^ExecStart=//')"
    else
      echo "  drop-in:   none (k0s default profile)"
    fi
    free -m | awk 'NR==2 {print "  memory:    " $2 " MiB total, " $7 " MiB available"}'
    ;;
  validate)
    merged_config "$1" | k0s config validate --config - && echo "  new k0s.yaml validates"
    ;;
  config)
    new="$(merged_config "$1")"
    printf '%s\n' "$new" | k0s config validate --config -
    if cmp -s <(printf '%s\n' "$new") "$cfg"; then
      echo "  $cfg already holds these profiles"
    else
      bak="$cfg.bak-$(date +%Y%m%d-%H%M%S)"
      cp -p "$cfg" "$bak"
      printf '%s\n' "$new" > "$cfg"
      echo "  $cfg updated (previous one: $bak)"
    fi
    ;;
  unit)  # unit <k0scontroller|k0sworker> <extra flags...>
    unit="$1"; shift
    base="$(base_execstart "$unit")"
    case "$base" in *--profile*) echo "the base unit already passes --profile; edit it by hand" >&2; exit 1 ;; esac
    mkdir -p "/etc/systemd/system/$unit.service.d"
    cat > "/etc/systemd/system/$unit.service.d/__DROPIN__" <<EOF
# Managed by deploy/k0s-nodes/apply.sh (Middlewares repo): kubelet memory
# protection. Remove this file and restart $unit to go back to the defaults.
[Service]
ExecStart=
ExecStart=$base $*
EOF
    systemctl daemon-reload
    systemctl restart "$unit"
    echo "  $unit restarted with: $*"
    ;;
  unit-rollback)
    unit="$1"
    if [ -f "/etc/systemd/system/$unit.service.d/__DROPIN__" ]; then
      rm -f "/etc/systemd/system/$unit.service.d/__DROPIN__"
      systemctl daemon-reload
      systemctl restart "$unit"
      echo "  drop-in removed, $unit restarted"
    else
      echo "  no drop-in on this node"
    fi
    ;;
  config-rollback)
    bak="$(ls -1t "$cfg".bak-* 2>/dev/null | tail -1 || true)"
    if [ -n "$bak" ]; then
      cp -p "$bak" "$cfg"
      echo "  $cfg restored from $bak (the oldest backup: the pre-apply config)"
    else
      echo "  no backup of $cfg found; left as is"
    fi
    ;;
  wait-api) wait_api ;;
  kubectl) wait_api; k0s kubectl "$@" ;;
  check-node)  # check-node <node> <expected memory.available hard threshold>
    node="$1"; want="$2"
    for _ in $(seq 60); do
      got="$(k0s kubectl get --raw "/api/v1/nodes/$node/proxy/configz" 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["kubeletconfig"]["evictionHard"]["memory.available"])' 2>/dev/null || true)"
      ready="$(k0s kubectl get node "$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
      if [ "$got" = "$want" ] && [ "$ready" = True ]; then
        echo "  $node Ready, kubelet evictionHard memory.available=$got, allocatable memory $(k0s kubectl get node "$node" -o jsonpath='{.status.allocatable.memory}')"
        exit 0
      fi
      sleep 5
    done
    echo "$node: kubelet not on the new profile after 5 minutes (Ready=$ready, evictionHard memory.available=$got)" >&2
    exit 1
    ;;
  *) echo "unknown remote command $cmd" >&2; exit 2 ;;
esac
NODE
REMOTE="${REMOTE//__DROPIN__/$DROPIN}"

# on <ip> <command> [args...]: run $REMOTE as root on the node.
on() {
  local ip="$1"; shift
  local remote="sudo bash -s -- $*"
  if [ -n "$JUMP" ]; then
    ssh -o ConnectTimeout=15 "$JUMP" "ssh -o ConnectTimeout=20 $SSH_USER@$ip '$remote'" <<<"$REMOTE"
  else
    ssh -o ConnectTimeout=20 "$SSH_USER@$ip" "$remote" <<<"$REMOTE"
  fi
}

name() { echo "${1%%=*}"; }
ip()   { echo "${1#*=}"; }
PROFILES_B64="$(base64 -w0 < "$HERE/worker-profiles.yaml")"
CIP="$(ip "$CONTROLLER")"; CNAME="$(name "$CONTROLLER")"

hard_threshold() {  # the profile's evictionHard memory.available, as the kubelet reports it
  awk -v want="$1" '
    /^- name:/ { inp = ($3 == want) }
    inp && /evictionHard:/ { inh = 1; next }
    inp && inh && /memory.available:/ { print $2; exit }
  ' "$HERE/worker-profiles.yaml"
}

plan() {
  log "controller $CNAME ($CIP)"
  on "$CIP" show k0scontroller
  on "$CIP" validate "$PROFILES_B64"
  for w in $WORKERS; do
    log "worker $(name "$w") ($(ip "$w"))"
    on "$(ip "$w")" show k0sworker
  done
  log "current taints and allocatable memory"
  on "$CIP" kubectl get nodes -o custom-columns=NODE:.metadata.name,ALLOCATABLE:.status.allocatable.memory,TAINTS:.spec.taints[*].effect
}

apply() {
  [ -n "$(hard_threshold protected)" ] && [ -n "$(hard_threshold control-plane)" ] \
    || die "worker-profiles.yaml: no evictionHard memory.available for both profiles"
  log "controller $CNAME: worker profiles into k0s.yaml"
  on "$CIP" config "$PROFILES_B64"
  log "controller $CNAME: restart with --profile=control-plane, taint PreferNoSchedule (API down ~1 min)"
  on "$CIP" unit k0scontroller --profile=control-plane --no-taints "--taints=$CP_TAINT=:PreferNoSchedule"
  on "$CIP" wait-api
  on "$CIP" kubectl taint node "$CNAME" "$CP_TAINT:NoSchedule-" >/dev/null 2>&1 || true
  on "$CIP" kubectl taint node "$CNAME" "$CP_TAINT=:PreferNoSchedule" --overwrite
  on "$CIP" check-node "$CNAME" "$(hard_threshold control-plane)"
  for w in $WORKERS; do
    log "worker $(name "$w"): restart with --profile=protected"
    on "$(ip "$w")" unit k0sworker --profile=protected
    on "$CIP" check-node "$(name "$w")" "$(hard_threshold protected)"
  done
  log "done. Allocatable memory now:"
  on "$CIP" kubectl get nodes -o custom-columns=NODE:.metadata.name,ALLOCATABLE:.status.allocatable.memory,TAINTS:.spec.taints[*].effect
}

rollback() {
  for w in $WORKERS; do
    log "worker $(name "$w"): back to the default profile"
    on "$(ip "$w")" unit-rollback k0sworker
  done
  log "controller $CNAME: back to the default profile and NoSchedule taint"
  on "$CIP" config-rollback
  on "$CIP" unit-rollback k0scontroller
  on "$CIP" wait-api
  on "$CIP" kubectl taint node "$CNAME" "$CP_TAINT:PreferNoSchedule-" >/dev/null 2>&1 || true
  on "$CIP" kubectl taint node "$CNAME" "$CP_TAINT=:NoSchedule" --overwrite
}

case "${1:-}" in
  plan) plan ;;
  apply) apply ;;
  rollback) rollback ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
