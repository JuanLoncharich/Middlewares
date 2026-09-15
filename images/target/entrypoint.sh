#!/bin/sh
# Supervisor for the untrusted MCP server.
#
# IPC contract with the evaluator:
#   stdio : server stdin  <- $IPC_DIR/stdin  (FIFO, evaluator writes)
#           server stdout -> $IPC_DIR/stdout (FIFO, evaluator reads)
#   sse   : server listens on 127.0.0.1:$MCP_PORT (same Pod network namespace)
#   both  : stderr        -> $IPC_DIR/target.log
#           each crash    -> one JSON line appended to $IPC_DIR/crashes.jsonl
#           $IPC_DIR/done -> written by the evaluator; supervisor exits 0
#
# Restarts the server after a crash so the evaluator can reconnect and keep
# fuzzing; never exits non-zero because of the server (the evaluator decides
# the verdict). This container has no credentials, no CA bundle, and no
# network egress by policy.
set -u

IPC="${IPC_DIR:-/ipc}"
LAUNCH="${LAUNCH_FILE:-/workspace/.mcp-launch.json}"
TRANSPORT="${MCP_TRANSPORT:-stdio}"
PORT="${MCP_PORT:-8080}"
DONE="$IPC/done"
LOG="$IPC/target.log"
CRASHES="$IPC/crashes.jsonl"
MAX_RESTARTS="${MAX_RESTARTS:-50}"
RESTART_DELAY="${RESTART_DELAY:-1}"

log() { printf '[target-supervisor] %s\n' "$*" >>"$LOG" 2>/dev/null || printf '[target-supervisor] %s\n' "$*" >&2; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

if [ ! -f "$LAUNCH" ]; then
  log "launch file $LAUNCH missing; nothing to run"
  # Wait for the evaluator to finish anyway so the Job does not fail early.
  while [ ! -e "$DONE" ]; do sleep 2; done
  exit 0
fi

CMD="$(jq -r '.cmd' "$LAUNCH")"
CWD="$(jq -r '.cwd // "/workspace"' "$LAUNCH")"
EXTRA_ARGS="$(jq -r '(.args // []) | map(@sh) | join(" ")' "$LAUNCH")"
TRANSPORT="$(jq -r --arg d "$TRANSPORT" '.transport // $d' "$LAUNCH")"
PORT="$(jq -r --arg d "$PORT" '(.port // $d) | tostring' "$LAUNCH")"

# Environment declared by the cloner (VIRTUAL_ENV, NODE_ENV, ...).
jq -r '(.env // {}) | to_entries[] | select(.key|test("^[A-Za-z_][A-Za-z0-9_]*$")) | "\(.key)=\(.value|@sh)"' "$LAUNCH" \
  | while IFS= read -r kv; do printf '%s\n' "$kv"; done >/tmp/.launch-env
while IFS= read -r kv; do
  [ -n "$kv" ] && eval "export $kv"
done </tmp/.launch-env
rm -f /tmp/.launch-env
export PATH="/workspace/.venv/bin:/workspace/.bin:$CWD/node_modules/.bin:/workspace/repo/node_modules/.bin:/usr/local/bin:/usr/bin:/bin"
export HOME=/tmp
export PORT="$PORT" MCP_PORT="$PORT" MCP_HOST=127.0.0.1 HOST=127.0.0.1
export MCP_TRANSPORT="$TRANSPORT"

cd "$CWD" 2>/dev/null || cd /workspace

log "supervisor start transport=$TRANSPORT cmd='$CMD $EXTRA_ARGS' cwd=$CWD"

record_crash() {
  code="$1"
  sig=""
  if [ "$code" -gt 128 ] 2>/dev/null; then
    sig="$(kill -l $((code - 128)) 2>/dev/null || echo "")"
  fi
  printf '{"ts":"%s","exitCode":%s,"signal":"%s","restart":%s}\n' "$(now)" "$code" "$sig" "$restarts" >>"$CRASHES"
}

restarts=0
child=""

# Forward SIGTERM to the child and exit cleanly.
on_term() {
  log "SIGTERM received; stopping server"
  if [ -n "$child" ]; then kill -TERM "$child" 2>/dev/null; fi
  exit 0
}
trap on_term TERM INT

while :; do
  if [ -e "$DONE" ]; then
    log "done sentinel present; exiting"
    exit 0
  fi
  if [ "$restarts" -ge "$MAX_RESTARTS" ]; then
    log "restart limit ($MAX_RESTARTS) reached; waiting for evaluator"
    while [ ! -e "$DONE" ]; do sleep 2; done
    exit 0
  fi

  case "$TRANSPORT" in
    stdio)
      # Opening the FIFOs blocks until the evaluator opens the other ends; that
      # is the intended rendezvous. Each restart re-opens them, which the
      # evaluator handles by reconnecting.
      log "starting server (attempt $((restarts + 1))) on stdio FIFOs"
      sh -c "exec $CMD $EXTRA_ARGS" <"$IPC/stdin" >"$IPC/stdout" 2>>"$LOG" &
      child=$!
      ;;
    sse)
      log "starting server (attempt $((restarts + 1))) on 127.0.0.1:$PORT"
      sh -c "exec $CMD $EXTRA_ARGS" </dev/null >>"$LOG" 2>&1 &
      child=$!
      ;;
    *)
      log "unknown transport $TRANSPORT"
      while [ ! -e "$DONE" ]; do sleep 2; done
      exit 0
      ;;
  esac

  # Poll for the done sentinel while the child runs so an evaluator that
  # finishes (or is killed) always releases this container.
  while kill -0 "$child" 2>/dev/null; do
    if [ -e "$DONE" ]; then
      log "done sentinel present; terminating server"
      kill -TERM "$child" 2>/dev/null
      sleep 1
      kill -KILL "$child" 2>/dev/null
      wait "$child" 2>/dev/null
      exit 0
    fi
    sleep 1
  done
  wait "$child"
  code=$?
  child=""

  if [ -e "$DONE" ]; then
    log "server exited ($code) after done sentinel; exiting"
    exit 0
  fi
  log "server exited with code $code; recording crash"
  record_crash "$code"
  restarts=$((restarts + 1))
  sleep "$RESTART_DELAY"
done
