#!/bin/sh
# Cloner & detector init container.
#
# Inputs (env):  REPO_URL (https:// only), REPO_REF (branch/tag/SHA, default main),
#                REPO_PATH (optional subdirectory), TRANSPORT (stdio|sse),
#                TARGET_PORT (default 8080), GIT_USERNAME / GIT_TOKEN (optional),
#                LAUNCH_CMD (optional explicit override, e.g. "node dist/index.js").
# Outputs:       /workspace/<clone>, /workspace/.mcp-launch.json,
#                FIFOs /ipc/stdin and /ipc/stdout.
set -eu

WORKSPACE="${WORKSPACE_DIR:-/workspace}"
IPC="${IPC_DIR:-/ipc}"
REPO_URL="${REPO_URL:-}"
REPO_REF="${REPO_REF:-main}"
REPO_PATH="${REPO_PATH:-}"
TRANSPORT="${TRANSPORT:-stdio}"
TARGET_PORT="${TARGET_PORT:-8080}"
LAUNCH_CMD="${LAUNCH_CMD:-}"
CLONE_DIR="$WORKSPACE/repo"
LAUNCH_FILE="$WORKSPACE/.mcp-launch.json"

log() { printf '[cloner] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------- validation
[ -n "$REPO_URL" ] || die "REPO_URL is required"
case "$REPO_URL" in
  https://*) ;;
  *) die "REPO_URL must use https:// (got: $REPO_URL)" ;;
esac
case "$REPO_REF" in
  -*) die "REPO_REF must not start with '-'" ;;
esac
case "$REPO_PATH" in
  /*|*..*) die "REPO_PATH must be relative and must not contain '..'" ;;
esac
case "$TRANSPORT" in
  stdio|sse) ;;
  *) die "TRANSPORT must be stdio or sse" ;;
esac
mkdir -p "$WORKSPACE" "$IPC" /tmp
[ -w "$WORKSPACE" ] || die "$WORKSPACE is not writable"
[ -w "$IPC" ] || die "$IPC is not writable"

# ------------------------------------------------------------------- clone
# Credentials are passed to git through an in-memory credential helper,
# configured via GIT_CONFIG_* environment variables (git >= 2.31), so the token
# never touches disk and never appears in git's argv.
if [ -n "${GIT_TOKEN:-}" ]; then
  export GIT_USERNAME="${GIT_USERNAME:-x-access-token}"
  export GIT_TOKEN
  export GIT_CONFIG_COUNT=2
  export GIT_CONFIG_KEY_0=credential.helper
  export GIT_CONFIG_VALUE_0=""
  export GIT_CONFIG_KEY_1=credential.helper
  export GIT_CONFIG_VALUE_1='!f() { echo "username=$GIT_USERNAME"; echo "password=$GIT_TOKEN"; }; f'
fi

log "cloning $REPO_URL @ $REPO_REF"
rm -rf "$CLONE_DIR"
if ! git -c advice.detachedHead=false clone --depth 1 --single-branch --branch "$REPO_REF" \
      --no-tags --recurse-submodules --shallow-submodules "$REPO_URL" "$CLONE_DIR" 2>/tmp/clone.err; then
  log "branch/tag clone failed ($(tail -n1 /tmp/clone.err 2>/dev/null || true)); trying as commit SHA"
  rm -rf "$CLONE_DIR"
  mkdir -p "$CLONE_DIR"
  git -C "$CLONE_DIR" init -q
    git -C "$CLONE_DIR" remote add origin "$REPO_URL"
    git -C "$CLONE_DIR" fetch --depth 1 --no-tags origin "$REPO_REF" || die "unable to fetch ref $REPO_REF"
  git -C "$CLONE_DIR" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
unset GIT_TOKEN GIT_USERNAME GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1
COMMIT="$(git -C "$CLONE_DIR" rev-parse HEAD)"
log "checked out $COMMIT"
# The target must not be able to fetch anything else through git metadata.
rm -rf "$CLONE_DIR/.git"

PROJECT_DIR="$CLONE_DIR"
if [ -n "$REPO_PATH" ]; then
  PROJECT_DIR="$CLONE_DIR/$REPO_PATH"
  [ -d "$PROJECT_DIR" ] || die "REPO_PATH $REPO_PATH does not exist in the repository"
fi
cd "$PROJECT_DIR"

# --------------------------------------------------------------- detection
RUNTIME="unknown"
CMD=""
ARGS='[]'
ENVJSON='{}'

json_escape() { printf '%s' "$1" | jq -Rs '.'; }

# Read a pre-existing launch descriptor shipped in the repository, if any.
if [ -f "$PROJECT_DIR/.mcp-launch.json" ] && [ -z "$LAUNCH_CMD" ]; then
  LAUNCH_CMD="$(jq -r '.cmd // empty' "$PROJECT_DIR/.mcp-launch.json" 2>/dev/null || true)"
  ARGS="$(jq -c '.args // []' "$PROJECT_DIR/.mcp-launch.json" 2>/dev/null || echo '[]')"
  [ -n "$LAUNCH_CMD" ] && log "using launch descriptor from repository: $LAUNCH_CMD"
fi

# ---- Node -----------------------------------------------------------------
if [ -f package.json ]; then
  RUNTIME="node"
  log "node project detected; installing dependencies (scripts disabled)"
  if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
    npm ci --ignore-scripts --include=dev 2>&1 | tail -n 5 >&2 || npm install --ignore-scripts --include=dev 2>&1 | tail -n 5 >&2
  else
    npm install --ignore-scripts --include=dev 2>&1 | tail -n 5 >&2
  fi
  if jq -e '.scripts.build' package.json >/dev/null 2>&1; then
    log "running build script"
    npm run build --ignore-scripts 2>&1 | tail -n 20 >&2 || log "build script failed; continuing with sources as-is"
  fi
  # Trim dev dependencies so the target has the smallest possible surface.
  npm prune --omit=dev --ignore-scripts >/dev/null 2>&1 || true
  if [ -z "$LAUNCH_CMD" ]; then
    BIN="$(jq -r 'if (.bin|type)=="string" then .bin elif (.bin|type)=="object" then (.bin|to_entries[0].value) else empty end' package.json)"
    MAIN="$(jq -r '.main // empty' package.json)"
    for candidate in "$BIN" "$MAIN" dist/index.js build/index.js lib/index.js index.js server.js src/index.js; do
      if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        LAUNCH_CMD="node $candidate"
        break
      fi
    done
    if [ -z "$LAUNCH_CMD" ] && [ -f src/index.ts ] && [ -x node_modules/.bin/tsx ]; then
      LAUNCH_CMD="node_modules/.bin/tsx src/index.ts"
    fi
  fi
  ENVJSON='{"NODE_ENV":"production","NODE_OPTIONS":"--max-old-space-size=768"}'

# ---- Python ---------------------------------------------------------------
elif [ -f pyproject.toml ] || [ -f requirements.txt ]; then
  RUNTIME="python"
  log "python project detected; creating venv"
  uv venv --quiet "$WORKSPACE/.venv"
  export VIRTUAL_ENV="$WORKSPACE/.venv"
  if [ -f pyproject.toml ]; then
    uv pip install --quiet . 2>&1 | tail -n 5 >&2 || uv pip install --quiet -r requirements.txt 2>&1 | tail -n 5 >&2 || true
  else
    uv pip install --quiet -r requirements.txt 2>&1 | tail -n 5 >&2 || true
  fi
  if [ -z "$LAUNCH_CMD" ] && [ -f pyproject.toml ]; then
    # First [project.scripts] entry → console script installed into the venv.
    SCRIPT="$(python3 - <<'PY' 2>/dev/null || true
import sys, tomllib
try:
    with open("pyproject.toml", "rb") as f:
        d = tomllib.load(f)
    s = d.get("project", {}).get("scripts", {})
    if s:
        print(next(iter(s.keys())))
except Exception:
    pass
PY
)"
    if [ -n "$SCRIPT" ] && [ -x "$WORKSPACE/.venv/bin/$SCRIPT" ]; then
      LAUNCH_CMD="$WORKSPACE/.venv/bin/$SCRIPT"
    fi
  fi
  if [ -z "$LAUNCH_CMD" ]; then
    for candidate in server.py main.py app.py src/server.py src/main.py; do
      if [ -f "$candidate" ]; then
        LAUNCH_CMD="$WORKSPACE/.venv/bin/python $candidate"
        break
      fi
    done
  fi
  if [ -z "$LAUNCH_CMD" ] && [ -f pyproject.toml ]; then
    MODULE="$(python3 -c 'import tomllib;d=tomllib.load(open("pyproject.toml","rb"));print(d.get("project",{}).get("name","").replace("-","_"))' 2>/dev/null || true)"
    [ -n "$MODULE" ] && LAUNCH_CMD="$WORKSPACE/.venv/bin/python -m $MODULE"
  fi
  ENVJSON="{\"VIRTUAL_ENV\":\"$WORKSPACE/.venv\",\"PYTHONUNBUFFERED\":\"1\",\"PYTHONDONTWRITEBYTECODE\":\"1\"}"

# ---- Go -------------------------------------------------------------------
elif [ -f go.mod ]; then
  RUNTIME="go"
  log "go project detected; building"
  mkdir -p "$WORKSPACE/.bin"
  PKG="."
  if [ ! -f main.go ]; then
    PKG="$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./... 2>/dev/null | head -n1 || true)"
    [ -n "$PKG" ] || PKG="."
  fi
  CGO_ENABLED=0 go build -trimpath -o "$WORKSPACE/.bin/server" "$PKG" 2>&1 | tail -n 20 >&2 || die "go build failed"
  [ -z "$LAUNCH_CMD" ] && LAUNCH_CMD="$WORKSPACE/.bin/server"

# ---- Rust -----------------------------------------------------------------
elif [ -f Cargo.toml ]; then
  RUNTIME="rust"
  log "rust project detected but no toolchain in this image; expecting LAUNCH_CMD or a prebuilt binary"
fi

[ -n "$LAUNCH_CMD" ] || die "could not determine how to launch the MCP server (runtime=$RUNTIME); set LAUNCH_CMD or ship .mcp-launch.json"

# ------------------------------------------------------------- launch file
jq -n \
  --arg runtime "$RUNTIME" \
  --arg cmd "$LAUNCH_CMD" \
  --argjson args "$ARGS" \
  --arg cwd "$PROJECT_DIR" \
  --arg transport "$TRANSPORT" \
  --argjson port "$TARGET_PORT" \
  --argjson env "$ENVJSON" \
  --arg commit "$COMMIT" \
  --arg repo "$REPO_URL" \
  --arg ref "$REPO_REF" \
  '{runtime:$runtime, cmd:$cmd, args:$args, cwd:$cwd, transport:$transport, port:$port, env:$env, source:{repositoryUrl:$repo, ref:$ref, commit:$commit}}' \
  > "$LAUNCH_FILE"

# ------------------------------------------------------------------- FIFOs
for f in stdin stdout; do
  rm -f "$IPC/$f"
  mkfifo -m 0660 "$IPC/$f"
done
chmod 0666 "$IPC/stdin" "$IPC/stdout" 2>/dev/null || true
: > "$IPC/crashes.jsonl"
: > "$IPC/target.log"
chmod 0666 "$IPC/crashes.jsonl" "$IPC/target.log" 2>/dev/null || true
# The target (uid 10002, gid 10001) must be able to traverse the tree.
chmod -R g+rX "$WORKSPACE" 2>/dev/null || true

log "launch descriptor:"
cat "$LAUNCH_FILE" >&2
log "done"
