#!/bin/sh
# Rewrite the OpenCode config template with the runtime URLs, then idle.
set -eu

OCCLUDRA_BASE_URL="${OCCLUDRA_BASE_URL:-http://mcp-test-control-plane:30080/v1}"
VIGIL_URL="${VIGIL_URL:-http://mcp-test-control-plane:30500}"
export OPENCODE_API_KEY="${OPENCODE_API_KEY:-egress-via-occludra}"

CONFIG_DIR="${HOME:-/home/programmer}/.config/opencode"
mkdir -p "$CONFIG_DIR"

sed \
  -e "s|__OCCLUDRA_BASE_URL__|${OCCLUDRA_BASE_URL}|g" \
  -e "s|__VIGIL_URL__|${VIGIL_URL}|g" \
  "$CONFIG_DIR/opencode.json.template" > "$CONFIG_DIR/opencode.json"

chmod 600 "$CONFIG_DIR/opencode.json"

exec sleep infinity
