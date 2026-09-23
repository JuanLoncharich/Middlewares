#!/bin/sh
# Rewrite the OpenCode config with the runtime URLs, optionally start sshd
# (SSH_PASSWORD auth for the single `programmer` user), then idle.
#
# Two start modes:
#   default (--user programmer): CLI only; reach it with `docker exec`.
#   --user root: sshd is started on :22 (publish with -p 2222:22), then the
#   shell drops back to uid 1000 before idling. Root login stays disabled.
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

if [ "$(id -u)" = "0" ]; then
  chown -R programmer:programmer "$CONFIG_DIR"
  [ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
  printf 'programmer:%s\n' "${SSH_PASSWORD:-programmer}" | chpasswd
  sed -i \
    -e 's|^#\?PasswordAuthentication.*|PasswordAuthentication yes|' \
    -e 's|^#\?PermitRootLogin.*|PermitRootLogin no|' \
    /etc/ssh/sshd_config
  /usr/sbin/sshd
  echo "[entrypoint] sshd up on :22 (user programmer; password: \$SSH_PASSWORD or 'programmer')" >&2
  # Continue idling as the programmer user, not root.
  exec setpriv --reuid=1000 --regid=1000 --init-groups \
    env HOME=/home/programmer USER=programmer sleep infinity
fi

echo "[entrypoint] started as uid $(id -u); sshd not started (docker run --user root to enable SSH)" >&2
exec sleep infinity
