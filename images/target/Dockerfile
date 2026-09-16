# syntax=docker/dockerfile:1.7
# Sandbox image for the UNTRUSTED MCP server.
#
# Defence in depth on top of the Pod securityContext + NetworkPolicy:
#   * no package manager caches, no compilers, no git, no curl/wget
#   * CA certificate bundle removed: even if egress were reachable, TLS to any
#     public endpoint fails at trust verification
#   * non-root uid 10002 (distinct from the evaluator), gid 10001 (shares the
#     Pod fsGroup so it can read /workspace and the FIFOs in /ipc)
#   * the only entrypoint is the supervisor, which binds stdio to the IPC FIFOs
FROM node:22-bookworm-slim AS node

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv jq procps \
 && apt-get purge -y --auto-remove ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/ssl/certs/* /usr/share/ca-certificates \
 && groupadd -g 10001 sandbox \
 && useradd -u 10002 -g 10001 -M -d /tmp -s /usr/sbin/nologin target
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
 && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
ENV HOME=/tmp \
    LAUNCH_FILE=/workspace/.mcp-launch.json \
    IPC_DIR=/ipc \
    MCP_TRANSPORT=stdio \
    MCP_PORT=8080 \
    NODE_OPTIONS=--max-old-space-size=768 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NO_COLOR=1
USER 10002:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
