# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------- build
FROM node:22-bookworm-slim AS build
WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# -------------------------------------------------------------- runtime
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_DATA_HOME=/tmp/.local/share \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_STATE_HOME=/tmp/.local/state \
    OPENCODE_DISABLE_AUTOUPDATE=1 \
    OPENCODE_DISABLE_WATCHER=1 \
    OPENCODE_DISABLE_LSP_DOWNLOAD=1 \
    LOG_LEVEL=info

# The SDK spawns `opencode serve`; install the CLI globally at build time so
# the runtime image needs no network to boot an OpenCode server.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g --no-audit --no-fund opencode-ai@latest \
 && npm cache clean --force \
 && groupadd -g 10001 evaluator \
 && useradd -u 10001 -g 10001 -M -d /tmp -s /usr/sbin/nologin evaluator

WORKDIR /app
COPY --from=build --chown=10001:10001 /build/dist ./dist
COPY --from=build --chown=10001:10001 /build/node_modules ./node_modules
COPY --chown=10001:10001 package.json ./

# Writable paths are provided by emptyDir volumes at runtime (/tmp, /ipc, /output).
USER 10001:10001
CMD ["node", "dist/evaluator.js"]
