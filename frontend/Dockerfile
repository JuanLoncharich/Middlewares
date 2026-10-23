# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------- build
FROM node:22-bookworm-slim AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
COPY server ./server
RUN npm run build && npm prune --omit=dev

# -------------------------------------------------------------- runtime
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    HOME=/tmp \
    HOST=0.0.0.0 \
    PORT=8787
RUN groupadd -g 10003 ui && useradd -u 10003 -g 10003 -M -d /tmp -s /usr/sbin/nologin ui
WORKDIR /app
COPY --from=build --chown=10003:10003 /build/dist ./dist
COPY --from=build --chown=10003:10003 /build/node_modules ./node_modules
COPY --from=build --chown=10003:10003 /build/server ./server
COPY --from=build --chown=10003:10003 /build/src/model ./src/model
COPY --from=build --chown=10003:10003 /build/src/data/live.ts ./src/data/live.ts
COPY --chown=10003:10003 package.json ./
# /tmp is an emptyDir at runtime (tsx keeps its compile cache there).
USER 10003:10003
EXPOSE 8787
CMD ["node_modules/.bin/tsx", "server/live.ts"]
