# syntax=docker/dockerfile:1.7
# Init container: shallow-clones the target repository, installs its
# dependencies and writes /workspace/.mcp-launch.json for the target container.
FROM golang:1.22-alpine AS golang

FROM alpine:3.20
RUN apk add --no-cache git jq ca-certificates nodejs npm python3 py3-pip bash \
 && pip3 install --no-cache-dir --break-system-packages uv \
 && addgroup -g 10001 cloner \
 && adduser -u 10001 -G cloner -h /tmp -s /sbin/nologin -D cloner
COPY --from=golang /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    HOME=/tmp \
    GOPATH=/tmp/go \
    GOCACHE=/tmp/go-cache \
    GOMODCACHE=/tmp/go-mod \
    GOFLAGS=-mod=mod \
    GOTOOLCHAIN=local \
    NPM_CONFIG_CACHE=/tmp/npm-cache \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_PYTHON_PREFERENCE=only-system \
    PIP_NO_CACHE_DIR=1 \
    GIT_TERMINAL_PROMPT=0
COPY clone.sh /usr/local/bin/clone.sh
RUN chmod 0755 /usr/local/bin/clone.sh
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/clone.sh"]
