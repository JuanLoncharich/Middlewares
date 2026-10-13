# syntax=docker/dockerfile:1.7
# In-cluster HTTPS git server holding the two evaluation fixture repos
# (mcp-benign-demo / mcp-evil-demo). TEST-ONLY: dumb trust model, static
# content, no auth — never exposed outside the cluster (NetworkPolicy in
# test/git-server.yaml limits ingress to the evaluation namespace).
FROM alpine:3.20
# git-http-backend (smart HTTP) ships in git-daemon on Alpine, not in git.
RUN apk add --no-cache git git-daemon python3
# Build context is test/ (the fixtures live in test/mcp-servers):
#   docker build -f test/git-server/Dockerfile test/
COPY git-server/server.py /usr/local/bin/git-test-server.py
COPY mcp-servers/mcp-benign-demo/ /tmp/src/mcp-benign-demo/
COPY mcp-servers/mcp-evil-demo/ /tmp/src/mcp-evil-demo/
# Build bare repos and generate the dumb-protocol metadata; serving is smart
# HTTP (server.py bridges git-http-backend) so `clone --depth 1` works.
RUN set -eux; \
    git config --global user.email "fixture@example.invalid"; \
    git config --global user.name "fixture"; \
    for name in mcp-benign-demo mcp-evil-demo; do \
      git -C "/tmp/src/$name" init -q; \
      git -C "/tmp/src/$name" add -A; \
      git -C "/tmp/src/$name" commit -qm "fixture: $name"; \
      git init -q --bare "/repos/$name.git"; \
      git -C "/tmp/src/$name" push -q "/repos/$name.git" HEAD:main; \
      git -C "/repos/$name.git" update-server-info; \
    done; \
    rm -rf /tmp/src; \
    # The pod runs as UID/GID 1000 (test/git-server.yaml). git refuses to serve
    # repositories owned by another user ("dubious ownership"), so hand them
    # over instead of disabling that check with safe.directory=*.
    chown -R 1000:1000 /repos
ENV GIT_REPOS_ROOT=/repos \
    GIT_SERVER_PORT=5443
EXPOSE 5443
ENTRYPOINT ["python3", "/usr/local/bin/git-test-server.py"]
