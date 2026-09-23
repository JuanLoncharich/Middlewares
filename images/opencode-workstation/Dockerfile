# Programmer's workstation: OpenCode AI CLI routed through the
# security-gateway stack (occludra LLM egress proxy + vigil scanner).
FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates jq openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# OpenCode AI CLI
RUN npm install -g opencode-ai

# Non-root user (the base image's `node` user already owns uid 1000; replace
# it with `programmer` so the required name/uid pair is available).
RUN userdel --remove node \
    && useradd --create-home --shell /bin/bash --uid 1000 programmer

# Config template rewritten at container start by the entrypoint.
COPY opencode.json.template /home/programmer/.config/opencode/opencode.json.template
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && chown -R programmer:programmer /home/programmer/.config

USER programmer
WORKDIR /home/programmer

# Defaults use the NodePort services exposed by
# manifests/workstation-nodeport.yaml (kind node resolvable by name on the
# docker `kind` network; NetworkPolicy allow-nodeport-from-docker-workstations
# admits the docker bridge subnet).
# OCCLUDRA_BASE_URL must end in /v1.
ENV OCCLUDRA_BASE_URL=http://mcp-test-control-plane:30080/v1 \
    VIGIL_URL=http://mcp-test-control-plane:30500 \
    OPENCODE_API_KEY=egress-via-occludra

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
