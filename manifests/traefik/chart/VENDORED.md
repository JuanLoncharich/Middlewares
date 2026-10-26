# Vendored chart — Traefik

Helm chart `traefik` **41.7.1** (Traefik v3.7.14, 2026-10-09), MIT,
from https://traefik.github.io/charts/traefik/traefik-41.7.1.tgz
(sha256 `f9edd5ca699ff0f5eab14df6e4feefa15f7597a9b56f0b1c01f6089b1eecbaf1`,
matches https://traefik.github.io/charts/index.yaml).

Unpacked verbatim except `Changelog.md` (610 KB, not needed to render).
Values: `../values-mcp-eval.yaml`. `deploy.sh` applies only the `traefik.io_*`
CRDs from `crds/` (no Traefik Hub, no Gateway API). Do not hand-edit;
re-vendor to upgrade.
