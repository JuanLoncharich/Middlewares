#!/usr/bin/env bash
# Create the Secrets a Flux-managed cluster needs. They never go to git, so
# run this once per cluster (and again to rotate a key):
#
#   CONTEXT=k0s LOCAL_LLM_API_KEY="$(cat ~/.config/mcp-eval/local-llm.key)" hack/gitops/secrets.sh deploy/k0s
#   CONTEXT=k0s NVIDIA_API_KEY=... hack/gitops/secrets.sh deploy/k0s     # with LLM_PROVIDER=nvidia in render.env
#
# Writes, only when missing unless noted:
#   security-gateways/llm-provider-credentials   the upstream key Occludra sends (always rewritten)
#   mcp-evals/llm-provider-credentials           a placeholder: the evaluator never holds the key
#   chroma/chroma-auth                           random reader/writer tokens
#   security-gateways/chroma-reader              copy of the reader token, for Vigil
#   chroma/minio-credentials                     the fixed MinIO profile from manifests/chroma/minio.yaml
# Key values travel through pipes only: never on argv, never printed.
set -euo pipefail
cd "$(dirname "$0")/../.."

dir="${1:?usage: secrets.sh <cluster dir, e.g. deploy/k0s>}"
k() { kubectl ${CONTEXT:+--context "$CONTEXT"} "$@"; }
LLM_PROVIDER="$(. "$dir/render.env"; echo "${LLM_PROVIDER:-zen}")"

for ns in chroma security-gateways mcp-evals; do
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null
done

gateway_env() {
  case "$LLM_PROVIDER" in
    nvidia) printf 'UPSTREAM_API_KEY=%s\n' "${NVIDIA_API_KEY:?set NVIDIA_API_KEY}" ;;
    local)  [ -z "${LOCAL_LLM_API_KEY:-}" ] || printf 'UPSTREAM_API_KEY=%s\n' "$LOCAL_LLM_API_KEY" ;;
    zen)    printf 'OPENCODE_API_KEY=%s\n' "${OPENCODE_API_KEY:?set OPENCODE_API_KEY}"
            [ -z "${ANTHROPIC_API_KEY:-}" ] || printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY" ;;
  esac
}
k -n security-gateways create secret generic llm-provider-credentials \
  --from-env-file=<(gateway_env) --dry-run=client -o yaml | k apply -f - >/dev/null
# Occludra reads the key at start.
k -n security-gateways rollout restart deploy/occludra >/dev/null 2>&1 || true
k -n mcp-evals create secret generic llm-provider-credentials \
  --from-literal=OPENCODE_API_KEY=egress-via-occludra --dry-run=client -o yaml | k apply -f - >/dev/null
echo "llm-provider-credentials written ($LLM_PROVIDER)"

if ! k -n chroma get secret chroma-auth >/dev/null 2>&1; then
  python3 -c '
import secrets
print(f"""apiVersion: v1
kind: Secret
metadata:
  name: chroma-auth
  namespace: chroma
  labels: {{app.kubernetes.io/part-of: chroma-distributed}}
type: Opaque
stringData:
  reader-token: "{secrets.token_hex(32)}"
  writer-token: "{secrets.token_hex(32)}"
""")' | k apply -f - >/dev/null
  echo "chroma-auth generated"
fi
if ! k -n security-gateways get secret chroma-reader >/dev/null 2>&1; then
  k -n chroma get secret chroma-auth -o jsonpath='{.data.reader-token}' | python3 -c '
import sys
tok = sys.stdin.read().strip() or sys.exit("chroma-auth has no reader-token")
print(f"""apiVersion: v1
kind: Secret
metadata:
  name: chroma-reader
  namespace: security-gateways
  labels: {{app.kubernetes.io/part-of: mcp-eval-platform}}
type: Opaque
data:
  token: "{tok}"
""")' | k apply -f - >/dev/null
  echo "chroma-reader copied"
fi
if ! k -n chroma get secret minio-credentials >/dev/null 2>&1; then
  python3 -c '
import sys, yaml
for d in yaml.safe_load_all(open("manifests/chroma/minio.yaml")):
    if d and d["kind"] == "Secret":
        print(yaml.safe_dump(d))' | k apply -f - >/dev/null
  echo "minio-credentials written"
fi
