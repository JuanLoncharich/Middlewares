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
#   metallb-system/metallb-webhook-cert          with DEPLOY_INGRESS=1: empty; MetalLB's controller fills
#                                                it with its webhook certificate (the chart ships it empty,
#                                                but render.sh drops every Secret)
#   traefik/traefik-default-cert                 with DEPLOY_INGRESS=1: self-signed certificate for
#                                                INGRESS_IP (2 years); a copy of the public part goes to
#                                                ~/.config/mcp-eval/ingress-cert.pem, to trust it in a browser
#   mcp-eval-ui/ui-basic-auth                    with DEPLOY_INGRESS=1 and DEPLOY_UI=1: htpasswd line for
#                                                the UI. Login in ~/.config/mcp-eval/ui-login (user:password,
#                                                0600), generated once (UI_USER, default "mcp"); delete
#                                                that file and the Secret to rotate it.
# Key values travel through pipes only: never on argv, never printed.
set -euo pipefail
cd "$(dirname "$0")/../.."

dir="${1:?usage: secrets.sh <cluster dir, e.g. deploy/k0s>}"
k() { kubectl ${CONTEXT:+--context "$CONTEXT"} "$@"; }
LLM_PROVIDER="$(. "$dir/render.env"; echo "${LLM_PROVIDER:-zen}")"
read -r DEPLOY_INGRESS DEPLOY_UI INGRESS_IP < <(. "$dir/render.env"
  range="${INGRESS_IP_RANGE:-}"; echo "${DEPLOY_INGRESS:-0} ${DEPLOY_UI:-0} ${INGRESS_IP:-${range%%-*}}")

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

if [ "$DEPLOY_INGRESS" = "1" ]; then
  conf="$HOME/.config/mcp-eval"
  mkdir -p "$conf" && chmod 700 "$conf"
  k apply -f manifests/ingress/namespaces.yaml >/dev/null
  k create namespace mcp-eval-ui --dry-run=client -o yaml | k apply -f - >/dev/null
  if ! k -n metallb-system get secret metallb-webhook-cert >/dev/null 2>&1; then
    k -n metallb-system create secret generic metallb-webhook-cert --dry-run=client -o yaml | k apply -f - >/dev/null
    echo "metallb-webhook-cert created (empty; MetalLB fills it)"
  fi
  if ! k -n traefik get secret traefik-default-cert >/dev/null 2>&1; then
    work="$(mktemp -d)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 730 \
      -keyout "$work/tls.key" -out "$work/tls.crt" -subj "/CN=MCP Eval ($INGRESS_IP)" \
      -addext "subjectAltName=IP:$INGRESS_IP" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
    k -n traefik create secret tls traefik-default-cert --cert="$work/tls.crt" --key="$work/tls.key" \
      --dry-run=client -o yaml | k apply -f - >/dev/null
    cp "$work/tls.crt" "$conf/ingress-cert.pem"
    rm -rf "$work"
    echo "traefik-default-cert generated for $INGRESS_IP (public part: $conf/ingress-cert.pem)"
  fi
  if [ "$DEPLOY_UI" = "1" ] && ! k -n mcp-eval-ui get secret ui-basic-auth >/dev/null 2>&1; then
    login="$conf/ui-login"
    if [ ! -s "$login" ]; then
      ( umask 077; printf '%s:%s\n' "${UI_USER:-mcp}" "$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')" > "$login" )
    fi
    user="$(cut -d: -f1 "$login")"
    # bcrypt via mkpasswd (whois package) or htpasswd (apache-tools); the
    # password goes through stdin only.
    if command -v htpasswd >/dev/null; then
      hash="$(cut -d: -f2- "$login" | htpasswd -niB "$user" | cut -d: -f2-)"
    else
      hash="$(cut -d: -f2- "$login" | mkpasswd -m bcrypt -R 10 -s)"
    fi
    printf '%s:%s\n' "$user" "$hash" | k -n mcp-eval-ui create secret generic ui-basic-auth \
      --from-file=users=/dev/stdin --dry-run=client -o yaml | k apply -f - >/dev/null
    echo "ui-basic-auth written (login in $login)"
  fi
fi
