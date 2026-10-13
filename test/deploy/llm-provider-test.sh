#!/usr/bin/env bash
# Offline test of deploy.sh's LLM_PROVIDER option: runs deploy.sh against a
# stub `kubectl` that records every manifest it would apply (no cluster, no
# docker, no network) and checks what each provider renders.
#
#   test/deploy/llm-provider-test.sh
#
# Needs the real kubectl on PATH (only for offline `kustomize` and
# `create --dry-run=client`) and python3 with PyYAML (deploy.sh needs it too).
set -uo pipefail
cd "$(dirname "$0")/../.."
REAL_KUBECTL="$(command -v kubectl)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
# deploy.sh's legacy-mode manifest filter needs PyYAML; use a throwaway venv
# when the system python3 lacks it.
PYPATH=""
if ! python3 -c 'import yaml' 2>/dev/null; then
  python3 -m venv "$WORK/venv" && "$WORK/venv/bin/pip" install -q pyyaml \
    || { echo "need PyYAML (python3 -m venv + pip failed)" >&2; exit 2; }
  PYPATH="$WORK/venv/bin:"
fi

cat > "$WORK/bin/kubectl" <<STUB
#!/usr/bin/env bash
# Offline subcommands go to the real kubectl; "apply -f -" is captured.
case "\$*" in
  kustomize*|*--dry-run=client*) exec "$REAL_KUBECTL" "\$@" ;;
  *"apply -f -"*) cat >> "\$CAPTURE"; echo "---" >> "\$CAPTURE" ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/kubectl"

# A recognisable fake key: the test fails if it shows up in deploy.sh output
# or in any manifest other than the gateway Secret.
FAKE_KEY="nvapi-TEST-ONLY-0000000000000000"
FAKE_ZEN="zen-TEST-ONLY-0000000000000000"

run_deploy() { # $1 = capture file, rest = env assignments
  local capture="$1"; shift
  : > "$capture"
  env -i PATH="$WORK/bin:$PYPATH$PATH" HOME="$HOME" CAPTURE="$capture" \
    IMG_REGISTRY=registry.test/x SKIP_BUILD=1 TRIGGER=0 MESH_ENFORCE=false \
    DEPLOY_VECTOR_DB=0 "$@" ./deploy.sh > "$capture.log" 2>&1
}

check() { # python assertions over the captured manifests
  PATH="$PYPATH$PATH" python3 - "$@" <<'PY'
import base64, sys, yaml
capture, provider, provider_id, model, upstream, key = sys.argv[1:7]
docs = [d for d in yaml.safe_load_all(open(capture)) if d]
fail = []
agents = [d for d in docs if d.get("kind") == "OpenCodeAgent"]
if len(agents) != 4:
    fail.append(f"expected 4 personas, got {len(agents)}")
for a in agents:
    m = a["spec"]["model"]
    if (m["providerID"], m["modelID"]) != (provider_id, model):
        fail.append(f"{a['metadata']['name']}: model {m} != {provider_id}/{model}")
occ = [d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "occludra"]
env = {e["name"]: e.get("value") for e in occ[0]["spec"]["template"]["spec"]["containers"][0]["env"]} if occ else {}
if env.get("OCCLUDRA_UPSTREAM_BASE_URL") != upstream:
    fail.append(f"occludra upstream {env.get('OCCLUDRA_UPSTREAM_BASE_URL')!r} != {upstream!r}")
secrets = {d["metadata"]["namespace"]: {k: base64.b64decode(v).decode() for k, v in d["data"].items()}
           for d in docs if d.get("kind") == "Secret" and d["metadata"]["name"] == "llm-provider-credentials"}
gw, ev = secrets.get("security-gateways", {}), secrets.get("mcp-evals", {})
if provider == "nvidia":
    if gw != {"UPSTREAM_API_KEY": key}: fail.append(f"gateway secret keys {sorted(gw)} (want only UPSTREAM_API_KEY with the key)")
    if key in ev.values(): fail.append("real NVIDIA key leaked into mcp-evals")
    if ev.get("OPENCODE_API_KEY") != "egress-via-occludra": fail.append("mcp-evals placeholder missing")
else:
    for ns, s in (("security-gateways", gw), ("mcp-evals", ev)):
        if s != {"OPENCODE_API_KEY": key}: fail.append(f"{ns} secret keys {sorted(s)} (want OPENCODE_API_KEY)")
for f in fail: print("  FAIL:", f)
sys.exit(1 if fail else 0)
PY
}

rc=0
echo "== default provider (zen)"
run_deploy "$WORK/zen" OPENCODE_API_KEY="$FAKE_ZEN"
check "$WORK/zen" zen opencode muse-spark-1.3-contributor-free "" "$FAKE_ZEN" && echo "  ok" || rc=1

echo "== LLM_PROVIDER=nvidia"
run_deploy "$WORK/nv" LLM_PROVIDER=nvidia NVIDIA_API_KEY="$FAKE_KEY"
check "$WORK/nv" nvidia nvidia z-ai/glm-5.3 https://integrate.api.nvidia.com/v1 "$FAKE_KEY" && echo "  ok" || rc=1

echo "== keys never printed by deploy.sh"
if grep -qF -e "$FAKE_KEY" -e "$FAKE_ZEN" "$WORK/zen.log" "$WORK/nv.log"; then echo "  FAIL: key in output"; rc=1; else echo "  ok"; fi

echo "== invalid provider and missing key are rejected"
if run_deploy "$WORK/bad" LLM_PROVIDER=bogus; then echo "  FAIL: bogus provider accepted"; rc=1
elif run_deploy "$WORK/nokey" LLM_PROVIDER=nvidia; then echo "  FAIL: missing NVIDIA_API_KEY accepted"; rc=1
else echo "  ok"; fi

[ "$rc" = 0 ] && echo "PASS" || { echo "FAILED"; for f in "$WORK"/*.log; do echo "--- $f"; tail -5 "$f"; done; }
exit "$rc"
