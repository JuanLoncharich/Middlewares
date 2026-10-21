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
# Offline subcommands go to the real kubectl; "apply -f -" is captured and
# every invocation is logged to \$CAPTURE.cmds.
echo "\$*" >> "\$CAPTURE.cmds"
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
FAKE_LOCAL="llama-TEST-ONLY-0000000000000000"

run_deploy() { # $1 = capture file, rest = env assignments
  local capture="$1"; shift
  : > "$capture"; : > "$capture.cmds"
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
    want_ctx = 32768 if provider == "local" else None   # local: hack/local-llm/llm's CTX
    if m.get("contextTokens") != want_ctx:
        fail.append(f"{a['metadata']['name']}: contextTokens {m.get('contextTokens')!r} != {want_ctx!r}")
occ = [d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "occludra"]
env = {e["name"]: e.get("value") for e in occ[0]["spec"]["template"]["spec"]["containers"][0]["env"]} if occ else {}
if env.get("OCCLUDRA_UPSTREAM_BASE_URL") != upstream:
    fail.append(f"occludra upstream {env.get('OCCLUDRA_UPSTREAM_BASE_URL')!r} != {upstream!r}")
secrets = {d["metadata"]["namespace"]: {k: base64.b64decode(v).decode() for k, v in (d.get("data") or {}).items()}
           for d in docs if d.get("kind") == "Secret" and d["metadata"]["name"] == "llm-provider-credentials"}
gw, ev = secrets.get("security-gateways", {}), secrets.get("mcp-evals", {})
pols = [d for d in docs if d.get("kind") == "NetworkPolicy" and d["metadata"]["name"] == "occludra-egress-local-llm"]
deleted = any("delete networkpolicy occludra-egress-local-llm" in l for l in open(capture + ".cmds"))
allow = []
for d in docs:
    if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "occludra-policy":
        allow = yaml.safe_load(d["data"]["policy.yaml"])["models"]["allow"]
if provider in ("nvidia", "local"):
    want_gw = {"UPSTREAM_API_KEY": key} if key else {}
    if gw != want_gw: fail.append(f"gateway secret keys {sorted(gw)} (want {sorted(want_gw)} with the key)")
    if key and key in ev.values(): fail.append(f"real {provider} key leaked into mcp-evals")
    if ev.get("OPENCODE_API_KEY") != "egress-via-occludra": fail.append("mcp-evals placeholder missing")
if provider == "local":
    ip, port = sys.argv[7], int(sys.argv[8])
    if len(pols) != 1:
        fail.append(f"expected the local-LLM egress policy, got {len(pols)}")
    else:
        spec = pols[0]["spec"]
        ok = (spec["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "occludra"}}
              and spec["policyTypes"] == ["Egress"]
              and spec["egress"] == [{"to": [{"ipBlock": {"cidr": f"{ip}/32"}}],
                                      "ports": [{"protocol": "TCP", "port": port}]}])
        if not ok: fail.append(f"local-LLM policy spec not exactly Occludra -> {ip}/32:{port}: {spec}")
    import re
    if not any(re.fullmatch(p, model) for p in allow if p.startswith("^") and p.endswith("$")):
        fail.append(f"model {model!r} not in Occludra allowlist as an exact entry")
    if any(re.fullmatch(p, model + "x") for p in allow if p.startswith("^") and p.endswith("$")):
        fail.append("local allowlist entry is not anchored")
else:
    if pols: fail.append("local-LLM egress policy rendered for a non-local provider")
    if not deleted: fail.append("non-local deploy does not delete a leftover local-LLM policy")
if provider == "zen":
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

echo "== LLM_PROVIDER=local (llama-server on the kind host, with --api-key)"
run_deploy "$WORK/local" LLM_PROVIDER=local LOCAL_LLM_URL=http://172.18.0.1:8080/v1 \
  LLM_MODEL=lfm2-24b-a2b.Q4_K_M LOCAL_LLM_API_KEY="$FAKE_LOCAL"
check "$WORK/local" local local lfm2-24b-a2b.Q4_K_M http://172.18.0.1:8080/v1 "$FAKE_LOCAL" 172.18.0.1 8080 \
  && echo "  ok" || rc=1

echo "== LLM_PROVIDER=local without key, default http port"
run_deploy "$WORK/local2" LLM_PROVIDER=local LOCAL_LLM_URL=http://10.147.17.5/v1 LLM_MODEL=qwen-local
check "$WORK/local2" local local qwen-local http://10.147.17.5/v1 "" 10.147.17.5 80 && echo "  ok" || rc=1

echo "== keys never printed by deploy.sh"
if grep -qF -e "$FAKE_KEY" -e "$FAKE_ZEN" -e "$FAKE_LOCAL" "$WORK/zen.log" "$WORK/nv.log" "$WORK/local.log"; then
  echo "  FAIL: key in output"; rc=1; else echo "  ok"; fi

echo "== invalid provider, missing key, local hostname/missing inputs are rejected"
if run_deploy "$WORK/bad" LLM_PROVIDER=bogus; then echo "  FAIL: bogus provider accepted"; rc=1
elif run_deploy "$WORK/nokey" LLM_PROVIDER=nvidia; then echo "  FAIL: missing NVIDIA_API_KEY accepted"; rc=1
elif run_deploy "$WORK/host" LLM_PROVIDER=local LOCAL_LLM_URL=http://my-pc.lan:8080/v1 LLM_MODEL=m; then
  echo "  FAIL: hostname LOCAL_LLM_URL accepted"; rc=1
elif ! grep -q "not a hostname" "$WORK/host.log"; then echo "  FAIL: hostname rejection message unclear"; rc=1
elif run_deploy "$WORK/nourl" LLM_PROVIDER=local LLM_MODEL=m; then echo "  FAIL: missing LOCAL_LLM_URL accepted"; rc=1
elif run_deploy "$WORK/nomodel" LLM_PROVIDER=local LOCAL_LLM_URL=http://172.18.0.1:8080/v1; then
  echo "  FAIL: missing LLM_MODEL accepted"; rc=1
elif run_deploy "$WORK/ctx" LLM_PROVIDER=local LOCAL_LLM_URL=http://172.18.0.1:8080/v1 LLM_MODEL=m LLM_CONTEXT_TOKENS=32k; then
  echo "  FAIL: LLM_CONTEXT_TOKENS=32k accepted"; rc=1
else echo "  ok"; fi

[ "$rc" = 0 ] && echo "PASS" || { echo "FAILED"; for f in "$WORK"/*.log; do echo "--- $f"; tail -5 "$f"; done; }
exit "$rc"
