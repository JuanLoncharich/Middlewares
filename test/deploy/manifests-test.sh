#!/usr/bin/env bash
# Offline checks on the rendered operator manifests (no cluster needed).
#   test/deploy/manifests-test.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
rc=0
rendered="$(kubectl kustomize config/default)" || { echo "FAIL: kustomize config/default"; exit 1; }

# A fresh cluster has no mcp-eval-system namespace: the bundle must create it
# itself, or every namespaced object in it is rejected (regression of 103de6f).
echo "== config/default creates its own namespace"
if printf '%s\n' "$rendered" | awk '/^kind: Namespace$/{ns=1} ns && /^  name: mcp-eval-system$/{found=1} /^---$/{ns=0} END{exit !found}'; then
  echo "  ok"
else
  echo "  FAIL: no Namespace mcp-eval-system in kubectl kustomize config/default"; rc=1
fi

echo "== operator namespace enforces the restricted Pod Security Standard"
if printf '%s\n' "$rendered" | grep -q 'pod-security.kubernetes.io/enforce: restricted'; then echo "  ok"; else echo "  FAIL"; rc=1; fi

[ "$rc" = 0 ] && echo PASS || echo FAILED
exit "$rc"
