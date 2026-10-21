#!/usr/bin/env bash
# Vigil's REST v2 Chroma client (images/vigil-llm/remote_vectordb.py) against
# a real Chroma behind the real chroma-gateway (test/chroma/lib.sh): a
# single-node container of the build the distributed frontend was cut from
# (same /api/v2), loaded through the gateway with the writer token by the
# platform's own loader (images/vigil-corpus-loader); the client queries with
# the reader token.
#
#   test/vigil/remote-vectordb-test.sh [corpus-cache-dir]
#
# Needs docker, python3 (stdlib only) and network access to HuggingFace for
# the corpora unless corpus-cache-dir already holds ib.json and jb.json.
set -uo pipefail
cd "$(dirname "$0")/../.."
WORK="$(mktemp -d)"
CACHE="${1:-$WORK/corpus}"
source test/chroma/lib.sh
trap 'chroma_gw_down; rm -rf "$WORK"' EXIT
mkdir -p "$CACHE" "$WORK/subset"

fetch() { # fetch <file> <dataset>
  [ -s "$CACHE/$1" ] || curl -sfL -o "$CACHE/$1" \
    "https://huggingface.co/datasets/deadbits/$2/resolve/main/embeddings.json" || exit 2
}
fetch ib.json vigil-instruction-bypass-all-MiniLM-L6-v2
fetch jb.json vigil-jailbreak-all-MiniLM-L6-v2
python3 - "$CACHE" "$WORK/subset" <<'PY'
import json, sys
src, dst = sys.argv[1:]
for f, n in (("ib.json", 150), ("jb.json", 30)):
    json.dump(json.load(open(f"{src}/{f}"))[:n], open(f"{dst}/{f}", "w"))
PY

chroma_gw_up "$WORK" || exit 2
trap 'chroma_gw_down; rm -rf "$WORK"' EXIT
CHROMA_URL="$CHROMA_GW_URL" CHROMA_TOKEN="$CHROMA_WRITER" \
CORPUS_INSTRUCTION_BYPASS_URL="file://$WORK/subset/ib.json" \
CORPUS_JAILBREAK_URL="file://$WORK/subset/jb.json" \
  python3 images/vigil-corpus-loader/load_corpus.py || { echo "loader failed"; exit 1; }

CHROMA_URL="$CHROMA_GW_URL" CHROMA_TOKEN="$CHROMA_READER" SUBSET_DIR="$WORK/subset" python3 test/vigil/remote_vectordb_test.py
rc=$?

# The calibrated (vigil-corpus/1) path: loader + hybrid client, same Chroma.
CHROMA_URL="$CHROMA_GW_URL" CHROMA_READER="$CHROMA_READER" CHROMA_WRITER="$CHROMA_WRITER" WORK="$WORK" \
  python3 test/vigil/calibrated_corpus_test.py || rc=1
exit $rc
