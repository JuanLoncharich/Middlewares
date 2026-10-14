#!/usr/bin/env bash
# Vigil's REST v2 Chroma client (images/vigil-llm/remote_vectordb.py) against
# a real Chroma: a single-node container of the build the distributed
# frontend was cut from (same /api/v2), loaded with a subset of the Vigil
# corpora by the platform's own loader (images/vigil-corpus-loader).
#
#   test/vigil/remote-vectordb-test.sh [corpus-cache-dir]
#
# Needs docker, python3 (stdlib only) and network access to HuggingFace for
# the corpora unless corpus-cache-dir already holds ib.json and jb.json.
set -uo pipefail
cd "$(dirname "$0")/../.."
CHROMA_IMAGE="${CHROMA_IMAGE:-chromadb/chroma:1.5.10.dev296}"
PORT="${CHROMA_PORT:-18000}"
WORK="$(mktemp -d)"
CACHE="${1:-$WORK/corpus}"
trap 'docker rm -f vigil-chroma-test >/dev/null 2>&1; rm -rf "$WORK"' EXIT
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

docker run -d --name vigil-chroma-test --memory=512m -p "127.0.0.1:$PORT:8000" "$CHROMA_IMAGE" >/dev/null || exit 2
for _ in $(seq 60); do
  curl -sf "localhost:$PORT/api/v2/heartbeat" >/dev/null && break
  sleep 1
done
CHROMA_URL="http://127.0.0.1:$PORT" \
CORPUS_INSTRUCTION_BYPASS_URL="file://$WORK/subset/ib.json" \
CORPUS_JAILBREAK_URL="file://$WORK/subset/jb.json" \
  python3 images/vigil-corpus-loader/load_corpus.py || { echo "loader failed"; exit 1; }

CHROMA_URL="http://127.0.0.1:$PORT" SUBSET_DIR="$WORK/subset" python3 test/vigil/remote_vectordb_test.py
