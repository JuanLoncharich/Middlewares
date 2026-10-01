#!/usr/bin/env bash
# Build the GPU variant of Vigil from the same pinned upstream source as the
# cluster's CPU Vigil (deploy.sh: VIGIL_SRC_REPO / VIGIL_SRC_REF).
#   hack/gpu-node/build-vigil-gpu.sh [image-tag]
set -euo pipefail
cd "$(dirname "$0")/../.."
VIGIL_SRC_REPO="${VIGIL_SRC_REPO:-https://github.com/deadbits/vigil-llm}"
VIGIL_SRC_REF="${VIGIL_SRC_REF:-f2b4c134d060bae81d29fad07003f3c657e63fc8}"
IMG="${1:-vigil-llm-gpu:local}"
src="$(mktemp -d)"; trap 'rm -rf "$src"' EXIT
git init -q "$src"
git -C "$src" remote add origin "$VIGIL_SRC_REPO"
git -C "$src" fetch -q --depth 1 origin "$VIGIL_SRC_REF"
git -C "$src" checkout -q FETCH_HEAD
docker build -t "$IMG" -f images/vigil-gpu/Dockerfile "$src"
echo "built $IMG from $VIGIL_SRC_REPO@$VIGIL_SRC_REF"
