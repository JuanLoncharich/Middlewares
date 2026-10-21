# syntax=docker/dockerfile:1
# Vigil-LLM, built from the pinned upstream source (deadbits/vigil-llm @
# VIGIL_SRC_REF, see deploy.sh) — ONE Dockerfile for both variants:
#
#   CPU (in-cluster vigil):  --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cpu --build-arg EXPECT_CUDA=0
#   GPU (on-demand GPU node): defaults (CUDA 12.8 wheels; Blackwell / sm_120 capable)
#
# Build context = the upstream checkout (deploy.sh / hack/gpu-node/build-vigil-gpu.sh).
# What differs from upstream's own Dockerfile, and why (each verified by
# booting the image; an upstream-style build crashes at start):
#  1. torch 2.7.1 + matching torchvision from the PyTorch index, frozen by a
#     constraints file (upstream's 2.1.1+cpu cannot drive RTX 50xx; an
#     unpinned torchvision would drag a newer torch over the CUDA build);
#  2. huggingface_hub<0.26 — upstream's sentence-transformers 2.2.2 imports
#     `cached_download`, removed in 0.26, and requirements.txt leaves it
#     unpinned: "ImportError: cannot import name 'cached_download'";
#  3. the transformer scanner's pipeline runs on CUDA when one is visible
#     (upstream passes no device -> always CPU);
#  4. upstream bug: VectorDB logs an undefined `config_dict`, so any local
#     embedding model dies at boot with NameError — log the model instead;
#  5. the transformer truncates its input to 512 tokens (bounded memory);
#  6. scanner errors answer HTTP 500 instead of a "clean" 200 (fail closed);
#  7. the vectordb scanner queries the distributed Chroma over REST v2
#     (remote_vectordb.py, needs --build-context vigil-patches=images/vigil-llm);
#  8. upstream bug: [auto_update] enabled is read as a string, so "false" is
#     truthy and auto-update was always on — parse it as a boolean;
#  9. one SentenceTransformer per process (the Embedder reuses the vector
#     client's), so the multilingual-e5-small embedder is loaded once;
# 10. no Flask reloader: it loaded every model a second time in a child;
# 11. the e5 embedder is baked in at a pinned revision (only the files it
#     loads), instead of a 2.2 GB repository download at every boot.
# Runtime notes for the manifests: start the server directly (skip upstream's
# entrypoint dataset loader: its 1536-dim ada-002 vectors never match the
# 384-dim MiniLM embedder, and re-streaming them took ~6 min per start) and
# point SENTENCE_TRANSFORMERS_HOME at a persistent cache. Measured on the GPU
# variant: warm start 23 s (was 411 s), ~3.4 GiB host RAM, ~22 ms per scan.
FROM python:3.10-slim

ARG TORCH_VERSION=2.7.1
ARG TORCHVISION_VERSION=0.22.1
ARG TORCH_INDEX=https://download.pytorch.org/whl/cu128
# 1 = the build fails unless torch is a CUDA build (GPU variant); 0 for CPU.
ARG EXPECT_CUDA=1

WORKDIR /app

RUN apt-get update && apt-get install --no-install-recommends -y \
      automake autoconf build-essential libtool libc-dev make flex gcc \
      pkg-config libssl-dev curl unzip git git-lfs bison \
 && rm -rf /var/lib/apt/lists/*

# YARA from source, exactly as upstream (yara-python links against it).
RUN curl -fsSLo yara.zip https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.zip \
 && unzip -q yara.zip && cd yara-4.3.2 \
 && ./bootstrap.sh && ./configure && make -j"$(nproc)" && make install \
 && cd .. && rm -rf yara.zip yara-4.3.2 && ldconfig

COPY . .

# CUDA torch + the torchvision built against it, from the CUDA index (PyPI only
# as a fallback for their plain dependencies). sentence-transformers pulls in
# torchvision; without a pinned match pip would fetch the newest torchvision
# and, with it, a newer torch from PyPI over the CUDA build. The constraints
# file then freezes both for requirements.txt — and caps huggingface_hub:
# upstream's sentence-transformers==2.2.2 imports `cached_download`, which
# huggingface_hub removed in 0.26, and requirements.txt leaves it unpinned
# (an unpinned build crashes at import: "cannot import name 'cached_download'").
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install torch==${TORCH_VERSION} torchvision==${TORCHVISION_VERSION} \
      --index-url ${TORCH_INDEX} --extra-index-url https://pypi.org/simple \
 && printf 'torch==%s\ntorchvision==%s\nhuggingface_hub<0.26\n' "${TORCH_VERSION}" "${TORCHVISION_VERSION}" > /tmp/constraints.txt \
 && pip install -r requirements.txt -c /tmp/constraints.txt \
 && python -c "import torch; v=torch.__version__; assert v.startswith('${TORCH_VERSION}'), v; assert ('${EXPECT_CUDA}' != '1') or ('cu' in v), v; print('torch', v)" \
 && python -c "import sentence_transformers, huggingface_hub; print('sentence-transformers import ok, huggingface_hub', huggingface_hub.__version__)"

# Patch 2 — fail the build loudly if upstream's call site ever changes.
RUN sed -i "s/pipeline('text-classification', model=self.model_name)/pipeline('text-classification', model=self.model_name, device=(0 if __import__('torch').cuda.is_available() else -1))/" \
      vigil/scanners/transformer.py \
 && grep -q "__import__('torch').cuda.is_available()" vigil/scanners/transformer.py

# Patch 3 — upstream bug at the pinned commit: the SentenceTransformer branch of
# VectorDB logs `config_dict["embed_fn"]`, a name that does not exist, so any
# config with a local embedding model (ours: all-MiniLM-L6-v2) dies at boot
# with "NameError: name 'config_dict' is not defined". Log the model instead.
RUN sed -i 's/{config_dict\["embed_fn"\]}/{model}/' vigil/core/vectordb.py \
 && ! grep -q 'config_dict' vigil/core/vectordb.py

# Patch 4 — the transformer reads at most 512 tokens per request. Upstream
# feeds the whole prompt to deberta-v3 (512-token window), whose memory grows
# with the square of the length: one 64 KB payload OOM-killed the pod at its
# 3.5 GiB limit. The evaluator already sends ≤512-token chunks
# (runner/src/vigilsegments.ts); this bounds memory for any other caller.
# (The prompt must stay positional: transformers 4.36's text-classification
# __call__ reads args[0].)
RUN sed -i '/hits = self.pipeline(/{n;s/scan_obj.prompt$/scan_obj.prompt, truncation=True, max_length=512/}' \
      vigil/scanners/transformer.py \
 && grep -q 'scan_obj.prompt, truncation=True, max_length=512$' vigil/scanners/transformer.py

# Patch 5 — fail closed. Upstream's scanners catch their own errors (model
# not loaded, pipeline/YARA/vector failure) and return "no matches", so a
# broken scanner answers HTTP 200 "clean". Re-raise instead: the dispatcher
# records the error, and /analyze/prompt answers 500 (not cached) when any
# scanner errored, which the evaluator treats as Vigil unavailable.
RUN sed -i "/logger.error(f'Pipeline error/{n;s/return scan_obj/raise/}" vigil/scanners/transformer.py \
 && sed -i "/logger.error(f'Failed to perform yara scan/{n;s/return scan_obj/raise/}" vigil/scanners/yara.py \
 && sed -i "/logger.error(f'Failed to perform vector scan/{n;s/return scan_obj/raise/}" vigil/scanners/vectordb.py \
 && grep -A1 "Pipeline error" vigil/scanners/transformer.py | grep -q '^ *raise$' \
 && grep -A1 "Failed to perform yara scan" vigil/scanners/yara.py | grep -q '^ *raise$' \
 && grep -A1 "Failed to perform vector scan" vigil/scanners/vectordb.py | grep -q '^ *raise$' \
 && sed -i "s/^    result = vigil.input_scanner.perform_scan(input_prompt)$/&\n    if result.get('errors'):\n        logger.error(f'({request.path}) Scanner errors, answering 500: {result[\"errors\"]}')\n        return jsonify(result), 500/" vigil-server.py \
 && grep -q "return jsonify(result), 500" vigil-server.py \
 && python -c "import ast; [ast.parse(open(f).read()) for f in ('vigil-server.py', 'vigil/scanners/transformer.py', 'vigil/scanners/yara.py', 'vigil/scanners/vectordb.py')]"

# Patch 6 — the vectordb scanner queries the distributed Chroma. Upstream's
# VectorDB is a local chromadb==0.4.17 client (API v1); the platform's corpus
# lives in the Rust Chroma cluster, REST v2 only. remote_vectordb.py (from
# the `vigil-patches` build context: images/vigil-llm/) embeds locally and
# queries it; Vigil uses it when server.conf sets [vectordb] chroma_url.
# Build with: --build-context vigil-patches=images/vigil-llm
COPY --from=vigil-patches remote_vectordb.py vigil/core/remote_vectordb.py
RUN sed -i 's/^        self.vectordb = VectorDB(\*\*params)$/        if params.get("chroma_url"):\n            from vigil.core.remote_vectordb import RemoteVectorDB\n            self.vectordb = RemoteVectorDB(**params)\n        else:\n            self.vectordb = VectorDB(**params)/' vigil/vigil.py \
 && grep -q 'self.vectordb = RemoteVectorDB(\*\*params)' vigil/vigil.py \
 && python -c "import ast; ast.parse(open('vigil/vigil.py').read()); ast.parse(open('vigil/core/remote_vectordb.py').read())"

# Patch 7 — upstream bug at the pinned commit: `[auto_update] enabled` comes
# out of configparser as the string "false", which is truthy, so auto-update
# is ON whatever the config says: every prompt that 3 scanners flag is written
# into the vector corpus (scan traffic poisoning the shared corpus), and with
# the read-only remote client that write fails the whole scan with a 500.
# Parse the value as a boolean.
RUN sed -i "s/auto_update = manager_config.get('auto_update', {}).get('enabled', False)$/auto_update = str(manager_config.get('auto_update', {}).get('enabled', 'false')).strip().lower() in ('1', 'true', 'yes', 'on')/" vigil/vigil.py \
 && grep -q "in ('1', 'true', 'yes', 'on')" vigil/vigil.py \
 && python -c "import ast; ast.parse(open('vigil/vigil.py').read())"

# Patch 8 — one embedding model per process. Upstream's Embedder (used by the
# output similarity scanner) loads its own SentenceTransformer next to the
# vector db's: with multilingual-e5-small that is ~470 MB twice. It takes the
# remote client's cached instance instead (same model name -> same object).
RUN sed -i 's/^                self.model = SentenceTransformer(model)$/                from vigil.core.remote_vectordb import load_model\n                self.model = load_model(model)/' vigil/core/embedding.py \
 && grep -q 'self.model = load_model(model)' vigil/core/embedding.py \
 && python -c "import ast; ast.parse(open('vigil/core/embedding.py').read())"

# Patch 10 — no Flask reloader. Upstream starts the server with
# use_reloader=True: Werkzeug's reloader re-executes the whole script in a
# child process, so every model (deberta classifier, embedder) was loaded
# twice and the pod paid for both. With multilingual-e5-small that no longer
# fits the 3500Mi limit (measured: OOM-killed at boot). A server in a pod
# never edits its own code; the reloader only cost memory.
RUN sed -i "s/^    app.run(host='0.0.0.0', use_reloader=True)$/    app.run(host='0.0.0.0', use_reloader=False)/" vigil-server.py \
 && grep -q "use_reloader=False" vigil-server.py

# Patch 11 — the embedder ships in the image, pinned. sentence-transformers
# 2.2.2 downloads a model's WHOLE repository at every boot: 2.2 GB for
# multilingual-e5-small (ONNX and OpenVINO exports included), more than the
# pod's 2Gi tmp volume and slower than its startup probe (measured in kind).
# Only the files it loads (~480 MB), at the revision the corpus was built
# with; remote_vectordb.load_model picks /app/models/<org>_<name> up. The
# corpus's embedding probe still checks the result at the first scan.
ARG E5_MODEL=intfloat/multilingual-e5-small
ARG E5_REVISION=614241f622f53c4eeff9890bdc4f31cfecc418b3
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('${E5_MODEL}', revision='${E5_REVISION}', local_dir='/app/models/$(echo ${E5_MODEL} | tr / _)', local_dir_use_symlinks=False, allow_patterns=['modules.json', 'config.json', 'config_sentence_transformers.json', 'sentence_bert_config.json', '1_Pooling/*', 'model.safetensors', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'sentencepiece.bpe.model'])" \
 && test -f /app/models/intfloat_multilingual-e5-small/modules.json \
 && test -f /app/models/intfloat_multilingual-e5-small/model.safetensors \
 && rm -rf /app/models/*/.cache && du -sh /app/models

ENV HF_HOME=/cache/hf \
    SENTENCE_TRANSFORMERS_HOME=/cache/st \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

EXPOSE 5000
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "python", "vigil-server.py", "-c", "conf/server.conf"]
