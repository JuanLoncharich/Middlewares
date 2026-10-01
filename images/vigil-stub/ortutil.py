"""ONNX Runtime session factory shared by every model-backed engine.

Provider selection (env VIGIL_ORT_PROVIDER):
  cpu   (default) CPUExecutionProvider only — identical to the pre-GPU image.
  auto  CUDAExecutionProvider when onnxruntime-gpu exposes it, else CPU.
  cuda  CUDA or fail: the engine reports available=false instead of quietly
        running on CPU, so a mis-scheduled GPU pod is visible.
VIGIL_ORT_CPU_MODELS=minilm,... keeps those models on CPU in any mode.

GPU memory is capped with the CUDA EP's own arena limit
(VIGIL_GPU_MEM_LIMIT_BYTES, default 8 GiB). NVIDIA consumer GPUs have no
hard per-container VRAM limit, so this is a soft cap: it bounds what
onnxruntime will allocate, nothing more.
"""

import os

MODE = os.environ.get("VIGIL_ORT_PROVIDER", "cpu").lower()
GPU_MEM_LIMIT = int(os.environ.get("VIGIL_GPU_MEM_LIMIT_BYTES", str(8 * 1024 ** 3)))
DEVICE_ID = int(os.environ.get("VIGIL_GPU_DEVICE_ID", "0"))
# Models pinned to CPU even in auto/cuda mode. The shipped MiniLM is an int8
# export whose quantized ops the CUDA EP lacks (84 memcpy fallbacks: measured
# slower than CPU, and its embeddings drift from the CPU ones that the Chroma
# thresholds were calibrated on). Labels: minilm, transformer, canonical.
CPU_MODELS = {m.strip() for m in os.environ.get("VIGIL_ORT_CPU_MODELS", "").split(",") if m.strip()}

# model label -> provider actually bound to its session (surfaced in /health)
USED = {}


def _providers(ort, label):
    if MODE == "cpu" or label in CPU_MODELS:
        return ["CPUExecutionProvider"]
    if MODE not in ("auto", "cuda"):
        raise ValueError(f"VIGIL_ORT_PROVIDER must be cpu|auto|cuda, got {MODE!r}")
    # onnxruntime-gpu >= 1.21: load the CUDA/cuDNN libraries it needs (from the
    # nvidia-* pip wheels or the system) before the provider is requested.
    # No-op / harmless when they are already on the loader path (GPU image).
    try:
        ort.preload_dlls()
    except Exception:  # noqa: BLE001 - older onnxruntime or already loaded
        pass
    available = ort.get_available_providers()
    if "CUDAExecutionProvider" not in available:
        if MODE == "cuda":
            raise RuntimeError(
                f"VIGIL_ORT_PROVIDER=cuda but CUDAExecutionProvider is unavailable "
                f"(have: {available}); install onnxruntime-gpu"
            )
        return ["CPUExecutionProvider"]
    cuda = ("CUDAExecutionProvider", {
        "device_id": DEVICE_ID,
        "gpu_mem_limit": GPU_MEM_LIMIT,
        "arena_extend_strategy": "kSameAsRequested",
    })
    return [cuda, "CPUExecutionProvider"]


def create_session(ort, model_path, label):
    """InferenceSession for model_path, recording the provider it really got."""
    session = ort.InferenceSession(model_path, providers=_providers(ort, label))
    bound = session.get_providers()[0]
    if MODE == "cuda" and label not in CPU_MODELS and bound != "CUDAExecutionProvider":
        raise RuntimeError(
            f"{label}: CUDA requested but session bound to {bound} "
            f"(CUDA libraries/driver not usable in this container)"
        )
    USED[label] = bound
    print(f"[vigil-stub] onnx session {label}: {bound}", flush=True)
    return session
