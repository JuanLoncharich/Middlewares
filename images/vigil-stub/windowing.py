"""Sliding-window tokenisation + batched inference helpers (REPORT-ONLY).

The ONNX models only read a fixed number of tokens (deberta 256, MiniLM 128),
so on a 64 KiB evaluator payload they see ~1 %. Windowing classifies the whole
payload as one batch and reports the worst window.

IT NEVER CHANGES A VERDICT. Measured on real code/config/JSON payloads with
planted injections (hack/gpu-node/calibrate-windows.py, calibrate-vector.py):
  * deberta worst-window: 2-6 of 8 benign payloads score >= 0.99 (false alarms)
    while real detection is no better than the first window;
  * vector (MiniLM -> Vigil corpus): 0 false alarms but 0/192 detections —
    paraphrased injections are not close to the corpus phrases.
So the windowed numbers are emitted (window_score / window_distance, windows,
truncated) for calibration on real platform traffic, and the decision stays the
first-window one, identical to the CPU build.

Opt-in through env (defaults = off):
  VIGIL_MAX_WINDOWS          deberta engines, default 1  (= off)
  VIGIL_VECTOR_MAX_WINDOWS   MiniLM/vector engine, default 1 (= off)
  VIGIL_WINDOW_OVERLAP       tokens shared by neighbouring windows, default 32
  VIGIL_BATCH_SIZE           windows per session.run, default 32
"""

import os


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


MAX_WINDOWS = max(1, env_int("VIGIL_MAX_WINDOWS", 1))
VECTOR_MAX_WINDOWS = max(1, env_int("VIGIL_VECTOR_MAX_WINDOWS", 1))
OVERLAP = max(0, env_int("VIGIL_WINDOW_OVERLAP", 32))
BATCH_SIZE = max(1, env_int("VIGIL_BATCH_SIZE", 32))


def split(ids, size, overlap, max_windows):
    """ids -> (windows, truncated). Windows hold `size` content tokens and
    overlap by `overlap`; `truncated` is True when max_windows cut off a tail."""
    if size <= 0:
        raise ValueError("window size must be positive")
    if not ids:
        return [[]], False
    step = max(1, size - min(overlap, size - 1))
    windows, i = [], 0
    while True:
        windows.append(ids[i:i + size])
        if i + size >= len(ids):
            return windows, False
        i += step
        if len(windows) >= max_windows:
            return windows, True


def special_ids(tokenizer):
    """(cls, sep, pad) ids of a BERT/DeBERTa-style tokenizer, or ValueError."""
    cls, sep, pad = (tokenizer.token_to_id(t) for t in ("[CLS]", "[SEP]", "[PAD]"))
    if cls is None or sep is None:
        raise ValueError("tokenizer has no [CLS]/[SEP]; windowing unsupported for this model")
    return cls, sep, 0 if pad is None else pad


def pad_batch(np, windows, cls_id, sep_id, pad_id, fixed_len=None):
    """List of token-id windows -> (input_ids, attention_mask) int64 arrays.

    fixed_len pads every row to that width (how the MiniLM tokenizer pads the
    single-prompt path: dynamically quantised int8 activations depend on the
    padded width, so windows must be padded identically to stay comparable)."""
    seqs = [[cls_id] + w + [sep_id] for w in windows]
    width = max(len(s) for s in seqs) if fixed_len is None else max(fixed_len, *(len(s) for s in seqs))
    ids = np.full((len(seqs), width), pad_id, dtype=np.int64)
    mask = np.zeros((len(seqs), width), dtype=np.int64)
    for row, seq in enumerate(seqs):
        ids[row, :len(seq)] = seq
        mask[row, :len(seq)] = 1
    return ids, mask


def batches(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]
