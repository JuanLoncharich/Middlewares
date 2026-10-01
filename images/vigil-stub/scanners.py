"""Detection engines for the Vigil-compatible scanner stub.

Six scanners, mirroring vigil-llm's engine set (same detection semantics,
thresholds and defaults; model-based engines run ONNX on CPU by default,
or on CUDA when VIGIL_ORT_PROVIDER=auto|cuda, see ortutil.py):

  heuristics   regex families (always on)                       [stub-native]
  yara         YARA rules, vendored from vigil-llm data/yara/   [upstream rules]
  vector       all-MiniLM-L6-v2 → distributed Chroma (§ARCHITECTURE 5.2.1)
  transformer  protectai/deberta-v3-base-prompt-injection  (vigil-llm's
               laiyer model lineage), threshold 0.98, label INJECTION
  canonical    protectai/deberta-v3-base-prompt-injection-v2 — stands in for
               vigil-llm's retired `canonical` classifier (deepset/
               deberta-v3-base-injection), an independent training run
  sentiment    VADER, negative score > 0.7 (upstream default)

Every engine degrades independently: an engine that fails to init or errors
at scan time reports `available: false` in its `runs` entry and never fails
the /analyze request. Verdict = OR over the engines that fired.
"""

import os
import threading
import time

import windowing


# --------------------------------------------------------------------- utils
class LazyEngine:
    """Shared lazy-init + cooldown scaffold for engines with expensive state."""

    def __init__(self, name, retry_seconds):
        self.name = name
        self._ready = False
        self._error = "not initialized"
        self._lock = threading.Lock()
        self._retry_after = 0.0
        self._retry_seconds = retry_seconds

    @property
    def error(self):
        return self._error

    def _init(self):
        """Idempotent engine bootstrap; returns True when ready."""
        if self._ready:
            return True
        with self._lock:
            if self._ready:
                return True
            if time.monotonic() < self._retry_after:
                return False
            try:
                self._boot()
                self._ready = True
                self._error = ""
                print(f"[vigil-stub] engine online: {self.name}", flush=True)
                return True
            except Exception as err:  # noqa: BLE001 - degrade, never crash
                self._error = str(err)[:200]
                self._retry_after = time.monotonic() + self._retry_seconds
                print(f"[vigil-stub] engine {self.name} init failed "
                      f"(retry in {self._retry_seconds:.0f}s): {self._error}", flush=True)
                return False


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _softmax2(logits):
    import math
    m = max(logits)
    exps = [math.e ** (v - m) for v in logits]
    total = sum(exps)
    return [e / total for e in exps]


# ---------------------------------------------------------------- heuristics
HEURISTIC_PATTERNS = [
    # (name, compiled regex) — classic indirect prompt-injection families.
    ("ignore-instructions", r"\b(ignore|forget|disregard|drop|override|bypass)\b[^.]{0,40}?\b(instructions?|prompts?|rules?|directives?)\b"),
    ("reveal-system-prompt", r"\b(reveal|print|output|repeat|show|display|expose|disclose|leak|dump)\b[^.]{0,30}?\b(system\s+prompt|your\s+prompt|initial\s+instructions|hidden\s+(?:instructions|rules)|operating\s+instructions)\b"),
    ("role-hijack", r"you are now (a|an) [a-z ]+"),
    ("disregard-safety", r"disregard (all|any) (safety|content) (guidelines|policies|rules)"),
    ("exfiltration", r"(curl|wget|fetch|POST)\s+https?://\S+\s+.*(env|HOME|PATH|TOKEN|KEY)"),
    ("exfil-marker", r"send (all|the) (data|content|files) to https?://"),
    ("hidden-instruction", r"\[?system\]|\(system note\)|<\|im_start\|>"),
    ("credential-harvest", r"(api[_ ]?key|password|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}"),
]

import re  # noqa: E402 - compiled once at import
HEURISTIC_PATTERNS = [(n, re.compile(p, re.I)) for n, p in HEURISTIC_PATTERNS]

HEURISTIC_THRESHOLD = _env_float("VIGIL_STUB_THRESHOLD", "0.5")


class HeuristicsScanner(LazyEngine):
    def __init__(self):
        super().__init__("heuristics", 0)
        self._ready = True  # compiled at import; cannot fail

    def _boot(self):
        pass

    def scan(self, text):
        hits = []
        score = 0.0
        for name, pattern in HEURISTIC_PATTERNS:
            if pattern.search(text):
                hits.append(name)
                score = min(1.0, score + 0.6)
        detected = bool(hits) and score >= HEURISTIC_THRESHOLD
        return {
            "available": True,
            "is_injection": detected,
            "score": round(score, 2),
            "hits": hits,
        }, detected


# ---------------------------------------------------------------------- yara
YARA_RULES_DIR = os.environ.get("VIGIL_YARA_RULES_DIR", "/rules")
VIGIL_ENABLE_YARA = os.environ.get("VIGIL_ENABLE_YARA", "1") == "1"


class YaraScanner(LazyEngine):
    def __init__(self):
        super().__init__("yara", 60)

    def _boot(self):
        import yara
        files = {
            f: os.path.join(YARA_RULES_DIR, f)
            for f in sorted(os.listdir(YARA_RULES_DIR))
            if f.lower().endswith((".yar", ".yara"))
        }
        if not files:
            raise RuntimeError(f"no .yar files in {YARA_RULES_DIR}")
        self._rules = yara.compile(filepaths=files)

    def scan(self, text):
        if not VIGIL_ENABLE_YARA:
            return {"available": False, "reason": "disabled"}, False
        if not self._init():
            return {"available": False, "reason": self._error}, False
        matches = self._rules.match(data=text)
        rules = [m.rule for m in matches]
        return {
            "available": True,
            "is_injection": bool(rules),
            "score": 1.0 if rules else 0.0,
            "rules": rules,
        }, bool(rules)


# -------------------------------------------------------------------- vector
CHROMA_URL = os.environ.get("VIGIL_CHROMA_URL", "").rstrip("/")
CHROMA_TENANT = os.environ.get("VIGIL_CHROMA_TENANT", "default_tenant")
CHROMA_DATABASE = os.environ.get("VIGIL_CHROMA_DATABASE", "default_database")
CHROMA_COLLECTIONS = [
    c.strip()
    for c in os.environ.get("VIGIL_CHROMA_COLLECTIONS", "vigil_instruction_bypass,vigil_jailbreak").split(",")
    if c.strip()
]
VECTOR_THRESHOLD = _env_float("VIGIL_VECTOR_THRESHOLD", "0.45")
VECTOR_N_RESULTS = _env_int("VIGIL_VECTOR_N_RESULTS", 3)


class VectorScanner(LazyEngine):
    """Nearest-neighbour scan against the distributed Chroma frontend."""

    def __init__(self, embedder):
        super().__init__("vector", 60)
        self._embedder = embedder  # shared MiniLM encoder (transformers engine owns it)
        self._collection_ids = None

    def status(self):
        if not CHROMA_URL:
            return {"available": False, "reason": "VIGIL_CHROMA_URL not set"}
        if self._collection_ids is None:
            return {"available": False, "reason": f"initializing: {self._error}"}
        return {
            "available": True,
            "backend": "distributed-chroma",
            "collections": CHROMA_COLLECTIONS,
            "threshold": VECTOR_THRESHOLD,
        }

    def _boot(self):
        import urllib.request, json  # noqa: E402
        self._urllib = urllib.request
        self._json = json
        ids = {}
        for name in CHROMA_COLLECTIONS:
            url = f"{CHROMA_URL}/api/v2/tenants/{CHROMA_TENANT}/databases/{CHROMA_DATABASE}/collections"
            data = json.dumps({"name": name, "get_or_create": True}).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                ids[name] = json.loads(resp.read())["id"]
        self._collection_ids = ids

    def scan(self, text):
        if not CHROMA_URL:
            return {"available": False, "reason": "VIGIL_CHROMA_URL not set"}, False
        if not self._init():
            return {"available": False, "reason": self._error}, False
        try:
            # _embedder is the lazy factory (shared MiniLM encoder).
            meta = None
            if windowing.VECTOR_MAX_WINDOWS > 1:
                vectors, meta = self._embedder().encode_windows(text, windowing.VECTOR_MAX_WINDOWS)
            else:
                vectors = [self._embedder().encode(text)]
            best = None   # (distance, collection, document) — first window: the verdict
            worst = None  # smallest distance over ALL windows — reported only
            vectors_groups = list(windowing.batches(vectors, 64))
            for name, coll_id in self._collection_ids.items():
                url = f"{CHROMA_URL}/api/v2/tenants/{CHROMA_TENANT}/databases/{CHROMA_DATABASE}/collections/{coll_id}/query"
                # One request carries many query embeddings: the whole payload
                # costs one round trip per collection (groups of 64 at most).
                for group in vectors_groups:
                    data = self._json.dumps({"query_embeddings": group, "n_results": VECTOR_N_RESULTS}).encode()
                    req = self._urllib.Request(url, data=data, method="POST",
                                               headers={"Content-Type": "application/json"})
                    with self._urllib.urlopen(req, timeout=10) as resp:
                        res = self._json.loads(resp.read())
                    for qi, (distances, documents) in enumerate(zip(res.get("distances") or [], res.get("documents") or [])):
                        is_first = (group is vectors_groups[0] and qi == 0)
                        for distance, doc in zip(distances or [], documents or []):
                            if is_first and (best is None or distance < best[0]):
                                best = (float(distance), name, doc)        # decision: first window only
                            if worst is None or distance < worst:
                                worst = float(distance)                    # report: any window
            if best is None:
                return {"available": True, "is_injection": False, "score": 0.0}, False
            distance, collection, document = best
            matched = distance < VECTOR_THRESHOLD
            run = {
                "available": True,
                "is_injection": matched,
                "score": round(1.0 - distance, 3),
                "distance": round(distance, 4),
                "threshold": VECTOR_THRESHOLD,
                "matched_collection": collection,
                "nearest_document": (document or "")[:160],
            }
            if meta is not None:
                run.update(meta)
                if worst is not None:
                    run["window_distance"] = round(worst, 4)
            return run, matched
        except Exception as err:  # noqa: BLE001
            return {"available": False, "reason": str(err)[:200]}, False


# ------------------------------------------------------- transformers (ONNX)
MODEL_DIR = os.environ.get("VIGIL_VECTOR_MODEL_DIR", "/models")
TRANSFORMER_THRESHOLD = _env_float("VIGIL_TRANSFORMER_THRESHOLD", "0.98")
CANONICAL_THRESHOLD = _env_float("VIGIL_CANONICAL_THRESHOLD", "0.85")
TRANSFORMER_MAX_TOKENS = _env_int("VIGIL_TRANSFORMER_MAX_TOKENS", 256)
VIGIL_ENABLE_TRANSFORMER = os.environ.get("VIGIL_ENABLE_TRANSFORMER", "1") == "1"
VIGIL_ENABLE_CANONICAL = os.environ.get("VIGIL_ENABLE_CANONICAL", "1") == "1"


class _OnnxTextClassifier:
    """Shared ONNX text-classification backend (tokenizers + onnxruntime)."""

    def __init__(self, model_path, tokenizer_path, max_tokens, label):
        import numpy as np
        from tokenizers import Tokenizer
        import onnxruntime as ort
        from ortutil import create_session

        self.np = np
        self.max_tokens = max_tokens
        self.tokenizer = Tokenizer.from_file(tokenizer_path)
        self.tokenizer.enable_truncation(max_length=max_tokens)
        # Untruncated twin for windowed scans of the whole payload.
        self.tokenizer_full = Tokenizer.from_file(tokenizer_path)
        self.tokenizer_full.no_truncation()
        self.tokenizer_full.no_padding()
        self.session = create_session(ort, model_path, label)
        self.input_names = {i.name for i in self.session.get_inputs()}

    def probability_of_index(self, text, class_index):
        """P(class_index) after softmax over the single-pair logits."""
        np = self.np
        enc = self.tokenizer.encode(text, add_special_tokens=True)
        ids = np.array([enc.ids], dtype=np.int64)
        mask = np.array([enc.attention_mask], dtype=np.int64)
        feed = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self.input_names:
            feed["token_type_ids"] = np.zeros_like(ids)
        logits = self.session.run(None, feed)[0][0]  # (num_classes,)
        return _softmax2([float(v) for v in logits])[class_index]

    def probability_windows(self, text, class_index, max_windows):
        """P(class_index) over the WHOLE text: every overlapping window is
        classified (batched, one session.run per VIGIL_BATCH_SIZE windows) and
        the worst window wins. Returns (p_max, meta)."""
        np = self.np
        cls_id, sep_id, pad_id = windowing.special_ids(self.tokenizer_full)
        ids = self.tokenizer_full.encode(text, add_special_tokens=False).ids
        wins, truncated = windowing.split(ids, self.max_tokens - 2, windowing.OVERLAP, max_windows)
        probs = []
        for chunk in windowing.batches(wins, windowing.BATCH_SIZE):
            input_ids, mask = windowing.pad_batch(np, chunk, cls_id, sep_id, pad_id)
            feed = {"input_ids": input_ids, "attention_mask": mask}
            if "token_type_ids" in self.input_names:
                feed["token_type_ids"] = np.zeros_like(input_ids)
            logits = self.session.run(None, feed)[0]  # (n, num_classes)
            e = np.exp(logits - logits.max(axis=1, keepdims=True))
            probs.extend((e[:, class_index] / e.sum(axis=1)).tolist())
        worst = max(range(len(probs)), key=probs.__getitem__)
        return probs[worst], {
            "windows": len(wins), "truncated": truncated,
            "worst_window": worst, "tokens": len(ids),
        }


class DebertaScanner(LazyEngine):
    """Binary SAFE/INJECTION classifier (protectai deberta-v3, ONNX fp32).

    Model exports label {0: SAFE, 1: INJECTION}; we take P(class 1).
    NOTE: shipped fp32 on purpose — dynamic int8 quantization corrupts
    deberta-v3's disentangled attention (verified 2026-09-24: obvious
    injections scored 0.003 post-quantization); fp32 runs in ~0.1s.
    """

    def __init__(self, name, subdir, threshold, enabled=True):
        super().__init__(name, 60)
        self._subdir = subdir
        self._threshold = threshold
        self._enabled = enabled

    def _boot(self):
        self._clf = _OnnxTextClassifier(
            os.path.join(MODEL_DIR, self._subdir, "model.onnx"),
            os.path.join(MODEL_DIR, self._subdir, "tokenizer.json"),
            TRANSFORMER_MAX_TOKENS,
            self.name,
        )

    def warm(self):
        """One throwaway inference. On CUDA the first run JIT-compiles kernels
        (~40 s on a cold container, measured on Blackwell); doing it during
        startup keeps that latency out of the first real scan — /health stays
        503 until warmup finishes."""
        if self._enabled and self._ready:
            self._clf.probability_of_index("warm-up probe", 1)
            if windowing.MAX_WINDOWS > 1:
                # different batch shapes compile separate CUDA kernels/plans
                self._clf.probability_windows("warm-up probe " * 2000, 1, windowing.BATCH_SIZE)

    def scan(self, text):
        if not self._enabled:
            return {"available": False, "reason": "disabled"}, False
        if not self._init():
            return {"available": False, "reason": self._error}, False
        try:
            # The verdict ALWAYS comes from the first window, exactly like the
            # CPU build, so GPU and CPU pods decide identically.
            p_injection = self._clf.probability_of_index(text, 1)
            matched = p_injection > self._threshold
            run = {
                "available": True,
                "is_injection": matched,
                "score": round(p_injection, 4),
                "threshold": self._threshold,
            }
            if windowing.MAX_WINDOWS > 1:
                # Report-only whole-payload scan (see windowing.py): measured on
                # real code/config/JSON, the worst-window score false-alarms far
                # too often to block on (hack/gpu-node/calibrate-windows.py).
                p_worst, meta = self._clf.probability_windows(text, 1, windowing.MAX_WINDOWS)
                run.update(meta)
                run["window_score"] = round(p_worst, 4)
            return run, matched
        except Exception as err:  # noqa: BLE001
            return {"available": False, "reason": str(err)[:200]}, False


# ----------------------------------------------------------------- sentiment
SENTIMENT_THRESHOLD = _env_float("VIGIL_SENTIMENT_THRESHOLD", "0.7")
VIGIL_ENABLE_SENTIMENT = os.environ.get("VIGIL_ENABLE_SENTIMENT", "1") == "1"


class SentimentScanner(LazyEngine):
    """VADER negative-sentiment signal (upstream: nltk VADER, neg > threshold)."""

    def __init__(self):
        super().__init__("sentiment", 60)

    def _boot(self):
        from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
        self._analyzer = SentimentIntensityAnalyzer()

    def scan(self, text):
        if not VIGIL_ENABLE_SENTIMENT:
            return {"available": False, "reason": "disabled"}, False
        if not self._init():
            return {"available": False, "reason": self._error}, False
        try:
            scores = self._analyzer.polarity_scores(text)
            matched = scores["neg"] > SENTIMENT_THRESHOLD
            return {
                "available": True,
                "is_injection": matched,
                "score": round(scores["neg"], 3),
                "threshold": SENTIMENT_THRESHOLD,
                "compound": round(scores["compound"], 3),
                "positive": round(scores["pos"], 3),
                "neutral": round(scores["neu"], 3),
            }, matched
        except Exception as err:  # noqa: BLE001
            return {"available": False, "reason": str(err)[:200]}, False
