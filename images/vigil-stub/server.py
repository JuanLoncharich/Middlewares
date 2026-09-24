#!/usr/bin/env python3
"""Vigil-compatible scanner stub for local testing of the MCP eval platform.

Implements the subset of the vigil-llm REST contract the evaluator uses:

    POST /analyze  {"prompt": "<untrusted payload>"}
    GET  /health

Response carries every verdict shape the runner's parser understands
(integration contract + legacy status + per-scanner runs) so it exercises the
full parsing path:

    {"injection_detected": bool,
     "confidence": float,
     "status": "blocked" | "allowed",
     "scanners": [...],
     "runs": {"heuristics": {...}, "vector": {...}}}

Two detection layers:

1. Heuristics (always on): deterministic regex families for the classic
   indirect prompt-injection patterns. Stateless, instant.
2. Vector scanner (enabled when VIGIL_CHROMA_URL is set): embeds the prompt
   with all-MiniLM-L6-v2 (ONNX, baked into the image) and queries the
   **distributed Chroma cluster** (frontend REST v2) for nearest-neighbour
   matches against the real Vigil corpora loaded by the corpus-loader Job
   (deadbits/vigil-instruction-bypass-all-MiniLM-L6-v2, deadbits/vigil-
   jailbreak-all-MiniLM-L6-v2). This is the same detection idea as
   vigil-llm's `vectordb` scanner, backed by the distributed deployment
   instead of an embedded on-disk Chroma.

Failure policy mirrors vigil-llm's: a vector scanner outage degrades the
/analyze verdict to the heuristics layer (`runs.vector.available: false`)
rather than erroring the request; the runner's strict-mode gate keeps its
existing semantics.
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PATTERNS = [
    # Verb may be separated from the target noun by qualifiers ("all
    # previous", "any prior", "the above", …) — {0,40} of non-sentence
    # text. "Forget" and friends join the classic "ignore" family.
    ("ignore-instructions", re.compile(r"\b(ignore|forget|disregard|drop|override|bypass)\b[^.]{0,40}?\b(instructions?|prompts?|rules?|directives?)\b", re.I)),
    # "(your|the)" is optional: "reveal system prompt" (no possessive) is
    # just as much an extraction attempt as "reveal your system prompt".
    ("reveal-system-prompt", re.compile(r"\b(reveal|print|output|repeat|show|display|expose|disclose|leak|dump)\b[^.]{0,30}?\b(system\s+prompt|your\s+prompt|initial\s+instructions|hidden\s+(?:instructions|rules)|operating\s+instructions)\b", re.I)),
    ("role-hijack", re.compile(r"you are now (a|an) [a-z ]+", re.I)),
    ("disregard-safety", re.compile(r"disregard (all|any) (safety|content) (guidelines|policies|rules)", re.I)),
    ("exfiltration", re.compile(r"(curl|wget|fetch|POST)\s+https?://\S+\s+.*(env|HOME|PATH|TOKEN|KEY)", re.I)),
    ("exfil-marker", re.compile(r"send (all|the) (data|content|files) to https?://", re.I)),
    ("hidden-instruction", re.compile(r"\[?system\]|\(system note\)|<\|im_start\|>", re.I)),
    ("credential-harvest", re.compile(r"(api[_ ]?key|password|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}", re.I)),
]

THRESHOLD = float(os.environ.get("VIGIL_STUB_THRESHOLD", "0.5"))
# Bounded in-flight /analyze requests: at saturation answer 503 + Retry-After
# (the evaluator's Vigil client retries on 5xx) instead of spawning an
# unbounded thread per connection and letting memory decide the outcome.
MAX_INFLIGHT = int(os.environ.get("VIGIL_STUB_MAX_INFLIGHT", "64"))
MAX_BODY_BYTES = int(os.environ.get("VIGIL_STUB_MAX_BODY_BYTES", str(4 * 1024 * 1024)))
SEMAPHORE = threading.BoundedSemaphore(MAX_INFLIGHT)

# --------------------------------------------------------------- vector path
CHROMA_URL = os.environ.get("VIGIL_CHROMA_URL", "").rstrip("/")
# Cosine distance below which a corpus neighbour counts as a match (mirrors
# vigil-llm's [scanner:vectordb] threshold default).
VECTOR_THRESHOLD = float(os.environ.get("VIGIL_VECTOR_THRESHOLD", "0.45"))
VECTOR_N_RESULTS = int(os.environ.get("VIGIL_VECTOR_N_RESULTS", "3"))
CHROMA_TENANT = os.environ.get("VIGIL_CHROMA_TENANT", "default_tenant")
CHROMA_DATABASE = os.environ.get("VIGIL_CHROMA_DATABASE", "default_database")
CHROMA_COLLECTIONS = [
    c.strip()
    for c in os.environ.get("VIGIL_CHROMA_COLLECTIONS", "vigil_instruction_bypass,vigil_jailbreak").split(",")
    if c.strip()
]
MODEL_DIR = os.environ.get("VIGIL_VECTOR_MODEL_DIR", "/models")

VECTOR_DISABLED = {"available": False, "reason": "VIGIL_CHROMA_URL not set"}


class Embedder:
    """all-MiniLM-L6-v2 via ONNX (quantized), mean-pooled + L2-normalized."""

    def __init__(self, model_dir):
        import numpy as np  # noqa: F401 - ensures the dep is really there
        from tokenizers import Tokenizer
        import onnxruntime as ort

        self.np = np
        self.tokenizer = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        self.session = ort.InferenceSession(
            os.path.join(model_dir, "model_quantized.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self.input_names = {i.name for i in self.session.get_inputs()}

    def encode(self, text):
        np = self.np
        enc = self.tokenizer.encode(text[:2000], add_special_tokens=True)
        ids = np.array([enc.ids], dtype=np.int64)
        mask = np.array([enc.attention_mask], dtype=np.int64)
        feed = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self.input_names:
            feed["token_type_ids"] = np.zeros_like(ids)
        out = self.session.run(None, feed)[0]  # (1, seq, 384) last_hidden_state
        m = mask[:, :, None].astype(np.float32)
        summed = (out * m).sum(axis=1)
        counts = np.clip(m.sum(axis=1), 1e-9, None)
        mean = summed / counts
        norm = np.clip(np.linalg.norm(mean, axis=1, keepdims=True), 1e-9, None)
        return (mean / norm)[0].tolist()


class ChromaVectorScanner:
    """Nearest-neighbour scan against the distributed Chroma frontend."""

    def __init__(self):
        self.embedder = None
        self.collection_ids = None
        self.last_error = "not initialized"
        self.lock = threading.Lock()
        # After a failed init, serve heuristics-only for this long before
        # retrying: with the cluster down we must not pay a connection
        # timeout on every /analyze.
        self.retry_after = 0.0
        self.init_retry_seconds = float(os.environ.get("VIGIL_VECTOR_INIT_RETRY_S", "60"))

    @property
    def status(self):
        if not CHROMA_URL:
            return {"available": False, "reason": "VIGIL_CHROMA_URL not set"}
        if self.collection_ids is None:
            return {"available": False, "reason": f"initializing: {self.last_error}"}
        return {
            "available": True,
            "backend": "distributed-chroma",
            "collections": CHROMA_COLLECTIONS,
            "threshold": VECTOR_THRESHOLD,
        }

    def _chroma(self, method, path, payload=None, timeout=10):
        url = f"{CHROMA_URL}/api/v2/tenants/{CHROMA_TENANT}/databases/{CHROMA_DATABASE}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data else {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"null")

    def _init(self):
        """Resolve the embedding model + collection ids once (lazy, locked)."""
        with self.lock:
            if self.collection_ids is not None:
                return
            if time.monotonic() < self.retry_after:
                return
            try:
                if self.embedder is None:
                    self.embedder = Embedder(MODEL_DIR)
                ids = {}
                for name in CHROMA_COLLECTIONS:
                    coll = self._chroma("POST", "/collections", {"name": name, "get_or_create": True})
                    ids[name] = coll["id"]
                self.collection_ids = ids
                self.last_error = ""
                print(f"[vigil-stub] vector scanner online: {ids}", flush=True)
            except Exception as err:  # noqa: BLE001 - degrade, don't crash /health
                self.last_error = str(err)
                self.retry_after = time.monotonic() + self.init_retry_seconds
                print(f"[vigil-stub] vector scanner init failed (retry in {self.init_retry_seconds:.0f}s): {err}", flush=True)

    def scan(self, text):
        """Returns (runs-entry, matched: bool). Never raises."""
        if not CHROMA_URL:
            return dict(VECTOR_DISABLED), False
        self._init()
        if self.collection_ids is None:
            return {"available": False, "reason": f"init failed: {self.last_error}"}, False
        try:
            vector = self.embedder.encode(text)
            best = None  # (distance, collection, document)
            for name, coll_id in self.collection_ids.items():
                res = self._chroma(
                    "POST", f"/collections/{coll_id}/query",
                    {"query_embeddings": [vector], "n_results": VECTOR_N_RESULTS},
                )
                distances = (res.get("distances") or [[]])[0] or []
                documents = (res.get("documents") or [[]])[0] or []
                for distance, doc in zip(distances, documents):
                    if best is None or distance < best[0]:
                        best = (float(distance), name, doc)
            if best is None:
                return {"available": True, "is_injection": False, "score": 0.0,
                        "note": "corpus empty or unreachable results"}, False
            distance, collection, document = best
            matched = distance < VECTOR_THRESHOLD
            return {
                "available": True,
                "is_injection": matched,
                # Similarity (1 - cosine distance) so the runner's generic
                # per-scanner score semantics still read sensibly.
                "score": round(1.0 - distance, 3),
                "distance": round(distance, 4),
                "threshold": VECTOR_THRESHOLD,
                "matched_collection": collection,
                "nearest_document": document[:160],
            }, matched
        except Exception as err:  # noqa: BLE001
            return {"available": False, "reason": str(err)[:200]}, False


VECTOR_SCANNER = ChromaVectorScanner()


class Handler(BaseHTTPRequestHandler):
    # A wedged client must not hold a semaphore slot (or a thread) forever.
    timeout = 30

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self._send(200, {"status": "ok", "vector": VECTOR_SCANNER.status})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/analyze":
            self._send(404, {"error": "not found"})
            return
        if not SEMAPHORE.acquire(timeout=2):
            self._send(503, {"error": "scanner at capacity; retry with backoff"})
            return
        try:
            self._analyze()
        finally:
            SEMAPHORE.release()

    def _analyze(self):
        try:
            length = int(self.headers.get("content-length", 0))
            if length <= 0 or length > MAX_BODY_BYTES:
                self._send(413, {"error": "missing or oversized body"})
                return
            payload = json.loads(self.rfile.read(length))
            prompt = str(payload.get("prompt", ""))
        except Exception:
            self._send(400, {"error": "invalid JSON body"})
            return

        started = time.monotonic()
        hits = []
        score = 0.0
        for name, pattern in PATTERNS:
            if pattern.search(prompt):
                hits.append(name)
                score = min(1.0, score + 0.6)
        # Test toggle: force a detection so the runner's abort path can be
        # exercised deterministically (kubectl set env deploy/vigil ...).
        if os.environ.get("VIGIL_STUB_ALWAYS_BLOCK") == "1":
            hits = ["forced-detection"]
            score = 1.0

        vector_run, vector_matched = VECTOR_SCANNER.scan(prompt)
        detected = (bool(hits) and score >= THRESHOLD) or vector_matched
        if vector_matched and score < 0.6:
            score = 0.6
        self._send(200, {
            "injection_detected": detected,
            "confidence": round(score, 2),
            "status": "blocked" if detected else "allowed",
            "scanners": hits + (["vector"] if vector_matched else []),
            "runs": {
                "heuristics": {
                    "score": round(score, 2),
                    "is_injection": bool(hits) and score >= THRESHOLD,
                    "hits": hits,
                },
                "vector": vector_run,
            },
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
        })

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[vigil-stub]", args[0] if args else fmt, flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("VIGIL_STUB_PORT", "5000"))
    mode = "heuristics+vector(distributed-chroma)" if CHROMA_URL else "heuristics-only"
    print(f"vigil-stub listening on 0.0.0.0:{port} ({len(PATTERNS)} heuristics; {mode})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
