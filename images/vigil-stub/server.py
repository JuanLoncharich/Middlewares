#!/usr/bin/env python3
"""Vigil-compatible scanner for the MCP eval platform — six detection engines.

Implements the vigil-llm REST contract the evaluator uses:

    POST /analyze  {"prompt": "<untrusted payload>"}
    GET  /health

Response carries every verdict shape the runner's parser understands
(integration contract + legacy status + per-scanner runs) so it exercises the
full parsing path:

    {"injection_detected": bool,
     "confidence": float,
     "status": "blocked" | "allowed",
     "scanners": [...],
     "runs": {"heuristics": ..., "yara": ..., "vector": ...,
              "transformer": ..., "canonical": ..., "sentiment": ...}}

The six engines (details and upstream fidelity notes in scanners.py):

    heuristics   regex families                                  always on
    yara         vendored vigil-llm YARA rules (yara-python)     always on
    vector       all-MiniLM-L6-v2 → distributed Chroma cluster   VIGIL_CHROMA_URL
    transformer  protectai/deberta-v3-base-prompt-injection      always on
    canonical    protectai/deberta-v3-base-prompt-injection-v2   always on
    sentiment    VADER negative-sentiment signal                 always on

Verdict = OR over engines (same semantics as vigil-llm, where every scanner
appends matches and any match flags the payload). Each engine degrades
independently: an outage or init failure marks `runs.<engine>.available =
false` and never fails the request. Engine thresholds are env-tunable;
model engines run ONNX fp32/int8 on CPU with lazy init + a 60 s retry
cooldown, warmed up in the background at startup.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners import (
    CHROMA_URL,
    DebertaScanner,
    HeuristicsScanner,
    SentimentScanner,
    VectorScanner,
    YaraScanner,
    _env_int,
)

# Bounded in-flight /analyze requests: at saturation answer 503 + Retry-After
# (the evaluator's Vigil client retries on 5xx) instead of spawning an
# unbounded thread per connection and letting memory decide the outcome.
MAX_INFLIGHT = _env_int("VIGIL_STUB_MAX_INFLIGHT", 64)
MAX_BODY_BYTES = _env_int("VIGIL_STUB_MAX_BODY_BYTES", 4 * 1024 * 1024)
SEMAPHORE = threading.BoundedSemaphore(MAX_INFLIGHT)

# Test toggle handled inside the heuristics engine's caller (see _analyze):
VIGIL_STUB_ALWAYS_BLOCK = os.environ.get("VIGIL_STUB_ALWAYS_BLOCK") == "1"


class Scanner:
    """All engines + the merge logic; one instance per process."""

    def __init__(self):
        # Shared MiniLM encoder for the vector engine.
        self.embedder = None
        self.vector = VectorScanner(self._mini_lm)
        self.engines = {
            "heuristics": HeuristicsScanner(),
            "yara": YaraScanner(),
            "vector": self.vector,
            "transformer": DebertaScanner(
                "transformer", "transformer",
                float(os.environ.get("VIGIL_TRANSFORMER_THRESHOLD", "0.98")),
                enabled=os.environ.get("VIGIL_ENABLE_TRANSFORMER", "1") == "1",
            ),
            "canonical": DebertaScanner(
                "canonical", "canonical",
                float(os.environ.get("VIGIL_CANONICAL_THRESHOLD", "0.85")),
                enabled=os.environ.get("VIGIL_ENABLE_CANONICAL", "1") == "1",
            ),
            "sentiment": SentimentScanner(),
        }
        self.warmup_started = False
        self.warmup_done = False

    def _mini_lm(self):
        """Lazy shared all-MiniLM-L6-v2 encoder (vector engine)."""
        if self.embedder is None:
            from scanners import MODEL_DIR
            from embedder import Embedder
            self.embedder = Embedder(MODEL_DIR)
        return self.embedder

    def warmup(self):
        """Best-effort warmup so the first real scan is fast.

        Engines load SEQUENTIALLY on purpose: two fp32 deberta sessions
        loading at once spike past the container limit and get the pod
        OOMKilled (verified 2026-09-24). Sequential peak is ~1.5 GiB and
        the full pass takes ~20 s — well inside the 5 min startupProbe.
        `/health` answers 503 until the pass completes so startup/readiness
        probes hold the pod out of the Service endpoints while loading.
        Engines whose init fails keep retrying in the background with a
        60 s cooldown and degrade their scans at runtime — a permanently
        broken engine never wedges readiness.
        """
        if self.warmup_started:
            return
        self.warmup_started = True

        def run():
            for engine in self.engines.values():
                try:
                    engine._init()
                except Exception:  # noqa: BLE001 - warmup must never crash
                    pass
            self.warmup_done = True
            states = {n: ("ok" if e._ready else "degraded") for n, e in self.engines.items()}
            print(f"[vigil-stub] warmup pass complete: {states}", flush=True)

        threading.Thread(target=run, daemon=True, name="engine-warmup").start()

    def scan(self, prompt):
        runs = {}
        detected = False
        contributions = []
        for name, engine in self.engines.items():
            try:
                run, matched = engine.scan(prompt)
            except Exception as err:  # noqa: BLE001 - belt and braces
                run, matched = {"available": False, "reason": str(err)[:200]}, False
            runs[name] = run
            if matched:
                detected = True
                score = run.get("score", 1.0)
                if isinstance(score, (int, float)):
                    contributions.append(float(score))
        confidence = max(contributions) if contributions else 0.0
        return runs, detected, confidence

    def status(self):
        return {
            "engines": {
                name: (engine.status() if hasattr(engine, "status") else {
                    "available": engine._ready,
                    "reason": None if engine._ready else engine._error,
                })
                for name, engine in self.engines.items()
            },
        }


SCANNER = Scanner()


class Handler(BaseHTTPRequestHandler):
    # A wedged client must not hold a semaphore slot (or a thread) forever.
    timeout = 30

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            # 503 until the warmup pass has completed so startup/readiness
            # probes keep the pod out of the endpoints while models load.
            code = 200 if self.warm_ready() else 503
            self._send(code, {"status": "ok" if code == 200 else "warming-up",
                              "engines": SCANNER.status()})
        else:
            self._send(404, {"error": "not found"})

    @staticmethod
    def warm_ready():
        return SCANNER.warmup_done

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
        SCANNER.warmup()
        runs, detected, confidence = SCANNER.scan(prompt)

        # Test toggle: force a detection so the runner's abort path can be
        # exercised deterministically (kubectl set env deploy/vigil ...).
        if VIGIL_STUB_ALWAYS_BLOCK:
            detected = True
            confidence = max(confidence, 1.0)
            runs["forced-detection"] = {"available": True, "is_injection": True, "score": 1.0}

        triggered = sorted(
            name for name, run in runs.items() if run.get("is_injection")
        )
        self._send(200, {
            "injection_detected": detected,
            "confidence": round(confidence, 2),
            "status": "blocked" if detected else "allowed",
            "scanners": triggered,
            "runs": runs,
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
    port = _env_int("VIGIL_STUB_PORT", 5000)
    SCANNER.warmup()
    active = [n for n, e in SCANNER.engines.items()
              if getattr(e, "_enabled", True) or n != "vector"]
    print(f"vigil-stub listening on 0.0.0.0:{port} "
          f"({len(SCANNER.engines)} engines: {', '.join(SCANNER.engines)}; "
          f"vector backend: {CHROMA_URL or 'disabled'})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
