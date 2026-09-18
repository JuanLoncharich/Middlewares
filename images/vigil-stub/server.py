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
     "runs": {"heuristics": {"score": float, "is_injection": bool}}}

Detection is a deterministic heuristic: the patterns below are the classic
indirect prompt-injection families. This is a TEST DOUBLE — not a replacement
for the real deadbits/vigil-llm (YARA, embeddings, canonical classifiers).
"""

import json
import os
import re
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


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/analyze":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("content-length", 0))
            payload = json.loads(self.rfile.read(length))
            prompt = str(payload.get("prompt", ""))
        except Exception:
            self._send(400, {"error": "invalid JSON body"})
            return

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
        detected = bool(hits) and score >= THRESHOLD
        self._send(200, {
            "injection_detected": detected,
            "confidence": round(score, 2),
            "status": "blocked" if detected else "allowed",
            "scanners": hits,
            "runs": {
                "heuristics": {
                    "score": round(score, 2),
                    "is_injection": detected,
                    "hits": hits,
                },
            },
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
    print(f"vigil-stub listening on 0.0.0.0:{port} ({len(PATTERNS)} heuristics)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
