#!/usr/bin/env python3
"""Load Vigil's embedding corpora (HuggingFace) into distributed Chroma.

Downloads the pre-embedded prompt corpora from the deadbits HF org and adds
them to collections on the Chroma distributed frontend (REST v2). The
datasets carry precomputed `all-MiniLM-L6-v2` (384-dim) embeddings, so no
embedding model is needed here — only HTTP.

Collections (defaults, overridable via env):
    vigil_instruction_bypass  <- deadbits/vigil-instruction-bypass-all-MiniLM-L6-v2
    vigil_jailbreak           <- deadbits/vigil-jailbreak-all-MiniLM-L6-v2

Idempotent: a collection whose count is already > 0 is skipped unless
FORCE_LOAD=1. Designed to run as a K8s Job (manifests/chroma/corpus-loader-job.yaml);
safe to re-run on every deploy.

Stdlib only (urllib/json) so the image stays python:alpine with zero pip
dependencies and works air-gapped except for the HF download itself.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

CHROMA_URL = os.environ.get("CHROMA_URL", "http://rust-frontend-service.chroma.svc.cluster.local:8000").rstrip("/")
TENANT = os.environ.get("CHROMA_TENANT", "default_tenant")
DATABASE = os.environ.get("CHROMA_DATABASE", "default_database")
FORCE = os.environ.get("FORCE_LOAD", "0") == "1"
RECREATE = os.environ.get("RECREATE", "0") == "1"
BATCH = int(os.environ.get("BATCH_SIZE", "500"))
RETRIES = int(os.environ.get("RETRIES", "8"))
TIMEOUT = int(os.environ.get("HTTP_TIMEOUT_S", "120"))

CORPORA = [
    {
        "collection": os.environ.get("COLLECTION_INSTRUCTION_BYPASS", "vigil_instruction_bypass"),
        "url": os.environ.get(
            "CORPUS_INSTRUCTION_BYPASS_URL",
            "https://huggingface.co/datasets/deadbits/vigil-instruction-bypass-all-MiniLM-L6-v2/resolve/main/embeddings.json",
        ),
    },
    {
        "collection": os.environ.get("COLLECTION_JAILBREAK", "vigil_jailbreak"),
        "url": os.environ.get(
            "CORPUS_JAILBREAK_URL",
            "https://huggingface.co/datasets/deadbits/vigil-jailbreak-all-MiniLM-L6-v2/resolve/main/embeddings.json",
        ),
    },
]

EXPECTED_DIM = 384  # all-MiniLM-L6-v2


def log(msg):
    print(f"[corpus-loader] {msg}", flush=True)


def request(method, url, payload=None, ok=(200, 201, 404, 409), timeout=TIMEOUT):
    """HTTP with retry/backoff; returns (status, parsed-json-or-None)."""
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    last_err = None
    for attempt in range(1, RETRIES + 1):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                status = resp.status
            parsed = None
            if body:
                try:
                    parsed = json.loads(body)
                except ValueError:
                    parsed = body.decode(errors="replace")
            return status, parsed
        except urllib.error.HTTPError as err:
            # HTTPError is a response: read it and honor the caller's ok-set.
            status = err.code
            try:
                parsed = json.loads(err.read() or b"null")
            except ValueError:
                parsed = None
            if status in ok:
                return status, parsed
            last_err = f"HTTP {status}: {parsed}"
        except (urllib.error.URLError, OSError, TimeoutError) as err:
            last_err = str(err)
        if attempt < RETRIES:
            delay = min(2 ** attempt, 30)
            log(f"  retry {attempt}/{RETRIES} for {method} {url} ({last_err}); sleeping {delay}s")
            time.sleep(delay)
    raise RuntimeError(f"{method} {url} failed after {RETRIES} attempts: {last_err}")


def wait_for_frontend():
    status, parsed = request("GET", f"{CHROMA_URL}/api/v2/version", ok=tuple(range(200, 500)))
    if status != 200:
        raise RuntimeError(f"chroma frontend not healthy at {CHROMA_URL}: HTTP {status}")
    log(f"frontend up, version={parsed}")


def api(path):
    return f"{CHROMA_URL}/api/v2/tenants/{TENANT}/databases/{DATABASE}{path}"


def get_or_create_collection(name):
    # Cosine space so the Vigil vector scanner's threshold (calibrated on
    # cosine distance) applies — chroma's default space (l2) would silently
    # rescale it. The distributed frontend defaults to the SPANN index;
    # deployments with HNSW reject the spann config and vice versa, so try
    # each shape and fall back to the server default.
    attempts = [
        {"spann": {"space": "cosine"}},
        {"hnsw": {"space": "cosine"}},
        None,
    ]
    last = None
    for configuration in attempts:
        payload = {"name": name, "get_or_create": True}
        if configuration:
            payload["configuration"] = configuration
        status, coll = request("POST", api("/collections"), payload, ok=(200, 201, 400))
        if status in (200, 201) and isinstance(coll, dict) and coll.get("id"):
            which = "spann" if configuration and "spann" in configuration else ("hnsw" if configuration else "server-default")
            log(f"collection {name!r} id={coll['id']} (space=cosine via {which})")
            return coll["id"]
        last = coll
    raise RuntimeError(f"get_or_create {name!r} failed: {last}")


def collection_count(coll_id):
    # /count is a GET in the v2 API (openapi.json), even though add/query are POST.
    status, count = request("GET", api(f"/collections/{coll_id}/count"), ok=(200,))
    return int(count)


def add_entries(coll_id, name, entries):
    ids = []
    embeddings = []
    documents = []
    metadatas = []
    dim = None

    def flush():
        if not ids:
            return
        status, resp = request(
            "POST",
            api(f"/collections/{coll_id}/add"),
            {"ids": ids, "embeddings": embeddings, "documents": documents, "metadatas": metadatas},
            ok=(200, 201),
        )
        log(f"  +{len(ids)} -> {name} (total pending flushed)")
        ids.clear(); embeddings.clear(); documents.clear(); metadatas.clear()

    for i, entry in enumerate(entries):
        text = entry.get("text")
        vector = entry.get("embeddings") or entry.get("embedding")
        if not text or not vector:
            log(f"  skipping malformed entry {i}")
            continue
        dim = dim or len(vector)
        if len(vector) != dim:
            raise RuntimeError(f"{name}: inconsistent embedding dim at entry {i}: {len(vector)} != {dim}")
        ids.append(f"{name}-{i}")
        embeddings.append(vector)
        documents.append(text)
        metadatas.append({"model": entry.get("model", "all-MiniLM-L6-v2"), "source": name, "corpus_index": i})
        if len(ids) >= BATCH:
            flush()
    flush()
    if dim is not None and dim != EXPECTED_DIM:
        log(f"WARNING: {name} embedding dim is {dim}, expected {EXPECTED_DIM} (all-MiniLM-L6-v2)")


def load_corpus(spec):
    name = spec["collection"]
    log(f"--- corpus {name} <- {spec['url']}")
    coll_id = get_or_create_collection(name)
    existing = collection_count(coll_id)
    if existing > 0 and RECREATE:
        # Drop and re-create: needed e.g. to change index configuration
        # (vector space) of an already-loaded collection.
        log(f"RECREATE=1: dropping {name!r} ({existing} vectors)")
        request("DELETE", api(f"/collections/{coll_id}"), ok=(200, 204))
        coll_id = get_or_create_collection(name)
        existing = collection_count(coll_id)
    if existing > 0 and not FORCE:
        log(f"collection {name!r} already holds {existing} vectors; skipping (FORCE_LOAD=1 to reload)")
        return
    if existing > 0 and FORCE:
        log(f"FORCE_LOAD=1: collection {name!r} has {existing} vectors; adding anyway (ids are stable)")

    log("downloading corpus JSON...")
    status, parsed = request("GET", spec["url"], ok=(200,), timeout=600)
    if not isinstance(parsed, list):
        raise RuntimeError(f"{spec['url']}: expected a JSON list, got {type(parsed).__name__}")
    log(f"downloaded {len(parsed)} entries; adding in batches of {BATCH}")
    add_entries(coll_id, name, parsed)
    final = collection_count(coll_id)
    log(f"collection {name!r} now holds {final} vectors")


def main():
    log(f"chroma frontend: {CHROMA_URL} (tenant={TENANT} database={DATABASE})")
    wait_for_frontend()
    failures = 0
    for spec in CORPORA:
        try:
            load_corpus(spec)
        except Exception as err:  # noqa: BLE001 - report every corpus, fail the job at the end
            log(f"ERROR loading {spec['collection']}: {err}")
            failures += 1
    if failures:
        raise SystemExit(f"{failures} corpus load(s) failed")
    log("all corpora loaded")


if __name__ == "__main__":
    main()
