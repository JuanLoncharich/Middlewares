#!/usr/bin/env python3
"""Load Vigil's embedding corpora (HuggingFace) into distributed Chroma.

Downloads the pre-embedded prompt corpora from the deadbits HF org and adds
them to collections on the Chroma distributed frontend (REST v2). The
datasets carry precomputed `all-MiniLM-L6-v2` (384-dim) embeddings, so no
embedding model is needed here — only HTTP.

Two inputs:

CORPUS_URL (+ CORPUS_SHA256, required with it): our calibrated corpus, one
vigil-corpus/1 file built by hack/vigil-corpus/build_corpus.py (gzip, JSON
lines: a header, then {"c": collection, "t": text, "s": source, "e":
base64 float16 vector}). The file is fetched (https:// or file://), its
sha256 checked BEFORE anything is written, and each collection gets the
header's model, prefix, kind, threshold and embedding probe as metadata —
the remote Vigil client reads its thresholds from there and refuses a corpus
its embedder does not reproduce. Collection names carry the corpus name
(e.g. vigil_e5s_v2_whole), so a new corpus never mixes with an old one.

Without CORPUS_URL, the legacy deadbits corpora:

Collections (defaults, overridable via env):
    vigil_instruction_bypass  <- deadbits/vigil-instruction-bypass-all-MiniLM-L6-v2
    vigil_jailbreak           <- deadbits/vigil-jailbreak-all-MiniLM-L6-v2

Idempotent: a collection whose count is already > 0 is skipped unless
FORCE_LOAD=1. Designed to run as a K8s Job (manifests/chroma/corpus-loader-job.yaml);
safe to re-run on every deploy.

Auth: CHROMA_URL is chroma-gateway (manifests/chroma/gateway.yaml); the
writer token comes from CHROMA_TOKEN (a Secret) and is sent only to
CHROMA_URL, never to the dataset hosts.

Stdlib only (urllib/json) so the image stays python:alpine with zero pip
dependencies and works air-gapped except for the HF download itself.
"""

import base64
import gzip
import hashlib
import io
import json
import struct
import os
import sys
import time
import urllib.error
import urllib.request

CHROMA_URL = os.environ.get("CHROMA_URL", "http://chroma-gateway.chroma.svc.cluster.local:8080").rstrip("/")
CHROMA_TOKEN = os.environ.get("CHROMA_TOKEN", "")
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
CORPUS_URL = os.environ.get("CORPUS_URL", "")
CORPUS_SHA256 = os.environ.get("CORPUS_SHA256", "").strip().lower()


def log(msg):
    print(f"[corpus-loader] {msg}", flush=True)


def request(method, url, payload=None, ok=(200, 201, 404, 409), timeout=TIMEOUT):
    """HTTP with retry/backoff; returns (status, parsed-json-or-None)."""
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if CHROMA_TOKEN and url.startswith(CHROMA_URL + "/"):
        headers["Authorization"] = f"Bearer {CHROMA_TOKEN}"
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


def get_or_create_collection(name, metadata=None):
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
        if metadata:
            payload["metadata"] = metadata
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


def fetch_verified(url, sha256):
    """The corpus file's bytes, only if their sha256 is the pinned one."""
    if not sha256:
        raise RuntimeError("CORPUS_URL needs CORPUS_SHA256 (the lock file's sha256)")
    log(f"downloading {url} ...")
    with urllib.request.urlopen(url, timeout=600) as resp:
        data = resp.read()
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        raise RuntimeError(f"{url}: sha256 {got} != pinned {sha256}; refusing to load")
    log(f"sha256 ok ({len(data) / 1e6:.0f} MB)")
    return data


def collection_metadata(header, name, spec):
    return {
        "vigil_corpus": header["name"],
        "vigil_corpus_sha256": CORPUS_SHA256,
        "vigil_embedding_model": header["model"],
        "vigil_text_prefix": header["prefix"],
        "vigil_kind": spec["kind"],
        "vigil_threshold": float(spec["threshold"]),
        "vigil_probe_text": header["probe_text"],
        "vigil_probe_head": json.dumps(header["probe_head"]),
    }


def load_calibrated(url):
    # Streamed: the decompressed file is several times the download.
    lines = (line.decode() for line in gzip.GzipFile(fileobj=io.BytesIO(fetch_verified(url, CORPUS_SHA256))))
    header = json.loads(next(lines))
    if header.get("format") != "vigil-corpus/1":
        raise RuntimeError(f"{url}: not a vigil-corpus/1 file: {str(header)[:200]}")
    dim = int(header["dim"])
    ids = {}
    for name, spec in header["collections"].items():
        coll_id = get_or_create_collection(name, collection_metadata(header, name, spec))
        existing = collection_count(coll_id)
        _, coll = request("GET", api(f"/collections/{name}"), ok=(200,))
        held = (coll.get("metadata") or {}).get("vigil_corpus_sha256") if isinstance(coll, dict) else None
        if existing > 0 and held != CORPUS_SHA256 and not RECREATE:
            raise RuntimeError(f"collection {name!r} holds another corpus build (sha256 {held}); RECREATE=1 replaces it")
        if existing > 0 and RECREATE:
            log(f"RECREATE=1: dropping {name!r} ({existing} vectors)")
            request("DELETE", api(f"/collections/{coll_id}"), ok=(200, 204))
            coll_id = get_or_create_collection(name, collection_metadata(header, name, spec))
            existing = collection_count(coll_id)
        if existing == spec["count"] and not FORCE:
            log(f"collection {name!r} already holds its {existing} vectors; skipping (FORCE_LOAD=1 to reload)")
            continue
        if existing:
            log(f"collection {name!r} holds {existing} of {spec['count']} vectors; adding (ids are stable)")
        ids[name] = coll_id
    batches = {name: ([], [], [], []) for name in ids}
    counts = dict.fromkeys(ids, 0)

    def flush(name):
        b_ids, b_emb, b_doc, b_meta = batches[name]
        if b_ids:
            # upsert: a re-run after a partial load rewrites the same ids
            request("POST", api(f"/collections/{ids[name]}/upsert"),
                    {"ids": b_ids, "embeddings": b_emb, "documents": b_doc, "metadatas": b_meta}, ok=(200, 201))
            for part in batches[name]:
                part.clear()

    for line in lines:
        e = json.loads(line)
        name = e["c"]
        if name not in ids:
            continue
        raw = base64.b64decode(e["e"])
        if len(raw) != 2 * dim:
            raise RuntimeError(f"{name}: vector of {len(raw) // 2} dims, header says {dim}")
        b_ids, b_emb, b_doc, b_meta = batches[name]
        b_ids.append(f"{name}-{counts[name]}")
        b_emb.append(list(struct.unpack(f"<{dim}e", raw)))
        b_doc.append(e["t"])
        b_meta.append({"source": e["s"]})
        counts[name] += 1
        if len(b_ids) >= BATCH:
            flush(name)
            if counts[name] % (BATCH * 40) == 0:
                log(f"  {name}: {counts[name]} / {header['collections'][name]['count']}")
    for name in ids:
        flush(name)
        final = collection_count(ids[name])
        want = header["collections"][name]["count"]
        if final != want:
            raise RuntimeError(f"collection {name!r} holds {final} vectors after loading, expected {want}")
        log(f"collection {name!r} now holds {final} vectors (threshold {header['collections'][name]['threshold']:.4f})")


def main():
    log(f"chroma frontend: {CHROMA_URL} (tenant={TENANT} database={DATABASE})")
    wait_for_frontend()
    if CORPUS_URL:
        load_calibrated(CORPUS_URL)
        log("calibrated corpus loaded")
        return
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
