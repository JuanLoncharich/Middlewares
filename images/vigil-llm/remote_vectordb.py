"""Vigil vector database backend for the distributed Chroma (REST API v2).

Copied into the vigil-llm image as vigil/core/remote_vectordb.py
(images/vigil-llm/Dockerfile, patch 6). Upstream's VectorDB is a local
chromadb==0.4.17 PersistentClient; the platform's corpus lives in the
distributed Rust Chroma (manifests/chroma/), which only speaks REST v2.

Two modes, chosen by what the collections carry:

CALIBRATED (our corpus, hack/vigil-corpus/, loaded by images/vigil-corpus-loader
from a vigil-corpus/1 file). Every collection's metadata says which embedding
model and text prefix built it, whether it holds WHOLE texts or single
SENTENCES, and its own distance threshold, calibrated on benign tool-like
text to a fixed false-positive rate. A query is "hybrid":
  - the whole text (one runner chunk, <= 500 chars) is compared with the
    whole-text collections ([vectordb] collections);
  - each of its sentences (sentences() below, the same split the corpus and
    its calibration used) is compared with the sentence collections
    ([vectordb] sentence_collections);
  - a hit is a neighbour closer than ITS collection's threshold. Only hits
    are returned, so [scanner:vectordb] threshold must not filter again
    (server.conf sets it to 2.0, above any cosine distance).
  Before the first query the client checks that its embedder reproduces the
  corpus: model name equal, and the embedding of the corpus's probe text
  within 0.01 of the recorded one (a different model revision, library
  version or prefix moves it). A mismatch fails closed.

LEGACY (deadbits' MiniLM corpora, no metadata): the nearest n_results of the
whole text, raw, and upstream's scanner threshold applies.

In both modes the answer has upstream's query shape
({"documents": [[...]], "metadatas": [[...]], "distances": [[...]]}), and any
Chroma error, timeout, missing collection, bad answer or model mismatch
RAISES: with the image's fail-closed patch the scan answers HTTP 500 and the
evaluator fails the run. The corpus is required, not best-effort.

It is read-only: add_texts/add_embeddings raise, so Vigil's /add/texts
endpoint and auto-update cannot write scan traffic into the shared corpus.

Selected in server.conf by setting [vectordb] chroma_url; without it Vigil
keeps upstream's local VectorDB.

Auth: chroma_url points at chroma-gateway (manifests/chroma/gateway.yaml),
which wants a bearer token. The token comes from the environment variable
named by [vectordb] token_env (default CHROMA_TOKEN, filled from a Secret),
never from server.conf, and never appears in errors or logs.

Stdlib HTTP only (urllib), like the corpus loader.
"""

import functools
import json
import os
import re
import threading
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

try:  # Inside Vigil; the unit tests run without it.
    from loguru import logger
except ImportError:  # pragma: no cover
    import logging

    logger = logging.getLogger("remote_vectordb")
    logger.success = logger.info  # type: ignore[attr-defined]

# Sentence split shared with the corpus builder (hack/vigil-corpus/), which
# imports it from here: the calibrated thresholds hold only for this split.
MAX_SENTENCE_WORDS = 40   # longer runs (code, no punctuation) are cut into 40-word pieces
MIN_SENTENCE_WORDS = 3    # shorter pieces ("Hi.", "Thanks!") say nothing
MAX_SENTENCES = 40        # per query text; a runner chunk has ~5

PROBE_TOLERANCE = 0.01    # max abs difference per recorded probe dimension


def sentences(text: str) -> List[str]:
    """Sentences of text (split after . ! ? and at newlines), >= 3 words, <= 40 words each."""
    out = []
    for part in re.split(r"(?<=[.!?])\s+|\n+", text):
        w = part.split()
        for i in range(0, len(w), MAX_SENTENCE_WORDS):
            piece = " ".join(w[i:i + MAX_SENTENCE_WORDS])
            if len(piece.split()) >= MIN_SENTENCE_WORDS:
                out.append(piece)
    return out


@functools.lru_cache(maxsize=None)
def load_model(name: str):
    """One SentenceTransformer per process: Vigil's Embedder shares it (Dockerfile patch)."""
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(name)


class RemoteVectorDBError(RuntimeError):
    """Chroma could not answer a query; the scan must fail closed."""


class RemoteVectorDB:
    def __init__(
        self,
        model: str,
        chroma_url: str,
        collections: str = "vigil_instruction_bypass,vigil_jailbreak",
        sentence_collections: str = "",
        tenant: str = "default_tenant",
        database: str = "default_database",
        n_results: str = "5",
        timeout_s: str = "5",
        token_env: str = "CHROMA_TOKEN",
        embed_fn: Optional[Callable[[List[str]], List[List[float]]]] = None,
        **_unused,  # upstream's local-db keys (collection, db_dir, ...) stay in the conf, unused
    ):
        self.name = "database:vector:remote"
        self.model = model
        self.base = chroma_url.rstrip("/")
        self.tenant = tenant
        self.database = database
        split = lambda s: [c.strip() for c in s.split(",") if c.strip()]  # noqa: E731
        self.collections = split(collections)
        self.sentence_collections = split(sentence_collections)
        if not self.collections:
            raise ValueError("[vectordb] collections is empty")
        self.n_results = int(n_results)
        self.timeout = float(timeout_s)
        self._ids: Dict[str, str] = {}
        self._meta: Dict[str, dict] = {}
        self._mode: Optional[str] = None  # "calibrated" | "legacy", decided on first use
        self._lock = threading.Lock()
        token = os.environ.get(token_env, "")
        self._auth = {"Authorization": f"Bearer {token}"} if token else {}
        if embed_fn is None:
            st = load_model(model)
            embed_fn = lambda texts: st.encode(texts, normalize_embeddings=True).tolist()  # noqa: E731
        self.embed = embed_fn
        # No Chroma call here: Vigil must boot (and answer 500 per scan) even
        # while Chroma is down; collections are resolved and checked on first use.
        logger.success(
            f"Remote vector db: {self.base} tenant={tenant} database={database} collections={self.collections}"
            f" sentence_collections={self.sentence_collections}"
            f" auth={'bearer from $' + token_env if token else 'none'}"
        )

    # -- upstream VectorDB interface --------------------------------------------------

    def query(self, text: str) -> dict:
        self._prepare()
        if self._mode == "legacy":
            return self._query_legacy(text)
        return self._query_calibrated(text)

    def add_texts(self, texts, metadatas):
        raise RemoteVectorDBError("the shared corpus is read-only from Vigil")

    def add_embeddings(self, texts, embeddings, metadatas):
        raise RemoteVectorDBError("the shared corpus is read-only from Vigil")

    # -- modes ------------------------------------------------------------------------

    def _query_legacy(self, text: str) -> dict:
        embedding = self.embed([text])[0]
        hits = []
        for name in self.collections:
            for doc, meta, dist in self._nearest(name, [embedding], self.n_results)[0]:
                hits.append((dist, doc, meta))
        hits.sort(key=lambda h: h[0])
        return _shape(hits[: self.n_results])

    def _query_calibrated(self, text: str) -> dict:
        prefix = self._prefix
        sents = sentences(text)[:MAX_SENTENCES] if self.sentence_collections else []
        vectors = self.embed([prefix + text] + [prefix + s for s in sents])
        hits = []
        for name in self.collections:
            thr = self._meta[name]["vigil_threshold"]
            for doc, meta, dist in self._nearest(name, vectors[:1], self.n_results)[0]:
                if dist < thr:
                    hits.append((dist, doc, {**meta, "threshold": thr, "kind": "whole"}))
        if sents:
            for name in self.sentence_collections:
                thr = self._meta[name]["vigil_threshold"]
                for sent, row in zip(sents, self._nearest(name, vectors[1:], 1)):
                    for doc, meta, dist in row:
                        if dist < thr:
                            hits.append((dist, doc, {**meta, "threshold": thr, "kind": "sentence", "input_sentence": sent}))
        # Closest relative to its own threshold first; one hit per corpus text.
        hits.sort(key=lambda h: h[0] / h[2]["threshold"])
        seen, out = set(), []
        for h in hits:
            if h[1] not in seen:
                seen.add(h[1])
                out.append(h)
        return _shape(out[: self.n_results])

    # -- corpus checks ------------------------------------------------------------------

    def _prepare(self) -> None:
        if self._mode is not None:
            return
        with self._lock:
            if self._mode is not None:
                return
            names = self.collections + self.sentence_collections
            for name in names:
                self._collection_id(name)
            calibrated = [n for n in names if "vigil_threshold" in self._meta[n]]
            if not calibrated:
                if self.sentence_collections:
                    raise RemoteVectorDBError("sentence_collections need calibrated collections (vigil_threshold metadata)")
                self._mode = "legacy"
                logger.success("Remote vector db: legacy mode (no calibration metadata), scanner threshold applies")
                return
            if len(calibrated) != len(names):
                raise RemoteVectorDBError(f"mixed corpus: only {calibrated} of {names} carry calibration metadata")
            for name in names:
                m = self._meta[name]
                if m.get("vigil_embedding_model") != self.model:
                    raise RemoteVectorDBError(
                        f"collection {name!r} was embedded with {m.get('vigil_embedding_model')!r}, Vigil embeds with {self.model!r}")
                want = "sentence" if name in self.sentence_collections else "whole"
                if m.get("vigil_kind") != want:
                    raise RemoteVectorDBError(f"collection {name!r} holds {m.get('vigil_kind')!r} texts, configured as {want}")
            prefixes = {self._meta[n].get("vigil_text_prefix", "") for n in names}
            if len(prefixes) != 1:
                raise RemoteVectorDBError(f"collections disagree on the text prefix: {sorted(prefixes)}")
            self._prefix = prefixes.pop()
            self._check_probe(names)
            self._mode = "calibrated"
            logger.success(
                "Remote vector db: calibrated hybrid mode, thresholds "
                + ", ".join(f"{n}={self._meta[n]['vigil_threshold']:.4f}" for n in names))

    def _check_probe(self, names: List[str]) -> None:
        m = self._meta[names[0]]
        try:
            probe_text = m["vigil_probe_text"]
            want = json.loads(m["vigil_probe_head"])
        except (KeyError, ValueError) as err:
            raise RemoteVectorDBError(f"collection {names[0]!r} has no usable embedding probe") from err
        got = self.embed([self._prefix + probe_text])[0][: len(want)]
        diff = max(abs(a - b) for a, b in zip(got, want))
        if diff > PROBE_TOLERANCE:
            raise RemoteVectorDBError(
                f"embedder does not reproduce the corpus (probe differs by {diff:.4f} > {PROBE_TOLERANCE}):"
                " different model revision, library version or prefix")

    # -- REST v2 ----------------------------------------------------------------------

    def _api(self, path: str) -> str:
        return f"{self.base}/api/v2/tenants/{self.tenant}/databases/{self.database}{path}"

    def _collection_id(self, name: str) -> str:
        if name not in self._ids:
            res = self._request("GET", self._api(f"/collections/{name}"))
            if not isinstance(res, dict) or not res.get("id"):
                raise RemoteVectorDBError(f"collection {name!r} not found: {str(res)[:200]}")
            self._ids[name] = res["id"]
            self._meta[name] = dict(res.get("metadata") or {})
        return self._ids[name]

    def _nearest(self, name: str, embeddings: List[List[float]], n: int):
        """Per query embedding, its n nearest (document, metadata, distance) in collection name."""
        res = self._post(
            f"/collections/{self._collection_id(name)}/query",
            {"query_embeddings": embeddings, "n_results": n, "include": ["documents", "metadatas", "distances"]},
        )
        try:
            docs, metas, dists = res["documents"], res["metadatas"], res["distances"]
            if not (len(docs) == len(dists) == len(embeddings)):
                raise ValueError("row count")
        except (KeyError, TypeError, ValueError) as err:
            raise RemoteVectorDBError(f"unexpected query answer from {name}: {str(res)[:200]}") from err
        rows = []
        for i, (d_row, dist_row) in enumerate(zip(docs, dists)):
            m_row = (metas[i] if metas else None) or [None] * len(d_row)
            row = []
            for doc, meta, dist in zip(d_row, m_row, dist_row):
                if not isinstance(dist, (int, float)):
                    raise RemoteVectorDBError(f"non-numeric distance from {name}: {dist!r}")
                meta = dict(meta or {})
                meta.setdefault("collection", name)
                row.append((doc, meta, float(dist)))
            rows.append(row)
        return rows

    def _post(self, path: str, payload: dict):
        try:
            return self._request("POST", self._api(path), payload)
        except RemoteVectorDBError:
            # A collection re-created by the loader (RECREATE=1) has a new id.
            self._ids.clear()
            raise

    def _request(self, method: str, url: str, payload: Optional[dict] = None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = dict(self._auth)
        if data:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as err:
            detail = err.read()[:200].decode(errors="replace")
            raise RemoteVectorDBError(f"{method} {url}: HTTP {err.code} {detail}") from err
        except (urllib.error.URLError, OSError, TimeoutError) as err:
            raise RemoteVectorDBError(f"{method} {url}: {err}") from err
        try:
            return json.loads(body)
        except ValueError as err:
            raise RemoteVectorDBError(f"{method} {url}: answer is not JSON") from err


def _shape(hits) -> dict:
    """(distance, document, metadata) tuples -> upstream's query answer shape."""
    return {
        "documents": [[h[1] for h in hits]],
        "metadatas": [[h[2] for h in hits]],
        "distances": [[h[0] for h in hits]],
    }
