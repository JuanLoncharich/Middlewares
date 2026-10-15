"""Vigil vector database backend for the distributed Chroma (REST API v2).

Copied into the vigil-llm image as vigil/core/remote_vectordb.py
(images/vigil-llm/Dockerfile, patch 6). Upstream's VectorDB is a local
chromadb==0.4.17 PersistentClient; the platform's corpus lives in the
distributed Rust Chroma (manifests/chroma/), which only speaks REST v2. This
client:

  - embeds the text locally with the configured SentenceTransformer
    (all-MiniLM-L6-v2, the model the corpora were embedded with);
  - queries every configured collection (vigil_instruction_bypass,
    vigil_jailbreak by default, loaded by images/vigil-corpus-loader);
  - merges the hits by cosine distance and returns upstream's query shape
    ({"documents": [[...]], "metadatas": [[...]], "distances": [[...]]}),
    so upstream's vectordb scanner and its threshold apply unchanged;
  - RAISES on any Chroma error, timeout, missing collection or bad answer.
    With the image's fail-closed patch, the scan answers HTTP 500 and the
    evaluator fails the run: the corpus is required, not best-effort.

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

import json
import os
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

try:  # Inside Vigil; the unit tests run without it.
    from loguru import logger
except ImportError:  # pragma: no cover
    import logging

    logger = logging.getLogger("remote_vectordb")
    logger.success = logger.info  # type: ignore[attr-defined]


class RemoteVectorDBError(RuntimeError):
    """Chroma could not answer a query; the scan must fail closed."""


class RemoteVectorDB:
    def __init__(
        self,
        model: str,
        chroma_url: str,
        collections: str = "vigil_instruction_bypass,vigil_jailbreak",
        tenant: str = "default_tenant",
        database: str = "default_database",
        n_results: str = "5",
        timeout_s: str = "5",
        token_env: str = "CHROMA_TOKEN",
        embed_fn: Optional[Callable[[str], List[float]]] = None,
        **_unused,  # upstream's local-db keys (collection, db_dir, ...) stay in the conf, unused
    ):
        self.name = "database:vector:remote"
        self.base = chroma_url.rstrip("/")
        self.tenant = tenant
        self.database = database
        self.collections = [c.strip() for c in collections.split(",") if c.strip()]
        if not self.collections:
            raise ValueError("[vectordb] collections is empty")
        self.n_results = int(n_results)
        self.timeout = float(timeout_s)
        self._ids: Dict[str, str] = {}
        token = os.environ.get(token_env, "")
        self._auth = {"Authorization": f"Bearer {token}"} if token else {}
        if embed_fn is None:
            from sentence_transformers import SentenceTransformer

            st = SentenceTransformer(model)
            embed_fn = lambda text: st.encode(text).tolist()  # noqa: E731
        self.embed = embed_fn
        # No Chroma call here: Vigil must boot (and answer 500 per scan) even
        # while Chroma is down; collection ids are resolved on first use.
        logger.success(
            f"Remote vector db: {self.base} tenant={tenant} database={database} collections={self.collections}"
            f" auth={'bearer from $' + token_env if token else 'none'}"
        )

    # -- upstream VectorDB interface --------------------------------------------------

    def query(self, text: str) -> dict:
        embedding = self.embed(text)
        hits = []
        for name in self.collections:
            res = self._post(
                f"/collections/{self._collection_id(name)}/query",
                {"query_embeddings": [embedding], "n_results": self.n_results,
                 "include": ["documents", "metadatas", "distances"]},
            )
            try:
                docs, metas, dists = res["documents"][0], res["metadatas"][0], res["distances"][0]
            except (KeyError, IndexError, TypeError) as err:
                raise RemoteVectorDBError(f"unexpected query answer from {name}: {str(res)[:200]}") from err
            for doc, meta, dist in zip(docs, metas or [None] * len(docs), dists):
                if not isinstance(dist, (int, float)):
                    raise RemoteVectorDBError(f"non-numeric distance from {name}: {dist!r}")
                meta = dict(meta or {})
                meta.setdefault("collection", name)
                hits.append((float(dist), doc, meta))
        hits.sort(key=lambda h: h[0])
        hits = hits[: self.n_results]
        return {
            "documents": [[h[1] for h in hits]],
            "metadatas": [[h[2] for h in hits]],
            "distances": [[h[0] for h in hits]],
        }

    def add_texts(self, texts, metadatas):
        raise RemoteVectorDBError("the shared corpus is read-only from Vigil")

    def add_embeddings(self, texts, embeddings, metadatas):
        raise RemoteVectorDBError("the shared corpus is read-only from Vigil")

    # -- REST v2 ----------------------------------------------------------------------

    def _api(self, path: str) -> str:
        return f"{self.base}/api/v2/tenants/{self.tenant}/databases/{self.database}{path}"

    def _collection_id(self, name: str) -> str:
        if name not in self._ids:
            res = self._request("GET", self._api(f"/collections/{name}"))
            if not isinstance(res, dict) or not res.get("id"):
                raise RemoteVectorDBError(f"collection {name!r} not found: {str(res)[:200]}")
            self._ids[name] = res["id"]
        return self._ids[name]

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
