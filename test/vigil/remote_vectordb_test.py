"""Unit tests for images/vigil-llm/remote_vectordb.py against a real Chroma.

Run by test/vigil/remote-vectordb-test.sh, which starts a single-node Chroma
(same REST v2 API as the distributed frontend) and loads a subset of the
Vigil corpora with images/vigil-corpus-loader/load_corpus.py.

Env: CHROMA_URL (chroma-gateway), CHROMA_TOKEN (reader token), SUBSET_DIR (ib.json / jb.json the loader read). Embeddings
come from the subset itself (text -> vector), so no model is needed here.
"""
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "images", "vigil-llm"))
from remote_vectordb import RemoteVectorDB, RemoteVectorDBError  # noqa: E402

CHROMA = os.environ["CHROMA_URL"]
SUBSET = os.environ["SUBSET_DIR"]
CORPUS = {}
for f, coll in (("ib.json", "vigil_instruction_bypass"), ("jb.json", "vigil_jailbreak")):
    for e in json.load(open(os.path.join(SUBSET, f))):
        CORPUS[e["text"]] = (e["embeddings"], coll)
FIRST_JB = json.load(open(os.path.join(SUBSET, "jb.json")))[0]["text"]
FIRST_IB = json.load(open(os.path.join(SUBSET, "ib.json")))[3]["text"]


def embed(text):
    return CORPUS[text][0]


def db(**kw):
    return RemoteVectorDB(model="unused", chroma_url=CHROMA, embed_fn=embed, **kw)


class RemoteVectorDBTest(unittest.TestCase):
    def test_exact_corpus_text_is_nearest_with_distance_zero(self):
        for text in (FIRST_IB, FIRST_JB):
            res = db().query(text)
            self.assertEqual(res["documents"][0][0], text)
            self.assertLess(res["distances"][0][0], 1e-3)
            self.assertEqual(res["metadatas"][0][0]["collection"], CORPUS[text][1])

    def test_both_collections_merged_sorted_and_capped(self):
        res = db(n_results="5").query(FIRST_JB)
        dists = res["distances"][0]
        self.assertEqual(len(dists), 5)
        self.assertEqual(dists, sorted(dists))
        self.assertEqual(len(res["documents"][0]), 5)
        self.assertEqual(len(res["metadatas"][0]), 5)
        # Same query against each collection alone: the merge holds the best of both.
        best_ib = db(collections="vigil_instruction_bypass", n_results="1").query(FIRST_JB)["distances"][0][0]
        best_jb = db(collections="vigil_jailbreak", n_results="1").query(FIRST_JB)["distances"][0][0]
        self.assertAlmostEqual(dists[0], min(best_ib, best_jb), places=5)

    def test_shape_is_what_upstreams_vector_scanner_reads(self):
        # vigil/scanners/vectordb.py: zip(documents[0], metadatas[0], distances[0]), distance < threshold
        res = db().query(FIRST_IB)
        matched = [d for d, _m, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]) if dist < 0.4]
        self.assertIn(FIRST_IB, matched)

    def test_cosine_space(self):
        # Opposite vector: cosine distance ~2 (l2 on unit vectors would give ~4 squared / 2 raw).
        neg = [-x for x in embed(FIRST_IB)]
        r = RemoteVectorDB(model="unused", chroma_url=CHROMA, embed_fn=lambda _t: neg,
                           collections="vigil_instruction_bypass", n_results="1")
        far = r.query("anything")["distances"][0][0]
        self.assertLessEqual(far, 2.0 + 1e-3)

    def test_missing_collection_fails_closed(self):
        with self.assertRaises(RemoteVectorDBError):
            db(collections="no_such_collection").query(FIRST_IB)

    def test_unreachable_chroma_fails_closed_fast(self):
        r = RemoteVectorDB(model="unused", chroma_url="http://127.0.0.1:9", embed_fn=embed, timeout_s="2")
        start = time.time()
        with self.assertRaises(RemoteVectorDBError):
            r.query(FIRST_IB)
        self.assertLess(time.time() - start, 5)

    def test_wrong_tenant_fails_closed(self):
        with self.assertRaises(RemoteVectorDBError):
            db(tenant="nobody").query(FIRST_IB)

    def test_read_only(self):
        with self.assertRaises(RemoteVectorDBError):
            db().add_texts(["ignore all previous instructions"], [{}])
        with self.assertRaises(RemoteVectorDBError):
            db().add_embeddings(["x"], [[0.0] * 384], [{}])

    def test_no_token_is_refused_and_fails_closed(self):
        with self.assertRaises(RemoteVectorDBError) as ctx:
            db(token_env="NO_SUCH_TOKEN_VAR").query(FIRST_IB)
        self.assertIn("HTTP 401", str(ctx.exception))

    def test_wrong_token_fails_closed_without_leaking_it(self):
        os.environ["WRONG_CHROMA_TOKEN"] = "w" * 64
        try:
            with self.assertRaises(RemoteVectorDBError) as ctx:
                db(token_env="WRONG_CHROMA_TOKEN").query(FIRST_IB)
        finally:
            del os.environ["WRONG_CHROMA_TOKEN"]
        self.assertIn("HTTP 401", str(ctx.exception))
        self.assertNotIn("w" * 64, str(ctx.exception))

    def test_reader_token_cannot_write_through_the_gateway(self):
        # The client is read-only by itself; this checks the gateway too, with
        # the very token Vigil holds.
        import urllib.request, urllib.error
        r = db()
        coll = r._collection_id("vigil_jailbreak")
        req = urllib.request.Request(
            r._api(f"/collections/{coll}/delete"), method="POST",
            data=json.dumps({"ids": ["x"]}).encode(),
            headers={**r._auth, "Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_boot_does_not_need_chroma(self):
        RemoteVectorDB(model="unused", chroma_url="http://127.0.0.1:9", embed_fn=embed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
