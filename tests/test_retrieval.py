import tempfile
import unittest

import numpy as np

from corpus.common import Chunk
from retrieval.index import build_index, source_of
from retrieval.search import Retriever, min_max, tokenize

WORDS = ["sql", "injection", "query", "parameterized", "password", "hash",
         "salt", "path", "traversal", "file", "redirect", "url", "cookie",
         "secure", "random", "key", "encrypt", "token"]


class WordEmbedder:
    """A stand-in for the real model: one dimension per word, so texts that
    share words get similar vectors. Good enough to test the plumbing."""

    def _vec(self, text):
        words = tokenize(text)
        v = np.array([words.count(w) for w in WORDS], dtype=float)
        norm = np.linalg.norm(v)
        return v / norm if norm else v

    def embed_documents(self, texts, batch_size=16):
        return np.array([self._vec(t) for t in texts])

    def embed_query(self, text):
        return self._vec(text)


class LengthReranker:
    """Prefers the shortest text, so the effect on the order is easy to see."""

    def score(self, query, texts):
        return [-len(t) for t in texts]


def make_chunks():
    texts = {
        "cwe-struct-89-mitigations": "Use a parameterized query to stop sql injection.",
        "cwe-struct-22-definition": "A path traversal reads a file outside the folder.",
        "asvs-struct-2.4": "Store a password with a salt and a slow hash.",
        "pci-struct-3.5": "Encrypt the key and protect the token with a secure cookie.",
        "cbn-struct-part4": "Use a random token and a url redirect check, with a parameterized query.",
    }
    return [Chunk(cid, text, "structure_aware", [cid]) for cid, text in texts.items()]


class RetrievalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Chroma keeps its files open on Windows, so deleting the folder can fail
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.chunks = make_chunks()
        stored = build_index("structure_aware", cls.chunks, WordEmbedder(), cls.tmp.name)
        cls.stored = stored
        cls.retriever = Retriever("structure_aware", WordEmbedder(), cls.tmp.name,
                                  LengthReranker())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_chunk_is_stored(self):
        self.assertEqual(self.stored, len(self.chunks))

    def test_rebuilding_does_not_duplicate(self):
        again = build_index("structure_aware", self.chunks, WordEmbedder(), self.tmp.name)
        self.assertEqual(again, len(self.chunks))

    def test_source_comes_from_the_id(self):
        self.assertEqual(source_of("cwe-struct-89-mitigations"), "cwe")

    def test_tokenize_splits_identifiers(self):
        self.assertEqual(tokenize("CWE-89 and 1.2.5"), ["cwe", "89", "and", "1", "2", "5"])

    def test_min_max_scales_to_zero_and_one(self):
        out = min_max(np.array([2.0, 4.0, 6.0]))
        self.assertEqual(list(out), [0.0, 0.5, 1.0])

    def test_min_max_of_equal_scores_is_zero(self):
        self.assertEqual(list(min_max(np.array([3.0, 3.0]))), [0.0, 0.0])

    def test_bm25_finds_the_matching_words(self):
        hits = self.retriever.bm25_search("path traversal file", k=1)
        self.assertEqual(hits[0].chunk_id, "cwe-struct-22-definition")

    def test_dense_finds_the_matching_words(self):
        hits = self.retriever.dense_search("password salt hash", k=1)
        self.assertEqual(hits[0].chunk_id, "asvs-struct-2.4")

    def test_hit_carries_source(self):
        hit = self.retriever.bm25_search("sql injection", k=1)[0]
        self.assertEqual(hit.source, "cwe")
        self.assertEqual(hit.shortcodes, ["cwe-struct-89-mitigations"])

    def test_hybrid_with_alpha_one_follows_bm25(self):
        q = "parameterized query sql"
        bm25 = [h.chunk_id for h in self.retriever.bm25_search(q, k=5)]
        hybrid = [h.chunk_id for h in self.retriever.hybrid_search(q, k=5, alpha=1.0)]
        self.assertEqual(bm25, hybrid)

    def test_hybrid_with_alpha_zero_follows_dense(self):
        q = "parameterized query sql"
        dense = [h.chunk_id for h in self.retriever.dense_search(q, k=5)]
        hybrid = [h.chunk_id for h in self.retriever.hybrid_search(q, k=5, alpha=0.0)]
        self.assertEqual(dense, hybrid)

    def test_rerank_reorders_the_candidates(self):
        hits = self.retriever.rerank_search("parameterized query", k=2, pool=3)
        lengths = [len(h.text) for h in hits]
        self.assertEqual(lengths, sorted(lengths))

    def test_rerank_without_a_reranker_fails_clearly(self):
        plain = Retriever("structure_aware", WordEmbedder(), self.tmp.name)
        with self.assertRaises(ValueError):
            plain.rerank_search("sql")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            self.retriever.search("sql", mode="nonsense")


if __name__ == "__main__":
    unittest.main()
