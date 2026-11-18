"""The four retrieval configurations from Chapter 3.

    bm25     keyword scoring only
    dense    embedding similarity only
    hybrid   alpha * norm(BM25) + (1 - alpha) * norm(dense)
    rerank   hybrid candidates rescored by the cross-encoder

The index is small (a few thousand chunks), so every chunk is scored for
every query. That keeps the min-max normalisation exact: it runs over the
whole corpus and not over a shortlist. Chroma holds the vectors on disk and
they are read into memory once when a Retriever is created.
"""

import re
from dataclasses import dataclass
from typing import List

import chromadb
import numpy as np
from rank_bm25 import BM25Okapi

from .index import collection_name

DEFAULT_ALPHA = 0.7      # BM25-heavy starting value, tuned later in the pilot
DEFAULT_POOL = 20        # candidates passed to the reranker

MODES = ["bm25", "dense", "hybrid", "rerank"]


@dataclass
class Hit:
    chunk_id: str
    text: str
    score: float
    source: str
    shortcodes: List[str]


def tokenize(text: str) -> List[str]:
    """Lower-case words and numbers. 'CWE-89' becomes 'cwe' and '89', so an
    identifier in the query still matches the same identifier in a chunk."""
    return re.findall(r"[a-z0-9]+", text.lower())


def min_max(scores: np.ndarray) -> np.ndarray:
    low, high = scores.min(), scores.max()
    if high == low:
        return np.zeros_like(scores, dtype=float)
    return (scores - low) / (high - low)


class Retriever:
    def __init__(self, strategy: str, embedder, db_path, reranker=None):
        self.embedder = embedder
        self.reranker = reranker

        client = chromadb.PersistentClient(path=str(db_path))
        stored = client.get_collection(collection_name(strategy)).get(
            include=["documents", "metadatas", "embeddings"])
        self.ids = stored["ids"]
        self.texts = stored["documents"]
        self.metas = stored["metadatas"]
        self.vectors = np.array(stored["embeddings"], dtype=float)
        self.bm25 = BM25Okapi([tokenize(t) for t in self.texts])

    def _hits(self, order, scores, k) -> List[Hit]:
        hits = []
        for i in order[:k]:
            meta = self.metas[i]
            hits.append(Hit(self.ids[i], self.texts[i], float(scores[i]),
                            meta["source"], meta["shortcodes"].split("|")))
        return hits

    def _bm25_scores(self, query: str) -> np.ndarray:
        return np.array(self.bm25.get_scores(tokenize(query)), dtype=float)

    def _dense_scores(self, query: str) -> np.ndarray:
        return self.vectors @ self.embedder.embed_query(query)

    def bm25_search(self, query: str, k: int = 5) -> List[Hit]:
        scores = self._bm25_scores(query)
        return self._hits(np.argsort(-scores, kind="stable"), scores, k)

    def dense_search(self, query: str, k: int = 5) -> List[Hit]:
        scores = self._dense_scores(query)
        return self._hits(np.argsort(-scores, kind="stable"), scores, k)

    def hybrid_search(self, query: str, k: int = 5,
                      alpha: float = DEFAULT_ALPHA) -> List[Hit]:
        scores = (alpha * min_max(self._bm25_scores(query))
                  + (1 - alpha) * min_max(self._dense_scores(query)))
        return self._hits(np.argsort(-scores, kind="stable"), scores, k)

    def rerank_search(self, query: str, k: int = 5,
                      alpha: float = DEFAULT_ALPHA,
                      pool: int = DEFAULT_POOL) -> List[Hit]:
        if self.reranker is None:
            raise ValueError("rerank_search needs a reranker")
        candidates = self.hybrid_search(query, pool, alpha)
        new_scores = self.reranker.score(query, [h.text for h in candidates])
        ranked = sorted(zip(candidates, new_scores), key=lambda p: -p[1])
        for hit, score in ranked:
            hit.score = score
        return [hit for hit, _ in ranked[:k]]

    def search(self, query: str, mode: str = "hybrid", k: int = 5,
               alpha: float = DEFAULT_ALPHA, pool: int = DEFAULT_POOL) -> List[Hit]:
        if mode == "bm25":
            return self.bm25_search(query, k)
        if mode == "dense":
            return self.dense_search(query, k)
        if mode == "hybrid":
            return self.hybrid_search(query, k, alpha)
        if mode == "rerank":
            return self.rerank_search(query, k, alpha, pool)
        raise ValueError(f"unknown mode '{mode}', expected one of {MODES}")
