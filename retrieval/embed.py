"""The dense embedding model and the reranker, both from BAAI.

They are loaded on first use, so importing this module is cheap and the
tests can pass in small stand-ins instead.
"""

import numpy as np

EMBED_MODEL = "BAAI/bge-base-en-v1.5"
RERANK_MODEL = "BAAI/bge-reranker-base"

# bge models expect this prefix on a short query, not on the passages
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


class Embedder:
    def __init__(self, model_name: str = EMBED_MODEL):
        self.model_name = model_name
        self._model = None

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name, device="cpu")
        return self._model

    def embed_documents(self, texts, batch_size: int = 16) -> np.ndarray:
        return self._load().encode(
            list(texts), batch_size=batch_size, normalize_embeddings=True,
            show_progress_bar=len(texts) > 200)

    def embed_query(self, text: str) -> np.ndarray:
        return self._load().encode(
            QUERY_PREFIX + text, normalize_embeddings=True)


class Reranker:
    def __init__(self, model_name: str = RERANK_MODEL):
        self.model_name = model_name
        self._model = None

    def score(self, query: str, texts) -> list:
        if self._model is None:
            from sentence_transformers import CrossEncoder
            self._model = CrossEncoder(self.model_name, device="cpu")
        pairs = [(query, t) for t in texts]
        return [float(x) for x in self._model.predict(pairs)]
