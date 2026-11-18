"""Put the chunks of one chunking strategy into a Chroma collection.

There is one collection per strategy, holding all four sources, so the
three chunkers can be compared on the same store and the same model.
"""

from pathlib import Path
from typing import List

import chromadb

from corpus.common import Chunk, load_chunks

SOURCES = ["asvs", "cwe", "pci", "cbn"]
STRATEGIES = ["fixed_window", "recursive", "structure_aware"]


def collection_name(strategy: str) -> str:
    return f"chunks_{strategy}"


def source_of(chunk_id: str) -> str:
    return chunk_id.split("-")[0]


def load_strategy(strategy: str, chunk_dir) -> List[Chunk]:
    """Every source's chunks for one strategy, in a fixed order."""
    chunks = []
    for source in SOURCES:
        path = Path(chunk_dir) / f"{source}_{strategy}.jsonl"
        if not path.exists():
            raise FileNotFoundError(
                f"{path} is missing. Run build_corpus.py first.")
        chunks.extend(load_chunks(path))
    return chunks


def build_index(strategy: str, chunks: List[Chunk], embedder, db_path,
                batch_size: int = 64) -> int:
    """Embed the chunks and store them. An existing collection for the
    strategy is dropped first, so a rerun starts clean."""
    client = chromadb.PersistentClient(path=str(db_path))
    name = collection_name(strategy)
    if name in [c.name for c in client.list_collections()]:
        client.delete_collection(name)
    collection = client.create_collection(name, metadata={"hnsw:space": "cosine"})

    for start in range(0, len(chunks), batch_size):
        batch = chunks[start:start + batch_size]
        vectors = embedder.embed_documents([c.text for c in batch])
        collection.add(
            ids=[c.chunk_id for c in batch],
            embeddings=[v.tolist() for v in vectors],
            documents=[c.text for c in batch],
            metadatas=[{"source": source_of(c.chunk_id),
                        "strategy": c.strategy,
                        "shortcodes": "|".join(c.source_shortcodes)}
                       for c in batch],
        )
    return collection.count()
