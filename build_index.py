"""Embed the chunks made by build_corpus.py and store them in Chroma.

    python build_index.py                      # all three strategies
    python build_index.py structure_aware      # one strategy

The first run downloads the embedding model (about 440 MB). On a CPU it
takes a few minutes per strategy.
"""

import sys
import time
from pathlib import Path

from retrieval.embed import Embedder
from retrieval.index import STRATEGIES, build_index, load_strategy

CHUNK_DIR = Path("output/chunks")
DB_PATH = Path("chroma_db")


def main(names):
    unknown = [n for n in names if n not in STRATEGIES]
    if unknown:
        print(f"Unknown strategy: {', '.join(unknown)}. Choose from {STRATEGIES}.")
        return 1

    embedder = Embedder()
    for strategy in names:
        try:
            chunks = load_strategy(strategy, CHUNK_DIR)
        except FileNotFoundError as err:
            print(err)
            return 1
        start = time.time()
        stored = build_index(strategy, chunks, embedder, DB_PATH)
        print(f"{strategy}: {len(chunks)} chunks read, {stored} stored, "
              f"{time.time() - start:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or STRATEGIES))
