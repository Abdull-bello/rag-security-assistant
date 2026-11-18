"""Ask the index a question and print the top chunks, to see it working.

    python try_search.py "how do I prevent SQL injection" structure_aware hybrid
"""

import sys
from pathlib import Path

from retrieval.embed import Embedder, Reranker
from retrieval.search import MODES, Retriever

DB_PATH = Path("chroma_db")


def main(args):
    if not args:
        print('Usage: python try_search.py "question" [strategy] [mode]')
        print(f"Modes: {MODES}")
        return 1
    query = args[0]
    strategy = args[1] if len(args) > 1 else "structure_aware"
    mode = args[2] if len(args) > 2 else "hybrid"

    reranker = Reranker() if mode == "rerank" else None
    retriever = Retriever(strategy, Embedder(), DB_PATH, reranker)
    for rank, hit in enumerate(retriever.search(query, mode, k=5), start=1):
        print(f"{rank}. [{hit.source}] {hit.chunk_id}  score {hit.score:.3f}")
        print("   " + hit.text[:200].replace("\n", " "))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
