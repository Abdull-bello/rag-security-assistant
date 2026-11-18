"""Command-line assistant (FR11).

  python assist.py "Unsanitized SQL query built from user input (CWE-89)" --model qwen2.5:3b
  python assist.py "..." --strategy structure_aware --mode hybrid --model <ollama model>
"""
import argparse, json
from pathlib import Path

from generation.ollama import OllamaGenerator
from generation.pipeline import assist
from retrieval.embed import Embedder, Reranker
from retrieval.search import Retriever


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("finding")
    p.add_argument("--model", required=True, help="Ollama model name")
    p.add_argument("--strategy", default="structure_aware",
                   choices=["fixed_window", "recursive", "structure_aware"])
    p.add_argument("--mode", default="hybrid", choices=["bm25", "dense", "hybrid", "rerank"])
    p.add_argument("--alpha", type=float, default=0.7)
    p.add_argument("--baseline", action="store_true", help="no retrieval")
    p.add_argument("--db", default="chroma_db")
    p.add_argument("--save", help="append the run record to this JSONL file")
    a = p.parse_args(argv)

    retriever = None
    if not a.baseline:
        retriever = Retriever(a.strategy, Embedder(), a.db,
                              Reranker() if a.mode == "rerank" else None)
    record = assist(a.finding, retriever, OllamaGenerator(a.model), a.mode, alpha=a.alpha)
    print(record["output"])
    print("\nEVIDENCE:")
    for e in record["evidence"]:
        print(f"  [{e['label']}] {e['chunk_id']} ({e['source']})")
    print("\nCHECK:", json.dumps(record["validation"]))
    if a.save:
        with open(a.save, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    main()
