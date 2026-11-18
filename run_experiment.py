"""Run conditions over the test set, one record per (condition, item).

Stage 1 (chunker varies, retrieval hybrid):  S1_fixed, S1_recursive, S1_structure
Stage 2 (chunker fixed to the Stage 1 winner): S2_bm25, S2_dense, S2_rerank
Baseline (no retrieval): BASE

  python run_experiment.py --model qwen2.5:3b --conditions BASE S1_fixed S1_recursive S1_structure
  python run_experiment.py --model qwen2.5:3b --winner structure_aware --conditions S2_bm25 S2_dense S2_rerank

Resumable: records already in the output file are skipped, so you can stop
with Ctrl+C and start again. Use --limit to run only the first N items.
"""
import argparse, csv, json, random, time
from pathlib import Path

from generation.ollama import OllamaGenerator
from generation.pipeline import assist
from retrieval.embed import Embedder, Reranker
from retrieval.search import Retriever

CONDITIONS = {
    "BASE":          (None, None),
    "S1_fixed":      ("fixed_window", "hybrid"),
    "S1_recursive":  ("recursive", "hybrid"),
    "S1_structure":  ("structure_aware", "hybrid"),
    "S2_bm25":       ("WINNER", "bm25"),
    "S2_dense":      ("WINNER", "dense"),
    "S2_rerank":     ("WINNER", "rerank"),
}


def done_keys(path):
    keys = set()
    if Path(path).exists():
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            keys.add((r["condition"], r["item_id"]))
    return keys


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--items", default="data/test_items.csv")
    p.add_argument("--model", required=True)
    p.add_argument("--conditions", nargs="+", required=True, choices=list(CONDITIONS))
    p.add_argument("--winner", help="chunking strategy for the Stage 2 conditions")
    p.add_argument("--alpha", type=float, default=0.7)
    p.add_argument("--limit", type=int)
    p.add_argument("--out", default="output/runs.jsonl")
    p.add_argument("--db", default="chroma_db")
    a = p.parse_args(argv)

    with open(a.items, newline="", encoding="utf-8-sig") as f:
        items = list(csv.DictReader(f))
    if a.limit:
        items = items[:a.limit]
    Path(a.out).parent.mkdir(exist_ok=True)
    generator = OllamaGenerator(a.model)
    seen = done_keys(a.out)
    reranker = Reranker() if "S2_rerank" in a.conditions else None
    embedder = Embedder()

    for cond in a.conditions:
        strategy, mode = CONDITIONS[cond]
        if strategy == "WINNER":
            if not a.winner:
                raise SystemExit(f"{cond} needs --winner")
            strategy = a.winner
        retriever = (Retriever(strategy, embedder, a.db, reranker)
                     if strategy else None)
        for n, item in enumerate(items, 1):
            if (cond, item["item_id"]) in seen:
                continue
            rec = assist(item["query"], retriever, generator, mode or "hybrid", alpha=a.alpha,
                         code=item.get("snippet", ""))
            rec.update({"condition": cond, "strategy": strategy, "mode": mode,
                        "item_id": item["item_id"], "cwe_class": item["cwe_class"],
                        "finding_cwe": item["finding_cwe"],
                        "ground_truth": item.get("ground_truth", "")})
            with open(a.out, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            print(f"{cond} {n}/{len(items)} {item['item_id']} {rec['seconds']}s "
                  f"verdict={rec['validation']['verdict']}", flush=True)


if __name__ == "__main__":
    main()
