"""Score retrieval on the test items.

    python score_retrieval.py data/test_items.csv
    python score_retrieval.py data/test_items.csv --strategies structure_aware --modes bm25 hybrid

The items file needs the columns item_id, cwe_class, query and finding_cwe.
Run build_corpus.py and build_index.py first. Results go to output/.
"""

import argparse
import csv
import sys
from pathlib import Path

from corpus import cwe
from evaluation.runner import ITEM_COLUMNS, METRICS, load_items, score_item, summarise
from retrieval.embed import Embedder, Reranker
from retrieval.index import STRATEGIES
from retrieval.search import DEFAULT_ALPHA, DEFAULT_POOL, MODES, Retriever

CWE_CSV = Path("data/1000.csv")
DB_PATH = Path("chroma_db")
OUT_DIR = Path("output")


def write_csv(path, rows, columns):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("items", help="CSV file of test items")
    parser.add_argument("--strategies", nargs="+", default=STRATEGIES, choices=STRATEGIES)
    parser.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    parser.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)
    parser.add_argument("--pool", type=int, default=DEFAULT_POOL)
    args = parser.parse_args()

    if not CWE_CSV.exists():
        print(f"{CWE_CSV} is missing.")
        return 1
    by_id = {w.cwe_id: w for w in cwe.load(CWE_CSV)}
    all_items = load_items(args.items)
    # Items with the same query text and the same CWE retrieve the same
    # chunks, so each distinct query is scored once.
    items, seen = [], set()
    for item in all_items:
        key = (item["query"], item["finding_cwe"])
        if key not in seen:
            seen.add(key)
            items.append(item)
    print(f"{len(all_items)} items, {len(items)} distinct queries scored")
    for item in items:
        if item["finding_cwe"] not in by_id:
            print(f"Warning: item {item['item_id']} has CWE {item['finding_cwe']}, "
                  "which is not in the CWE file. Its labels will all be 0.")

    embedder = Embedder()
    reranker = Reranker() if "rerank" in args.modes else None
    rows = []
    for strategy in args.strategies:
        retriever = Retriever(strategy, embedder, DB_PATH, reranker)
        for mode in args.modes:
            for item in items:
                scores = score_item(retriever, item["query"], item["finding_cwe"],
                                    by_id, mode, alpha=args.alpha, pool=args.pool)
                rows.append({"strategy": strategy, "mode": mode, **item, **scores})
            print(f"{strategy} / {mode}: {len(items)} items scored")

    OUT_DIR.mkdir(exist_ok=True)
    item_cols = ["strategy", "mode"] + ITEM_COLUMNS + METRICS + [
        "judged_found", "relevant_in_collection"]
    write_csv(OUT_DIR / "retrieval_scores_items.csv", rows, item_cols)

    summary = summarise(rows)
    summary_cols = ["strategy", "mode", "cwe_class", "items"] + [
        c for m in METRICS for c in (m, f"n_{m}")]
    write_csv(OUT_DIR / "retrieval_scores_summary.csv", summary, summary_cols)

    print(f"\nAll items, mean per strategy and mode (alpha {args.alpha}):")
    print(f"{'strategy':16}{'mode':8}{'P@5':>7}{'R@5':>7}{'MRR':>7}{'nDCG':>7}{'unjudged':>10}")
    for s in summary:
        if s["cwe_class"] == "ALL":
            vals = [s[m] if s[m] is not None else float("nan") for m in METRICS]
            print(f"{s['strategy']:16}{s['mode']:8}"
                  f"{vals[0]:7.3f}{vals[1]:7.3f}{vals[2]:7.3f}{vals[3]:7.3f}{vals[4]:10.2f}")
    print(f"\nWritten to {OUT_DIR / 'retrieval_scores_items.csv'} and "
          f"{OUT_DIR / 'retrieval_scores_summary.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
