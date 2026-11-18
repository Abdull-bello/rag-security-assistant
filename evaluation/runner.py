"""Score the retrieval of one test item, and add the items up."""

import csv
from collections import defaultdict
from statistics import mean
from typing import Dict, List

from retrieval.search import DEFAULT_ALPHA, DEFAULT_POOL

from .judge import chunk_label, collection_labels, is_judged
from .metrics import ndcg_at_k, precision_at_k, recall_at_k, reciprocal_rank

METRICS = ["p_at_5", "r_at_5", "mrr", "ndcg_at_5", "unjudged_share"]
ITEM_COLUMNS = ["item_id", "cwe_class", "query", "finding_cwe"]


def load_items(path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = [c for c in ITEM_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(missing)}")
        items = []
        for row in reader:
            row["finding_cwe"] = row["finding_cwe"].strip().replace("CWE-", "")
            items.append(row)
    return items


def score_item(retriever, query: str, finding_cwe: str, by_id, mode: str,
               k: int = 5, depth: int = 100, alpha: float = DEFAULT_ALPHA,
               pool: int = DEFAULT_POOL) -> dict:
    """Retrieve deep enough to find k judged chunks, drop the unjudged ones,
    and score the first k that remain. The share of unjudged chunks is taken
    from the plain top k, before anything is dropped."""
    hits = retriever.search(query, mode, k=depth, alpha=alpha, pool=pool)

    top_raw = hits[:k]
    unjudged_share = (sum(1 for h in top_raw if not is_judged(h.source))
                      / len(top_raw)) if top_raw else 0.0

    judged = [h for h in hits if is_judged(h.source)][:k]
    labels = [chunk_label(h.shortcodes, finding_cwe, by_id) for h in judged]

    everything = collection_labels(retriever, finding_cwe, by_id)
    total_relevant = sum(1 for label in everything if label >= 1)

    return {
        "p_at_5": precision_at_k(labels, k),
        "r_at_5": recall_at_k(labels, total_relevant, k),
        "mrr": reciprocal_rank(labels, k),
        "ndcg_at_5": ndcg_at_k(labels, everything, k),
        "unjudged_share": unjudged_share,
        "judged_found": len(judged),
        "relevant_in_collection": total_relevant,
    }


def summarise(rows: List[dict]) -> List[dict]:
    """Mean of each measure for every strategy and mode, over all items
    and then for each class. An item with an undefined measure (None) is
    left out of that measure's mean only, and n says how many were used."""
    groups = defaultdict(list)
    for row in rows:
        for cwe_class in ("ALL", row["cwe_class"]):
            groups[(row["strategy"], row["mode"], cwe_class)].append(row)

    summary = []
    for (strategy, mode, cwe_class), members in sorted(groups.items()):
        entry = {"strategy": strategy, "mode": mode, "cwe_class": cwe_class,
                 "items": len(members)}
        for metric in METRICS:
            values = [m[metric] for m in members if m[metric] is not None]
            entry[metric] = round(mean(values), 4) if values else None
            entry[f"n_{metric}"] = len(values)
        summary.append(entry)
    return summary
