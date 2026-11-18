"""The four retrieval measures from Chapter 3.

Each function takes the labels of the judged chunks in rank order, so the
first number is the label of the best-ranked judged chunk. A label is 2 for
the same weakness, 1 for a parent or child, 0 otherwise.
"""

import math
from typing import List, Optional


def precision_at_k(labels: List[int], k: int = 5) -> float:
    """Share of the top k judged chunks with a label of 1 or 2."""
    top = labels[:k]
    if not top:
        return 0.0
    return sum(1 for label in top if label >= 1) / len(top)


def recall_at_k(labels: List[int], total_relevant: int, k: int = 5) -> Optional[float]:
    """Share of all relevant chunks in the collection that are in the top k.
    None when the collection holds no relevant chunk for this finding."""
    if total_relevant == 0:
        return None
    return sum(1 for label in labels[:k] if label >= 1) / total_relevant


def reciprocal_rank(labels: List[int], k: int = 5) -> float:
    """One over the rank of the first chunk with label 2, 0 if there is none
    in the top k."""
    for rank, label in enumerate(labels[:k], start=1):
        if label == 2:
            return 1 / rank
    return 0.0


def dcg(labels: List[int], k: int = 5) -> float:
    return sum((2 ** label - 1) / math.log2(rank + 1)
               for rank, label in enumerate(labels[:k], start=1))


def ndcg_at_k(labels: List[int], all_labels: List[int], k: int = 5) -> Optional[float]:
    """DCG of the ranking divided by the DCG of the best possible ranking
    of every judged chunk in the collection. None when no chunk could earn
    any gain."""
    ideal = dcg(sorted(all_labels, reverse=True), k)
    if ideal == 0:
        return None
    return dcg(labels, k) / ideal
