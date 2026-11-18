"""Which retrieved chunks can be labelled, and what label they get.

Only chunks from the CWE source carry a CWE identifier, so only they are
judged. A fixed-window chunk can span several weaknesses. It gets the
highest label among them.
"""

from typing import Dict, List

from corpus.cwe import Weakness
from corpus.labels import relevance_label


def cwe_numbers(shortcodes: List[str]) -> List[str]:
    """['CWE-89', 'CWE-74'] -> ['89', '74']"""
    return [code[4:] for code in shortcodes if code.startswith("CWE-")]


def is_judged(source: str) -> bool:
    return source == "cwe"


def chunk_label(shortcodes: List[str], finding_cwe: str,
                by_id: Dict[str, Weakness]) -> int:
    labels = [relevance_label(finding_cwe, number, by_id)
              for number in cwe_numbers(shortcodes)]
    return max(labels, default=0)


def collection_labels(retriever, finding_cwe: str,
                      by_id: Dict[str, Weakness]) -> List[int]:
    """The label of every judged chunk in the collection. Recall and the
    ideal DCG are worked out against this list."""
    labels = []
    for meta in retriever.metas:
        if is_judged(meta["source"]):
            labels.append(chunk_label(meta["shortcodes"].split("|"),
                                      finding_cwe, by_id))
    return labels
