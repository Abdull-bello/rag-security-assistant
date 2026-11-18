"""Relevance labels for retrieval scoring, taken from the CWE hierarchy.

2 = the retrieved chunk is the same weakness as the finding
1 = it is a direct parent or child of that weakness
0 = anything else
Only CWE chunks can be labelled this way.
"""

from typing import Dict

from .cwe import Weakness


def relevance_label(finding_cwe: str, chunk_cwe: str,
                    by_id: Dict[str, Weakness]) -> int:
    """Both ids are CWE numbers without the "CWE-" prefix.
    by_id maps cwe_id to Weakness for the whole file."""
    if finding_cwe == chunk_cwe:
        return 2

    finding = by_id.get(finding_cwe)
    chunk = by_id.get(chunk_cwe)
    if finding and chunk_cwe in finding.parent_ids + finding.child_ids:
        return 1
    if chunk and finding_cwe in chunk.parent_ids + chunk.child_ids:
        return 1
    return 0
