"""CWE, Research Concepts view (1000.csv from MITRE).

Several columns (Related Weaknesses, Common Consequences, Potential
Mitigations) use MITRE's own format: "::KEY:VALUE:KEY:VALUE::" blocks.
parse_structured_field reads that format.
"""

import csv
from dataclasses import dataclass
from typing import Dict, List

from .common import Chunk, Piece

PREFIX = "cwe"


# Field names MITRE uses inside these columns. Only these start a new
# value, so a colon or "::" inside a description stays part of the text.
KEYS = {
    "NATURE", "CWE ID", "VIEW ID", "ORDINAL",
    "PHASE", "STRATEGY", "DESCRIPTION", "EFFECTIVENESS", "EFFECTIVENESS NOTES",
    "SCOPE", "IMPACT", "LIKELIHOOD", "NOTE",
}


def _parse_block(block: str) -> Dict[str, str]:
    """One record. A key can repeat (a consequence can list several
    scopes); the values are then joined with a comma."""
    values: Dict[str, List[List[str]]] = {}
    key = None
    for token in block.split(":"):
        if token.strip() in KEYS:
            key = token.strip()
            values.setdefault(key, []).append([])
        elif key is not None:
            values[key][-1].append(token)
    return {k: ", ".join(":".join(parts).strip() for parts in v)
            for k, v in values.items()}


def parse_structured_field(raw: str) -> List[Dict[str, str]]:
    """Turn "::A:1:B:2::A:3:B:4::" into [{A:1, B:2}, {A:3, B:4}].

    A block that does not start with a known field name is the rest of
    the previous value, where the text itself contained "::"."""
    if not raw or not raw.strip():
        return []
    records: List[Dict[str, str]] = []
    for block in raw.split("::"):
        if not block.strip():
            continue
        first = block.split(":", 1)[0].strip()
        if first not in KEYS and records and records[-1]:
            last_key = list(records[-1])[-1]
            records[-1][last_key] += "::" + block.strip()
            continue
        record = _parse_block(block)
        if record:
            records.append(record)
    return records


@dataclass
class Weakness:
    cwe_id: str                 # "89", no "CWE-" in front, as in the CSV
    name: str
    description: str
    abstraction: str = ""
    status: str = ""
    extended_description: str = ""
    related_raw: str = ""
    consequences_raw: str = ""
    mitigations_raw: str = ""

    @property
    def shortcode(self) -> str:
        return f"CWE-{self.cwe_id}"

    @property
    def parent_ids(self) -> List[str]:
        """Weaknesses this one is a ChildOf."""
        return [r["CWE ID"] for r in parse_structured_field(self.related_raw)
                if r.get("NATURE") == "ChildOf" and "CWE ID" in r]

    @property
    def child_ids(self) -> List[str]:
        """Weaknesses this one is a ParentOf."""
        return [r["CWE ID"] for r in parse_structured_field(self.related_raw)
                if r.get("NATURE") == "ParentOf" and "CWE ID" in r]

    @property
    def text(self) -> str:
        """Description plus extended description, on separate lines."""
        if self.extended_description:
            return self.description + "\n" + self.extended_description
        return self.description

    @property
    def consequences_text(self) -> str:
        lines = []
        for r in parse_structured_field(self.consequences_raw):
            scope, impact = r.get("SCOPE", ""), r.get("IMPACT", "")
            if scope or impact:
                lines.append(f"Scope: {scope}. Impact: {impact}.")
        return " ".join(lines)

    @property
    def mitigations_text(self) -> str:
        lines = []
        for r in parse_structured_field(self.mitigations_raw):
            phase, desc = r.get("PHASE", ""), r.get("DESCRIPTION", "")
            if desc:
                lines.append(f"[{phase}] {desc}" if phase else desc)
        return " ".join(lines)


def load(path) -> List[Weakness]:
    weaknesses = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cwe_id = row.get("CWE-ID", "").strip()
            description = row.get("Description", "").strip()
            if not cwe_id or not description:
                continue
            weaknesses.append(Weakness(
                cwe_id=cwe_id,
                name=row.get("Name", "").strip(),
                description=description,
                abstraction=row.get("Weakness Abstraction", "").strip(),
                status=row.get("Status", "").strip(),
                extended_description=row.get("Extended Description", "").strip(),
                related_raw=row.get("Related Weaknesses", ""),
                consequences_raw=row.get("Common Consequences", ""),
                mitigations_raw=row.get("Potential Mitigations", ""),
            ))
    return weaknesses


def as_pieces(weaknesses: List[Weakness]) -> List[Piece]:
    return [(w.shortcode, w.text) for w in weaknesses]


def structure_chunks(weaknesses: List[Weakness]) -> List[Chunk]:
    """Up to three chunks per weakness: definition, consequences and
    mitigations. Each starts with the CWE id and name."""
    chunks = []
    for w in weaknesses:
        heading = f"{w.shortcode}: {w.name} (Abstraction: {w.abstraction})"

        # (field, label, text); the definition always exists
        parts = [
            ("definition", "Definition", w.description +
             (" " + w.extended_description if w.extended_description else "")),
            ("consequences", "Common Consequences", w.consequences_text),
            ("mitigations", "Potential Mitigations", w.mitigations_text),
        ]
        for field_name, label, body in parts:
            if not body:
                continue
            chunks.append(Chunk(
                chunk_id=f"{PREFIX}-struct-{w.cwe_id}-{field_name}",
                text=f"{heading}\n[{label}] {body}",
                strategy="structure_aware",
                source_shortcodes=[w.shortcode],
                metadata={"field": field_name},
            ))
    return chunks
