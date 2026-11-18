"""CBN Risk-Based Cybersecurity Framework for DMBs and PSBs (2024).

Main body only, sections 1.0 to 7.0. The working text is plain text from
a mirror of the circular (cbn.gov.ng returned 403), so re-check it
against the original PDF. The appendices and glossary are not parsed
yet, and Appendix VII (blank incident forms) is left out on purpose.
"""

import re
from dataclasses import dataclass
from typing import List

from .common import Chunk, Piece

PREFIX = "cbn"

# a numbered heading at the start of a line: "1.0", "1.1.", "4.8 Title"
SECTION_RE = re.compile(r"^(\d+(?:\.\d+){0,2})\.?\s+([A-Z][A-Za-z].*)$", re.MULTILINE)


@dataclass
class Clause:
    section_id: str      # e.g. "1.1.1"
    title: str
    body: str

    @property
    def part(self) -> str:
        return self.section_id.split(".")[0]


def load(path) -> List[Clause]:
    with open(path, encoding="utf-8") as f:
        text = f.read()

    matches = list(SECTION_RE.finditer(text))
    clauses = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = re.sub(r"\s+", " ", text[m.end():end].strip())
        if body:
            clauses.append(Clause(m.group(1), m.group(2).strip(), body))
    return clauses


def as_pieces(clauses: List[Clause]) -> List[Piece]:
    return [(c.section_id, c.body) for c in clauses]


def structure_chunks(clauses: List[Clause]) -> List[Chunk]:
    """One chunk per Part (1 to 7). The numbering below the Part level is
    too uneven to group on."""
    parts = {}
    for c in clauses:
        parts.setdefault(c.part, []).append(c)

    chunks = []
    for part, group in parts.items():
        lines = [f"CBN Framework, Part {part}"]
        lines += [f"[{c.section_id}] {c.title}: {c.body}" for c in group]
        chunks.append(Chunk(
            chunk_id=f"{PREFIX}-struct-part{part}",
            text="\n".join(lines),
            strategy="structure_aware",
            source_shortcodes=[c.section_id for c in group],
            metadata={"part": part},
        ))
    return chunks
