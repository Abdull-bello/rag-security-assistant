"""OWASP ASVS 5.0.0, read from the CSV export.

Columns in the file: chapter_id, chapter_name, section_id, section_name,
req_id, req_description, L. There is no CWE column in this export.
"""

import csv
from dataclasses import dataclass
from typing import List

from .common import Chunk, Piece

PREFIX = "asvs"

CHAPTER_TITLES = {
    "1": "Encoding and Sanitization",
    "2": "Validation and Business Logic",
    "3": "Web Frontend Security",
    "4": "API and Web Service",
    "5": "File Handling",
    "6": "Authentication",
    "7": "Session Management",
    "8": "Authorization",
    "9": "Self-contained Tokens",
    "10": "OAuth and OIDC",
    "11": "Cryptography",
    "12": "Secure Communication",
    "13": "Configuration",
    "14": "Data Protection",
    "15": "Secure Coding and Architecture",
    "16": "Security Logging and Error Handling",
    "17": "WebRTC Use Cases",
}


@dataclass
class Requirement:
    shortcode: str            # e.g. "V1.2.5"
    description: str
    chapter_id: str = ""      # e.g. "V1"
    chapter_name: str = ""
    section_id: str = ""      # e.g. "V1.2"
    section_name: str = ""
    min_level: str = ""       # "1", "2" or "3"

    @property
    def chapter(self) -> str:
        return self.chapter_id or self.shortcode.split(".")[0]

    @property
    def section(self) -> str:
        if self.section_id:
            return self.section_id
        parts = self.shortcode.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else self.shortcode

    @property
    def chapter_title(self) -> str:
        return self.chapter_name or CHAPTER_TITLES.get(
            self.chapter.lstrip("Vv"), f"Chapter {self.chapter}")

    @property
    def levels(self) -> List[str]:
        # levels stack: an L1 requirement also applies at L2 and L3
        order = ["1", "2", "3"]
        if self.min_level not in order:
            return []
        return [f"L{lv}" for lv in order[order.index(self.min_level):]]


def _pick(row: dict, *names: str) -> str:
    lower = {k.lower(): v for k, v in row.items()}
    for name in names:
        if lower.get(name.lower()):
            return lower[name.lower()]
    return ""


def load(path) -> List[Requirement]:
    reqs = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            shortcode = _pick(row, "req_id", "Shortcode", "ReqID", "Identifier")
            description = _pick(row, "req_description", "Description", "Text")
            if not shortcode or not description:
                continue
            reqs.append(Requirement(
                shortcode=shortcode,
                description=description,
                chapter_id=_pick(row, "chapter_id"),
                chapter_name=_pick(row, "chapter_name"),
                section_id=_pick(row, "section_id"),
                section_name=_pick(row, "section_name"),
                min_level=_pick(row, "L", "Level"),
            ))
    return reqs


def as_pieces(reqs: List[Requirement]) -> List[Piece]:
    return [(r.shortcode, r.description) for r in reqs]


def structure_chunks(reqs: List[Requirement], group_by: str = "section") -> List[Chunk]:
    """One chunk per section (or chapter, or requirement), with the chapter
    and section headings written in front of the requirements."""
    if group_by not in ("section", "requirement", "chapter"):
        raise ValueError("group_by must be 'section', 'requirement' or 'chapter'")

    groups = {}
    for r in reqs:
        key = {"section": r.section, "requirement": r.shortcode,
               "chapter": r.chapter}[group_by]
        groups.setdefault(key, []).append(r)

    chunks = []
    for key, group in groups.items():
        first = group[0]
        heading = f"ASVS Chapter {first.chapter} ({first.chapter_title})"
        if group_by != "chapter":
            heading += f" - Section {first.section} ({first.section_name})"

        lines = [heading]
        for r in group:
            level_tag = "/".join(r.levels) if r.levels else "L?"
            lines.append(f"[{r.shortcode}] ({level_tag}): {r.description}")

        chunks.append(Chunk(
            chunk_id=f"{PREFIX}-struct-{key}",
            text="\n".join(lines),
            strategy="structure_aware",
            source_shortcodes=[r.shortcode for r in group],
            metadata={"group_by": group_by, "chapter_title": first.chapter_title},
        ))
    return chunks
