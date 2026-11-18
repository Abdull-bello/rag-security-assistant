"""PCI DSS v4.0.1, read from the official PDF.

Each page is a table with three columns: the requirement (and customized
approach objective), the testing procedure, and the guidance. The
requirement id is not at the start of its own text, it sits as a marker a
line below where the paragraph begins. So the extractor uses the markers'
vertical positions as row boundaries and puts every word on the page into
the row it falls in. Column limits come from word coordinates read with
pdfplumber, and 1.1.1 and 1.2.5 were checked against the real wording.

About 205 requirements come out. Outside sources count somewhere between
250 and 300, so some pages with odd layouts are probably missed.
"""

import re
from dataclasses import dataclass
from typing import List, Optional

from .common import Chunk, Piece

PREFIX = "pci"

COL1_MAX_X = 290
COL2_MAX_X = 505

ID_TOKEN_RE = re.compile(r'^\d+\.\d+\.\d+(\.[a-z])?$')
LEFT_MARGIN_X = 85   # real ID markers sit at x0 ~78; guards against
                      # a stray match further right in column 1


@dataclass
class PCIRequirement:
    req_id: str
    requirement_text: str = ""
    customized_objective: str = ""
    testing_procedure: str = ""
    guidance: str = ""
    page: int = 0

    @property
    def section(self) -> str:
        return ".".join(self.req_id.split(".")[:2])

    @property
    def chapter(self) -> str:
        return self.req_id.split(".")[0]


def _find_row_markers(words):
    """Column-1 words that are genuine requirement-ID row markers,
    sorted by vertical position (top)."""
    markers = [w for w in words
               if ID_TOKEN_RE.match(w['text']) and w['x0'] < LEFT_MARGIN_X]
    markers.sort(key=lambda w: w['top'])
    return markers


def _find_objective_label_tops(words):
    """Top positions where 'Customized Approach Objective' begins in
    column 1 (matched as three adjacent words, not a full-line string,
    since line reconstruction is exactly what we're avoiding)."""
    col1 = [w for w in words if w['x0'] < COL1_MAX_X]
    col1.sort(key=lambda w: (w['top'], w['x0']))
    tops = []
    for i in range(len(col1) - 2):
        if (col1[i]['text'] == 'Customized' and
                col1[i+1]['text'] == 'Approach' and
                col1[i+2]['text'] in ('Objective', 'Objectives')):
            tops.append(col1[i]['top'])
    return tops


def _join(words):
    words = sorted(words, key=lambda w: (round(w['top']), w['x0']))
    return " ".join(w['text'] for w in words)


def extract_requirements(pdf_path: str, first_page: int, last_page: int) -> List[PCIRequirement]:
    """first_page/last_page: 1-indexed PDF page numbers (inclusive)."""
    requirements: List[PCIRequirement] = []
    by_id = {}
    open_req: Optional[PCIRequirement] = None

    import pdfplumber   # imported here so the chunkers can be tested without it
    with pdfplumber.open(pdf_path) as pdf:
        for page_num in range(first_page, last_page + 1):
            page = pdf.pages[page_num - 1]
            words = page.extract_words()
            if not words:
                continue

            markers = _find_row_markers(words)
            objective_tops = _find_objective_label_tops(words)

            # Build ordered list of (top, kind, req_id-or-None) boundaries
            # for this page: each new requirement marker starts a new row;
            # each objective label starts a sub-section within the
            # CURRENT row (same req_id, objective mode).
            boundaries = [(m['top'], 'req', m['text']) for m in markers]
            boundaries += [(t, 'objective', None) for t in objective_tops]
            boundaries.sort(key=lambda b: b[0])

            if not boundaries:
                # A continuation page: no new requirement starts here, so
                # everything belongs to the one still open from the last page.
                if open_req is not None:
                    open_req.requirement_text += " " + _join(
                        [w for w in words if w['x0'] < COL1_MAX_X])
                    open_req.testing_procedure += " " + _join(
                        [w for w in words if COL1_MAX_X <= w['x0'] < COL2_MAX_X])
                    open_req.guidance += " " + _join(
                        [w for w in words if w['x0'] >= COL2_MAX_X])
                continue

            # Words before the first boundary on this page belong to
            # whatever requirement was still open from the previous page.
            first_top = boundaries[0][0]
            if open_req is not None:
                pre = [w for w in words if w['top'] < first_top - 3]
                open_req.requirement_text += " " + _join([w for w in pre if w['x0'] < COL1_MAX_X])
                open_req.testing_procedure += " " + _join([w for w in pre if COL1_MAX_X <= w['x0'] < COL2_MAX_X])
                open_req.guidance += " " + _join([w for w in pre if w['x0'] >= COL2_MAX_X])

            current_mode = 'req'
            for i, (top, kind, val) in enumerate(boundaries):
                row_end = boundaries[i + 1][0] if i + 1 < len(boundaries) else 10_000
                row_words = [w for w in words if top - 1 <= w['top'] < row_end - 1]

                if kind == 'req':
                    open_req = PCIRequirement(req_id=val, page=page_num)
                    requirements.append(open_req)
                    by_id[val] = open_req
                    current_mode = 'req'
                    # exclude the marker token itself from column-1 text
                    c1 = [w for w in row_words if w['x0'] < COL1_MAX_X
                          and not (w['text'] == val and w['top'] < top + 3)]
                    open_req.requirement_text = _join(c1)
                else:
                    current_mode = 'objective'
                    if open_req is not None:
                        c1 = [w for w in row_words if w['x0'] < COL1_MAX_X]
                        # drop the 3 label words themselves
                        c1_text = _join(c1)
                        c1_text = re.sub(r'^Customized Approach Objectives?\s*', '', c1_text)
                        open_req.customized_objective = (
                            open_req.customized_objective + " " + c1_text).strip()

                if open_req is not None:
                    tp = [w for w in row_words if COL1_MAX_X <= w['x0'] < COL2_MAX_X]
                    gd = [w for w in row_words if w['x0'] >= COL2_MAX_X]
                    if tp:
                        open_req.testing_procedure = (open_req.testing_procedure + " " + _join(tp)).strip()
                    if gd:
                        open_req.guidance = (open_req.guidance + " " + _join(gd)).strip()

    for r in requirements:
        r.requirement_text = _clean(r.requirement_text)
        r.customized_objective = _clean(r.customized_objective)
        r.testing_procedure = _clean(r.testing_procedure)
        r.guidance = _clean(r.guidance)

    return _merge_continuation_duplicates(requirements)


def _merge_continuation_duplicates(requirements: List[PCIRequirement]) -> List[PCIRequirement]:
    """
    A requirement whose text runs onto a second page sometimes triggers a
    second marker detection on that next page (PCI DSS occasionally
    re-prints context near a continuation). This produces two separate
    PCIRequirement objects with the SAME req_id on adjacent pages, where
    the second one's "requirement_text" is really the tail end of the
    first one's sentence. Detected and confirmed on 5 real instances in
    the full 12-requirement extraction (3.3.3, 4.2.1, 6.4.1, 10.7.1,
    12.8.4) - in every case the second occurrence's text was a plain
    continuation, not a distinct requirement. Merge rather than drop, so
    no real content is lost.
    """
    merged: List[PCIRequirement] = []
    seen_at: dict = {}  # req_id -> index in `merged`
    for r in requirements:
        if r.req_id in seen_at:
            prev = merged[seen_at[r.req_id]]
            prev.requirement_text = (prev.requirement_text + " " + r.requirement_text).strip()
            prev.customized_objective = (prev.customized_objective + " " + r.customized_objective).strip()
            prev.testing_procedure = (prev.testing_procedure + " " + r.testing_procedure).strip()
            prev.guidance = (prev.guidance + " " + r.guidance).strip()
        else:
            seen_at[r.req_id] = len(merged)
            merged.append(r)
    return merged


_BOILERPLATE_PATTERNS = [
    r'Payment Card Industry Data Security Standard:?\s*Requirements\s*(and\s*Testing\s*Procedures,?\s*v4\.0\.1)?',
    r'©\s*2006.*',
    r'\bJune\s*2024\b',
    r'\bPage\s*\d+\b',
    r'Requirements and Testing(\s+Procedures)?(\s+Guidance)?',
    r'\bDefined Approach Requirements\b',
    r'\bDefined Approach Testing Procedures\b',
    r'^\s*Purpose\s+',
]
_BOILERPLATE_RE = re.compile("|".join(_BOILERPLATE_PATTERNS))


def _clean(text: str) -> str:
    text = _BOILERPLATE_RE.sub(' ', text)
    return re.sub(r'\s+', ' ', text).strip()

def load(pdf_path, first_page: int = 42, last_page: int = 337) -> List[PCIRequirement]:
    """Pages 42 to 337 cover the 12 principal requirements (page numbers
    from the PDF's own bookmarks). Very short fragments are dropped."""
    reqs = extract_requirements(pdf_path, first_page, last_page)
    return [r for r in reqs if len(r.requirement_text.strip()) > 15]


def as_pieces(reqs: List[PCIRequirement]) -> List[Piece]:
    pieces = []
    for r in reqs:
        text = r.requirement_text
        if r.customized_objective:
            text += "\n" + r.customized_objective
        pieces.append((r.req_id, text))
    return pieces


def structure_chunks(reqs: List[PCIRequirement]) -> List[Chunk]:
    """One chunk per section, for example everything under 1.2."""
    sections = {}
    for r in reqs:
        sections.setdefault(r.section, []).append(r)

    chunks = []
    for section, group in sections.items():
        lines = [f"PCI DSS Requirement {group[0].chapter}, Section {section}"]
        for r in group:
            lines.append(f"[{r.req_id}] {r.requirement_text}")
            if r.customized_objective:
                lines.append(f"  Customized Approach Objective: {r.customized_objective}")
        chunks.append(Chunk(
            chunk_id=f"{PREFIX}-struct-{section}",
            text="\n".join(lines),
            strategy="structure_aware",
            source_shortcodes=[r.req_id for r in group],
            metadata={"section": section},
        ))
    return chunks
