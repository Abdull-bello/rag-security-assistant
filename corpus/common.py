"""The chunk record and the two chunkers that work on any source."""

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple

# A source turns each of its records into (record_id, text) pieces.
Piece = Tuple[str, str]

SEPARATORS = ["\n\n", "\n", ". ", ", ", " "]


@dataclass
class Chunk:
    chunk_id: str                  # source, strategy and a number or key
    text: str
    strategy: str                  # fixed_window, recursive or structure_aware
    source_shortcodes: List[str]   # ids of the records the text came from
    metadata: Dict = field(default_factory=dict)


def split_text(text: str, max_chars: int, separators: List[str]) -> List[str]:
    """Split on the first separator, and only use the next one for
    pieces that are still too long."""
    if len(text) <= max_chars:
        return [text]
    if not separators:
        return [text[i:i + max_chars] for i in range(0, len(text), max_chars)]

    sep, rest = separators[0], separators[1:]
    out, current = [], ""
    for part in text.split(sep):
        candidate = current + (sep if current else "") + part
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            out.append(current)
        if len(part) > max_chars:
            out.extend(split_text(part, max_chars, rest))
            current = ""
        else:
            current = part
    if current:
        out.append(current)
    return out


def fixed_window(pieces: List[Piece], prefix: str,
                 window_words: int = 150, overlap_words: int = 30) -> List[Chunk]:
    """Join everything into one stream of words and cut it by word count.
    Record boundaries are ignored on purpose, this is the baseline."""
    step = window_words - overlap_words
    if step <= 0:
        raise ValueError("overlap_words must be smaller than window_words")

    words = []
    for record_id, text in pieces:
        words.extend((w, record_id) for w in text.split())

    chunks = []
    for n, start in enumerate(range(0, len(words), step)):
        window = words[start:start + window_words]
        chunks.append(Chunk(
            chunk_id=f"{prefix}-fixed-{n:04d}",
            text=" ".join(w for w, _ in window),
            strategy="fixed_window",
            source_shortcodes=sorted({r for _, r in window}),
            metadata={"window_words": window_words, "overlap_words": overlap_words},
        ))
    return chunks


def recursive(pieces: List[Piece], prefix: str, max_chars: int = 500) -> List[Chunk]:
    """Split each record on its own, paragraph breaks first, then
    sentences, then words."""
    chunks = []
    n = 0
    for record_id, text in pieces:
        for part in split_text(text, max_chars, SEPARATORS):
            chunks.append(Chunk(
                chunk_id=f"{prefix}-recursive-{n:04d}",
                text=part.strip(),
                strategy="recursive",
                source_shortcodes=[record_id],
                metadata={"max_chars": max_chars},
            ))
            n += 1
    return chunks


def chunk_all(source, records) -> Dict[str, List[Chunk]]:
    """Run the three strategies on one source. `source` is one of the
    modules in this package (asvs, cwe, pci, cbn)."""
    pieces = source.as_pieces(records)
    return {
        "fixed_window": fixed_window(pieces, source.PREFIX),
        "recursive": recursive(pieces, source.PREFIX),
        "structure_aware": source.structure_chunks(records),
    }


def save_chunks(chunks: List[Chunk], path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for c in chunks:
            f.write(json.dumps(asdict(c), ensure_ascii=False) + "\n")


def load_chunks(path) -> List[Chunk]:
    with open(path, encoding="utf-8") as f:
        return [Chunk(**json.loads(line)) for line in f if line.strip()]
