"""Parse the four sources, chunk each one three ways and save the chunks.

    python build_corpus.py              all four sources
    python build_corpus.py cbn cwe      only the ones you name

Put the downloaded files in data/ first (see README.md).
Chunks are written to output/chunks/ as one .jsonl file per source and strategy.
"""

import sys
from pathlib import Path

from corpus import asvs, cwe, pci, cbn
from corpus.common import chunk_all, save_chunks

DATA = Path("data")
OUT = Path("output") / "chunks"

# name: (module, input file, expected record count)
SOURCES = {
    "asvs": (asvs, DATA / "OWASP_Application_Security_Verification_Standard_5_0_0_en.csv", 345),
    "cwe": (cwe, DATA / "1000.csv", 944),
    "pci": (pci, DATA / "PCI-DSS-v4_0_1.pdf", 205),
    "cbn": (cbn, DATA / "cbn_raw.txt", 35),
}


def main(names):
    OUT.mkdir(parents=True, exist_ok=True)
    failed = False

    for name in names:
        module, path, expected = SOURCES[name]
        if not path.exists():
            print(f"{name}: missing {path}")
            failed = True
            continue

        records = module.load(path)
        by_strategy = chunk_all(module, records)

        note = "" if len(records) == expected else f"   <- expected {expected}"
        counts = ", ".join(f"{s} {len(c)}" for s, c in by_strategy.items())
        print(f"{name}: {len(records)} records{note}\n    chunks: {counts}")

        for strategy, chunks in by_strategy.items():
            save_chunks(chunks, OUT / f"{name}_{strategy}.jsonl")

    return 1 if failed else 0


if __name__ == "__main__":
    wanted = sys.argv[1:] or list(SOURCES)
    unknown = [n for n in wanted if n not in SOURCES]
    if unknown:
        sys.exit(f"unknown source: {', '.join(unknown)} (choose from {', '.join(SOURCES)})")
    sys.exit(main(wanted))
