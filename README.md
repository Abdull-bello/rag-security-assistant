# Corpus build for the security assistant

Stage 1 reads four sources (CWE, ASVS 5.0.0, PCI DSS v4.0.1, the CBN 2024
framework), cuts each one into chunks three ways, and saves the chunks to
files. Stage 2 embeds the chunks, stores them in Chroma, and searches them
four ways (BM25, dense, hybrid, hybrid with a reranker). Stage 3 scores the
retrieval against the test items.

## Setup (Windows)

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

## Data

Put these four files in `data/`. The folder is ignored by Git.

| File | What it is |
|---|---|
| `OWASP_Application_Security_Verification_Standard_5_0_0_en.csv` | ASVS 5.0.0, CSV export |
| `1000.csv` | CWE Research Concepts view (view 1000), CSV from MITRE |
| `PCI-DSS-v4_0_1.pdf` | PCI DSS v4.0.1 requirements and testing procedures |
| `cbn_raw.txt` | Plain text of the CBN framework, main body (sections 1.0 to 7.0) |

## Run

    python build_corpus.py              # all four
    python build_corpus.py cbn cwe      # just these

It prints how many records each source gave and how many chunks each
strategy made, and warns if a record count is not the expected one
(ASVS 345, CWE 944, PCI 205, CBN 35). Chunks go to `output/chunks/`.

## Index and search (stage 2)

Run stage 1 first. Then:

    python build_index.py                # all three strategies
    python build_index.py structure_aware

The first run downloads the embedding model, about 440 MB, and needs an
internet connection. Embedding runs on the CPU and takes a few minutes per
strategy. The vectors are saved in `chroma_db/`, which Git ignores.

To see it work:

    python try_search.py "how do I prevent SQL injection" structure_aware hybrid

The last word is the mode: `bm25`, `dense`, `hybrid` or `rerank`. The
reranker downloads a second model the first time `rerank` is used.

## Score retrieval (stage 3)

Make a file `data/test_items.csv` with one row per test item and these
columns:

    item_id,cwe_class,query,finding_cwe

`finding_cwe` is the CWE number the finding was labelled with, such as 89 or
CWE-89. `query` is the text sent to the search. `examples/test_items_example.csv`
shows the format; its rows are made up. Then:

    python score_retrieval.py data/test_items.csv
    python score_retrieval.py data/test_items.csv --strategies structure_aware --modes bm25 hybrid
    python score_retrieval.py data/test_items.csv --alpha 0.5

It prints the mean P@5, R@5, MRR and nDCG@5 for each strategy and mode, and
writes `output/retrieval_scores_items.csv` (one row per item) and
`output/retrieval_scores_summary.csv` (means over all items and per class).

The rules, which follow Chapter 3:

- Only CWE chunks can be labelled, so only they are judged. Unjudged chunks
  (ASVS, PCI DSS, CBN) are dropped from the ranked list, then the first five
  judged chunks are scored. The share of unjudged chunks in the plain top five
  is reported as `unjudged_share`.
- Label 2 is the same weakness, 1 is a direct parent or child, 0 is anything
  else. P@5 and R@5 count labels of 1 or 2. MRR counts only label 2.
- R@5 and the ideal DCG are worked out against every judged chunk in that
  strategy's collection.
- A fixed-window chunk can span several weaknesses. It takes the highest label
  among them.
- If the collection holds no relevant chunk for a finding, R@5 and nDCG@5
  are left out for that item. The `n_` columns in the summary say how many
  items each mean used.
- Search depth is 100. For `rerank` only the top 20 hybrid candidates are
  reranked, so fewer than five judged chunks can be found.

## Test

    python -m unittest

The tests use small made-up sample files in `tests/fixtures/`, so they need
none of the real data.

## Layout

    build_corpus.py        runs everything
    corpus/common.py       the Chunk record, fixed-window and recursive chunkers
    corpus/asvs.py         ASVS loader and its structure-aware chunker
    corpus/cwe.py          CWE loader and its structure-aware chunker
    corpus/pci.py          PCI DSS PDF extractor and its structure-aware chunker
    corpus/cbn.py          CBN parser and its structure-aware chunker
    corpus/labels.py       relevance labels from the CWE hierarchy
    retrieval/embed.py     the embedding model and the reranker
    retrieval/index.py     puts one strategy's chunks into Chroma
    retrieval/search.py    the four retrieval modes
    build_index.py         runs the embedding and storing
    try_search.py          asks the index a question from the command line
    evaluation/metrics.py  P@5, R@5, MRR, nDCG@5
    evaluation/judge.py    which chunks are judged and what label they get
    evaluation/runner.py   scores one item, loads items, adds up the results
    score_retrieval.py     runs the scoring over a file of test items
    examples/              a sample items file (made-up rows)
    tests/                 unit tests and fixtures

Fixed-window (150 words, 30 overlap) and recursive (500 characters) work the
same on every source, so they live once in `common.py`. Structure-aware
chunking depends on how each document is built, so each source has its own.

## Chunk record

`chunk_id`, `text`, `strategy`, `source_shortcodes`, `metadata`. The id starts
with the source and the strategy, for example `cwe-struct-89-mitigations`.

## What each file does

Read them in this order.

**corpus/common.py.** Defines the `Chunk` record that every source returns.
Holds the two chunkers that do not depend on the source. `fixed_window` joins
all records into one stream of words and cuts every 150 words, with 30 words
of overlap, ignoring where one record ends. `recursive` splits each record on
paragraph breaks first, then lines, then sentences, until each piece is
under 500 characters. `chunk_all` runs all three strategies for one source,
and `save_chunks` writes them to a JSONL file.

**corpus/cwe.py.** Reads MITRE's `1000.csv`. Three columns use MITRE's own
`::KEY:VALUE::` format, and `parse_structured_field` reads it. A new value
starts only at a known field name (`KEYS`), because descriptions contain
colons. `structure_chunks` makes up to three chunks per weakness: definition,
consequences and mitigations, each headed with the CWE id and name.

**corpus/asvs.py.** Reads the ASVS CSV into requirements. `structure_chunks`
groups requirements by section and puts the chapter and section names at the
top of each chunk.

**corpus/pci.py.** The hardest source. The PDF is a three-column table, and
the requirement id sits below the text it belongs to. `extract_requirements`
uses the vertical position of each id marker to decide which words belong to
which requirement. `structure_chunks` groups by section.

**corpus/cbn.py.** Reads the CBN framework text. A regular expression finds the
numbered headings (1.0, 1.1, 1.1.1), and the text between two headings is one
clause. `structure_chunks` groups clauses by Part (1 to 7).

**corpus/labels.py.** Gives a retrieved chunk a relevance label for a
finding's CWE: 2 for the same CWE, 1 for a parent or child in the hierarchy,
0 otherwise. Used later to score retrieval.

**retrieval/embed.py.** Wraps bge-base-en-v1.5 (embeddings) and
bge-reranker-base (reranker). Both load on first use, so the tests can swap in
small stand-ins and run without the models.

**retrieval/index.py.** `build_index` embeds one strategy's chunks and stores
them in a Chroma collection named `chunks_<strategy>`. There is one collection
per strategy, each holding all four sources, so the chunkers are compared on
the same store and the same model. A rerun drops the old collection first.

**retrieval/search.py.** `Retriever` reads a collection back into memory and
offers `bm25_search`, `dense_search`, `hybrid_search` and `rerank_search`.
Hybrid is `alpha * norm(BM25) + (1 - alpha) * norm(dense)` with each score
min-max normalised over the whole collection. Alpha starts at 0.7 and is meant
to be tuned in the pilot. The reranker rescores the top 20 hybrid candidates.

**evaluation/metrics.py.** The four measures, each a short function over the
labels of the judged chunks in rank order. The tests check them against
values worked out by hand.

**evaluation/judge.py.** Decides which retrieved chunks can be labelled (the
CWE ones) and gives each a label using `corpus/labels.py`. Also lists the label
of every judged chunk in a collection, which recall and the ideal DCG need.

**evaluation/runner.py.** `score_item` retrieves, drops the unjudged chunks,
and scores one test item in one mode. `summarise` averages the items.

**score_retrieval.py.** Loops over strategies, modes and items, and writes the
two result files.

**build_corpus.py.** Runs each source through load, chunk and save, prints the
counts, and warns if a record count is not the expected one.

**tests/.** `test_common.py` checks the two shared chunkers. `test_sources.py`
checks each source's loader and chunker on the small made-up files in
`fixtures/`.

## Known limits

- PCI DSS gives about 205 requirements. Outside sources count 250 to 300, so
  some pages are probably missed.
- CBN covers the main body only. The appendices and glossary are not parsed.
- ASVS 5.0.0 has no CWE column, so relevance labels exist only for CWE chunks.
- The last fixed-window chunk of a source is often just the overlap of the
  one before it.
- The CWE field parser starts a new value only at MITRE's known field names
  (see KEYS in corpus/cwe.py), so colons inside descriptions are kept. If
  MITRE adds a new field name, add it to KEYS. To check, count the keys:
  python -c "from corpus import cwe; from collections import Counter; ws=cwe.load('data/1000.csv'); print(Counter(k for w in ws for r in cwe.parse_structured_field(w.mitigations_raw) for k in r))"

## Stage 4: generation, experiment and scoring

1. `python build_items.py ...` turns Semgrep and ZAP JSON into candidate test items. `python select_items.py --per-class 20` draws a balanced draft. Review it by hand, then save it as `data/test_items.csv`.
2. Install Ollama, pull a model, and time it on 10 findings with `python assist.py "<finding>" --model <name> --save output/pilot.jsonl`. The median `seconds` decides the model.
3. `python run_experiment.py --model <name> --conditions BASE S1_fixed S1_recursive S1_structure` runs the baseline and Stage 1. Pick the chunker with the best retrieval scores, then run `--winner <strategy> --conditions S2_bm25 S2_dense S2_rerank`. The run file `output/runs.jsonl` is resumable.
4. `python summarise_runs.py` gives triage accuracy, citation checks and timing per condition.
5. `python make_scoring_sheets.py 40` writes the blind hand-scoring sheet, its key, and the input for the RAGAs judge.

Evidence is shown to the model as labels E1 to E5. The validator maps each label back to a stored chunk identifier and flags any label that was not supplied.
