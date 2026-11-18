import csv
import math
import tempfile
import unittest
from pathlib import Path

from corpus.common import Chunk
from corpus.cwe import Weakness
from evaluation.judge import chunk_label, collection_labels, cwe_numbers, is_judged
from evaluation.metrics import (dcg, ndcg_at_k, precision_at_k, recall_at_k,
                                reciprocal_rank)
from evaluation.runner import load_items, score_item, summarise
from retrieval.index import build_index
from retrieval.search import Retriever
from tests.test_retrieval import WordEmbedder


def small_hierarchy():
    """CWE-74 is the parent of CWE-89, which is the parent of CWE-564.
    CWE-22 is unrelated to them."""
    return {
        "74": Weakness("74", "Injection", "d",
                       related_raw="::NATURE:ParentOf:CWE ID:89:VIEW ID:1000::"),
        "89": Weakness("89", "SQL Injection", "d",
                       related_raw="::NATURE:ChildOf:CWE ID:74:VIEW ID:1000::"
                                   "::NATURE:ParentOf:CWE ID:564:VIEW ID:1000::"),
        "564": Weakness("564", "Hibernate", "d",
                        related_raw="::NATURE:ChildOf:CWE ID:89:VIEW ID:1000::"),
        "22": Weakness("22", "Path traversal", "d"),
    }


class MetricTests(unittest.TestCase):
    def test_precision_counts_labels_of_one_and_two(self):
        self.assertAlmostEqual(precision_at_k([2, 0, 1, 0, 0]), 0.4)

    def test_precision_uses_the_chunks_that_exist(self):
        self.assertAlmostEqual(precision_at_k([2, 0]), 0.5)

    def test_precision_of_nothing_is_zero(self):
        self.assertEqual(precision_at_k([]), 0.0)

    def test_recall_is_against_all_relevant_chunks(self):
        self.assertAlmostEqual(recall_at_k([2, 0, 1, 0, 0], total_relevant=3), 2 / 3)

    def test_recall_is_undefined_without_relevant_chunks(self):
        self.assertIsNone(recall_at_k([0, 0, 0], total_relevant=0))

    def test_reciprocal_rank_of_first_exact_match(self):
        self.assertAlmostEqual(reciprocal_rank([1, 0, 2, 2, 0]), 1 / 3)

    def test_reciprocal_rank_ignores_parent_and_child(self):
        self.assertEqual(reciprocal_rank([1, 1, 1, 1, 1]), 0.0)

    def test_reciprocal_rank_only_looks_at_the_top_five(self):
        self.assertEqual(reciprocal_rank([0, 0, 0, 0, 0, 2]), 0.0)

    def test_dcg_by_hand(self):
        # (2^2 - 1) / log2(2) + (2^1 - 1) / log2(4) = 3 + 0.5
        self.assertAlmostEqual(dcg([2, 0, 1]), 3.5)

    def test_ndcg_by_hand(self):
        ideal = 3 + 1 / math.log2(3) + 1 / math.log2(4)
        got = ndcg_at_k([2, 0, 1, 0, 0], all_labels=[0, 1, 2, 1, 0, 0])
        self.assertAlmostEqual(got, 3.5 / ideal)

    def test_ndcg_of_the_best_ordering_is_one(self):
        self.assertAlmostEqual(ndcg_at_k([2, 1, 1], all_labels=[1, 2, 0, 1]), 1.0)

    def test_ndcg_is_undefined_without_any_gain(self):
        self.assertIsNone(ndcg_at_k([0, 0], all_labels=[0, 0, 0]))


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.by_id = small_hierarchy()

    def test_numbers_are_taken_from_cwe_codes_only(self):
        self.assertEqual(cwe_numbers(["CWE-89", "V1.2", "CWE-74"]), ["89", "74"])

    def test_only_cwe_chunks_are_judged(self):
        self.assertTrue(is_judged("cwe"))
        self.assertFalse(is_judged("asvs"))
        self.assertFalse(is_judged("pci"))
        self.assertFalse(is_judged("cbn"))

    def test_exact_parent_child_and_unrelated(self):
        self.assertEqual(chunk_label(["CWE-89"], "89", self.by_id), 2)
        self.assertEqual(chunk_label(["CWE-74"], "89", self.by_id), 1)
        self.assertEqual(chunk_label(["CWE-564"], "89", self.by_id), 1)
        self.assertEqual(chunk_label(["CWE-22"], "89", self.by_id), 0)

    def test_a_chunk_spanning_weaknesses_takes_the_highest_label(self):
        self.assertEqual(chunk_label(["CWE-22", "CWE-89"], "89", self.by_id), 2)
        self.assertEqual(chunk_label(["CWE-22", "CWE-74"], "89", self.by_id), 1)

    def test_a_chunk_with_no_cwe_code_gets_zero(self):
        self.assertEqual(chunk_label(["V1.2"], "89", self.by_id), 0)


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.by_id = small_hierarchy()
        chunks = [
            Chunk("cwe-struct-89-mitigations", "Use a parameterized query to stop sql injection.",
                  "structure_aware", ["CWE-89"]),
            Chunk("cwe-struct-74-definition", "An injection sends data to a query interpreter.",
                  "structure_aware", ["CWE-74"]),
            Chunk("cwe-struct-22-definition", "A path traversal reads a file outside the folder.",
                  "structure_aware", ["CWE-22"]),
            Chunk("asvs-struct-V1.2", "Use a parameterized query and encode output against injection.",
                  "structure_aware", ["V1.2.1"]),
            Chunk("pci-struct-6.2", "Protect against sql injection attacks in custom software.",
                  "structure_aware", ["6.2.4"]),
        ]
        build_index("structure_aware", chunks, WordEmbedder(), cls.tmp.name)
        cls.retriever = Retriever("structure_aware", WordEmbedder(), cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_collection_labels_cover_only_cwe_chunks(self):
        labels = collection_labels(self.retriever, "89", self.by_id)
        self.assertEqual(sorted(labels), [0, 1, 2])

    def test_unjudged_chunks_are_dropped_before_scoring(self):
        result = score_item(self.retriever, "parameterized query sql injection",
                            "89", self.by_id, "bm25")
        self.assertEqual(result["judged_found"], 3)
        self.assertEqual(result["relevant_in_collection"], 2)

    def test_the_best_chunk_is_found_first(self):
        result = score_item(self.retriever, "parameterized query sql injection",
                            "89", self.by_id, "bm25")
        self.assertEqual(result["mrr"], 1.0)

    def test_unjudged_share_is_taken_before_dropping(self):
        result = score_item(self.retriever, "parameterized query sql injection",
                            "89", self.by_id, "bm25")
        # 2 of the 5 chunks in the collection (ASVS and PCI) are unjudged
        self.assertAlmostEqual(result["unjudged_share"], 0.4)

    def test_a_cwe_with_no_relevant_chunk_leaves_recall_undefined(self):
        result = score_item(self.retriever, "sql injection", "999", self.by_id, "bm25")
        self.assertIsNone(result["r_at_5"])
        self.assertIsNone(result["ndcg_at_5"])

    def test_summary_means_and_counts(self):
        rows = [
            {"strategy": "s", "mode": "m", "cwe_class": "a", "p_at_5": 1.0, "r_at_5": 0.5,
             "mrr": 1.0, "ndcg_at_5": 1.0, "unjudged_share": 0.0},
            {"strategy": "s", "mode": "m", "cwe_class": "b", "p_at_5": 0.0, "r_at_5": None,
             "mrr": 0.0, "ndcg_at_5": None, "unjudged_share": 0.4},
        ]
        by_class = {(e["cwe_class"]): e for e in summarise(rows)}
        self.assertEqual(by_class["ALL"]["items"], 2)
        self.assertAlmostEqual(by_class["ALL"]["p_at_5"], 0.5)
        self.assertAlmostEqual(by_class["ALL"]["r_at_5"], 0.5)
        self.assertEqual(by_class["ALL"]["n_r_at_5"], 1)
        self.assertEqual(by_class["a"]["items"], 1)

    def test_items_file_needs_the_right_columns(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "items.csv"
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows([["item_id", "query"], ["1", "q"]])
            with self.assertRaises(ValueError):
                load_items(path)

    def test_items_file_strips_the_cwe_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "items.csv"
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows([
                    ["item_id", "cwe_class", "query", "finding_cwe"],
                    ["1", "injection", "q", "CWE-89"]])
            self.assertEqual(load_items(path)[0]["finding_cwe"], "89")


if __name__ == "__main__":
    unittest.main()
