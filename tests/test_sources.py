import unittest
from pathlib import Path

from corpus import asvs, cwe, cbn, pci
from corpus.common import chunk_all
from corpus.labels import relevance_label

FIXTURES = Path(__file__).parent / "fixtures"


class AsvsTests(unittest.TestCase):
    def setUp(self):
        self.reqs = asvs.load(FIXTURES / "asvs_sample.csv")

    def test_rows_without_an_id_are_skipped(self):
        self.assertEqual([r.shortcode for r in self.reqs], ["V1.2.1", "V1.2.2", "V8.1.1"])

    def test_levels_stack(self):
        self.assertEqual(self.reqs[1].levels, ["L2", "L3"])

    def test_structure_groups_by_section(self):
        chunks = asvs.structure_chunks(self.reqs)
        self.assertEqual([c.chunk_id for c in chunks], ["asvs-struct-V1.2", "asvs-struct-V8.1"])
        self.assertEqual(chunks[0].source_shortcodes, ["V1.2.1", "V1.2.2"])
        self.assertIn("Encoding and Sanitization", chunks[0].text)
        self.assertEqual(chunks[1].metadata["chapter_title"], "Authorization")


class CweTests(unittest.TestCase):

    def test_repeated_scope_is_kept(self):
        raw = "::SCOPE:Confidentiality:SCOPE:Integrity:IMPACT:Read Application Data::"
        self.assertEqual(cwe.parse_structured_field(raw),
                         [{"SCOPE": "Confidentiality, Integrity", "IMPACT": "Read Application Data"}])

    def test_colons_inside_a_description_are_kept(self):
        raw = ("::PHASE:Implementation:STRATEGY:Libraries:DESCRIPTION:Avoid auto_ptr "
               "(defined by ISO/IEC 14882:2011) and use the C++ std::unique_ptr instead.::"
               "PHASE:Testing:DESCRIPTION:Run the fuzzer.::")
        records = cwe.parse_structured_field(raw)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["DESCRIPTION"],
                         "Avoid auto_ptr (defined by ISO/IEC 14882:2011) and use the C++ std::unique_ptr instead.")
        self.assertEqual(records[0]["STRATEGY"], "Libraries")
        self.assertEqual(records[1]["PHASE"], "Testing")
        self.assertEqual(set(k for r in records for k in r), {"PHASE", "STRATEGY", "DESCRIPTION"})
    def setUp(self):
        self.weaknesses = cwe.load(FIXTURES / "cwe_sample.csv")
        self.by_id = {w.cwe_id: w for w in self.weaknesses}

    def test_structured_field_is_read(self):
        records = cwe.parse_structured_field(self.by_id["89"].related_raw)
        self.assertEqual(records[0]["CWE ID"], "943")
        self.assertEqual(records[1]["NATURE"], "ChildOf")

    def test_parents_and_children(self):
        self.assertEqual(self.by_id["89"].parent_ids, ["943", "74"])
        self.assertEqual(self.by_id["74"].child_ids, ["89"])

    def test_structure_splits_by_field(self):
        chunks = cwe.structure_chunks(self.weaknesses)
        ids = [c.chunk_id for c in chunks]
        self.assertIn("cwe-struct-89-mitigations", ids)
        self.assertNotIn("cwe-struct-74-mitigations", ids)   # nothing to put in it
        self.assertEqual(sum(1 for i in ids if i.startswith("cwe-struct-89-")), 3)

    def test_relevance_labels(self):
        self.assertEqual(relevance_label("89", "89", self.by_id), 2)
        self.assertEqual(relevance_label("89", "74", self.by_id), 1)     # its parent
        self.assertEqual(relevance_label("74", "89", self.by_id), 1)     # its child
        self.assertEqual(relevance_label("89", "79", self.by_id), 0)
        self.assertEqual(relevance_label("89", "9999", self.by_id), 0)   # not in the file


class CbnTests(unittest.TestCase):
    def test_sample_text(self):
        clauses = cbn.load(FIXTURES / "cbn_sample.txt")
        self.assertEqual([c.section_id for c in clauses], ["1.0", "1.1", "1.1.1", "2.0"])
        chunks = cbn.structure_chunks(clauses)
        self.assertEqual([c.chunk_id for c in chunks], ["cbn-struct-part1", "cbn-struct-part2"])

    @unittest.skipUnless(Path("data/cbn_raw.txt").exists(), "data/cbn_raw.txt not present")
    def test_real_text_has_35_clauses(self):
        self.assertEqual(len(cbn.load("data/cbn_raw.txt")), 35)


class PciTests(unittest.TestCase):
    def setUp(self):
        self.reqs = [
            pci.PCIRequirement("1.2.1", "First requirement text goes here."),
            pci.PCIRequirement("1.2.5", "Second requirement text.", customized_objective="An objective."),
            pci.PCIRequirement("2.1.1", "Third requirement text."),
        ]

    def test_pieces_add_the_objective_on_a_new_line(self):
        pieces = pci.as_pieces(self.reqs)
        self.assertEqual(pieces[1], ("1.2.5", "Second requirement text.\nAn objective."))
        self.assertEqual(pieces[0][1], "First requirement text goes here.")

    def test_structure_groups_by_section(self):
        chunks = pci.structure_chunks(self.reqs)
        self.assertEqual([c.chunk_id for c in chunks], ["pci-struct-1.2", "pci-struct-2.1"])
        self.assertIn("Customized Approach Objective: An objective.", chunks[0].text)

    def test_continuation_duplicates_are_merged(self):
        first = pci.PCIRequirement("3.3.3", "The sentence starts here")
        second = pci.PCIRequirement("3.3.3", "and ends here.")
        merged = pci._merge_continuation_duplicates([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].requirement_text, "The sentence starts here and ends here.")


class AllSourcesShareOneShape(unittest.TestCase):
    def test_chunk_ids_are_unique_and_prefixed(self):
        sources = [
            (asvs, asvs.load(FIXTURES / "asvs_sample.csv")),
            (cwe, cwe.load(FIXTURES / "cwe_sample.csv")),
            (cbn, cbn.load(FIXTURES / "cbn_sample.txt")),
        ]
        seen = set()
        for module, records in sources:
            for strategy, chunks in chunk_all(module, records).items():
                for c in chunks:
                    self.assertTrue(c.chunk_id.startswith(module.PREFIX + "-"))
                    self.assertEqual(c.strategy, strategy)
                    self.assertNotIn(c.chunk_id, seen)
                    seen.add(c.chunk_id)


if __name__ == "__main__":
    unittest.main()
