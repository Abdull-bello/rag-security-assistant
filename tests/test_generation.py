import json, os, tempfile, unittest
from pathlib import Path

from generation.pipeline import assist
from generation.prompt import build_prompt
from generation.validate import parse_verdict, validate
from retrieval.search import Hit

GOOD = """VERDICT: TRUE_POSITIVE
SEVERITY: High, user input reaches the query [E1]
REMEDIATION:
1. Use parameterised queries [E1][E2]
2. Validate input against an allow list [E2]
3. Apply least privilege to the database account. No passage supports this
"""
BAD = """VERDICT: false positive
SEVERITY: Low, nothing found
REMEDIATION:
1. Escape the input [E9]
2. Review the code
"""

class FakeRetriever:
    def search(self, q, mode, k=5, alpha=0.7, pool=20):
        return [Hit(f"c{i}", f"text {i}", 1.0, "cwe", ["89"]) for i in range(1, 3)]

class FakeGen:
    def __init__(self, text): self.text = text
    def generate(self, prompt):
        self.last = prompt
        return {"text": self.text, "seconds": 0.1, "tokens": 5}

class T(unittest.TestCase):
    def test_good_output(self):
        v = validate(GOOD, 2)
        self.assertEqual(v["verdict"], "TRUE_POSITIVE")
        self.assertEqual(v["n_claims"], 4)
        self.assertEqual(v["n_citations"], 4)
        self.assertEqual(v["citation_coverage"], 1.0)
        self.assertTrue(v["all_citations_valid"])

    def test_bad_output(self):
        v = validate(BAD, 2)
        self.assertEqual(v["verdict"], "FALSE_POSITIVE")
        self.assertEqual(v["n_invalid_citations"], 1)
        self.assertEqual(v["claims_cited"], 0)
        self.assertFalse(v["all_citations_valid"])

    def test_missing_verdict(self):
        self.assertIsNone(parse_verdict("no format here"))
        self.assertFalse(validate("no format here", 2)["format_ok"])

    def test_prompt_labels_and_sources(self):
        p = build_prompt("finding X", FakeRetriever().search("q", "hybrid"))
        self.assertIn("[E1] (cwe) text 1", p)
        self.assertIn("[E2]", p)
        self.assertIn("FINDING:\nfinding X", p)

    def test_assist_grounded_and_baseline(self):
        g = FakeGen(GOOD)
        rec = assist("f", FakeRetriever(), g)
        self.assertEqual([e["chunk_id"] for e in rec["evidence"]], ["c1", "c2"])
        self.assertTrue(rec["validation"]["all_citations_valid"])
        base = assist("f", None, FakeGen(GOOD))
        self.assertEqual(base["evidence"], [])
        self.assertNotIn("citation_coverage", base["validation"])

if __name__ == "__main__":
    unittest.main()


class CodeAndSnippetTests(unittest.TestCase):
    def test_code_reaches_generator_not_retriever(self):
        seen = {}
        class R(FakeRetriever):
            def search(self, q, mode, k=5, alpha=0.7, pool=20):
                seen["q"] = q
                return super().search(q, mode)
        g = FakeGen(GOOD)
        rec = assist("the finding", R(), g, code=">>   12 stmt.execute(sql)")
        self.assertEqual(seen["q"], "the finding")
        self.assertIn(">>   12 stmt.execute(sql)", g.last)
        self.assertEqual(rec["code"], ">>   12 stmt.execute(sql)")
        b = FakeGen(GOOD); assist("the finding", None, b, code="X = 1")
        self.assertIn("X = 1", b.last)
        self.assertNotIn("EVIDENCE", b.last)

    def test_add_snippets(self):
        import csv, add_snippets
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            d = Path(d); (d / "app" / "routes").mkdir(parents=True)
            (d / "app" / "routes" / "a.ts").write_text("\n".join(f"line{i}" for i in range(1, 61)))
            with open(d / "items.csv", "w", newline="") as f:
                w = csv.writer(f); w.writerow(["item_id", "app", "location", "snippet"])
                w.writerow(["T1", "juiceshop", "/src/routes/a.ts:40", "requires login"])
                w.writerow(["T2", "juiceshop", "/src/routes/missing.ts:3", "requires login"])
            add_snippets.main(["--items", str(d / "items.csv"), "--root", f"juiceshop={d / 'app'}"])
            with open(d / "items.csv", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertIn(">>   40 line40", rows[0]["snippet"])
            self.assertIn("line10", rows[0]["snippet"]); self.assertIn("line45", rows[0]["snippet"])
            self.assertNotIn("line46", rows[0]["snippet"])
            self.assertEqual(rows[1]["snippet"], "")
