import json, tempfile, unittest, csv
from pathlib import Path
import build_items as b

SEMGREP = {"results": [
 {"check_id": "java.sqli", "path": "src/BenchmarkTest00001.java", "start": {"line": 40},
  "extra": {"message": "Unsanitized  SQL query", "lines": "stmt.execute(sql)",
            "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]}}},
 {"check_id": "java.sqli", "path": "src/BenchmarkTest00001.java", "start": {"line": 40},
  "extra": {"message": "dup", "metadata": {"cwe": ["CWE-89: x"]}}},
 {"check_id": "java.hash", "path": "src/BenchmarkTest00002.java", "start": {"line": 9},
  "extra": {"message": "Weak hash", "metadata": {"cwe": "CWE-328: Use of Weak Hash"}}},
 {"check_id": "java.rand", "path": "src/BenchmarkTest00003.java", "start": {"line": 5},
  "extra": {"message": "Weak random", "metadata": {"cwe": ["CWE-330: Weak PRNG"]}}},
 {"check_id": "java.des", "path": "src/BenchmarkTest00004.java", "start": {"line": 5},
  "extra": {"message": "DES", "metadata": {"cwe": ["CWE-326: Inadequate Encryption Strength"]}}},
 {"check_id": "x.nocwe", "path": "a.java", "start": {"line": 1}, "extra": {"message": "m", "metadata": {}}},
 {"check_id": "x.other", "path": "a.java", "start": {"line": 2},
  "extra": {"message": "m", "metadata": {"cwe": ["CWE-1234: other"]}}}]}
ZAP = {"site": [{"alerts": [{"pluginid": "40018", "name": "SQL Injection", "cweid": "89",
  "desc": "<p>SQL may be injected</p>", "instances": [{"uri": "http://x/rest?q=1", "evidence": "err"}]},
  {"pluginid": "1", "name": "Info", "cweid": "-1", "desc": "", "instances": []}]}]}
EXPECTED = ("# test name, category, real vulnerability, cwe\nBenchmarkTest00001,sqli,true,89\n"
            "BenchmarkTest00002,hash,false,328\nBenchmarkTest00003,sqli,true,89\n"
            "BenchmarkTest00004,crypto,true,327\n")

class T(unittest.TestCase):
    def run_cli(self, args_extra, key, payload, expected=None):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            d = Path(d); (d / "in.json").write_text(json.dumps(payload))
            args = [f"--{key}", str(d / "in.json"), "--app", "benchmark", "--out-dir", str(d / "o")]
            if expected:
                (d / "e.csv").write_text(expected); args += ["--expected", str(d / "e.csv")]
            b.main(args)
            with open(next((d / "o").glob("*.csv")), newline="") as f:
                return list(csv.DictReader(f))

    def test_semgrep(self):
        rows = self.run_cli(None, "semgrep", SEMGREP, EXPECTED)
        self.assertEqual(len(rows), 4)  # dup, no-CWE and out-of-class dropped
        # weak random found in a file that tests SQL injection: no ground truth
        self.assertEqual(rows[2]["ground_truth"], "")
        # CWE-326 finding in a CWE-327 test file counts as the same category
        self.assertEqual(rows[3]["ground_truth"], "true_positive")
        self.assertEqual(rows[0]["cwe_class"], "Injection")
        self.assertEqual(rows[0]["query"], "Unsanitized SQL query (Improper Neutralization of Special Elements used in an SQL Command)")
        self.assertEqual(rows[0]["ground_truth"], "true_positive")
        self.assertEqual(rows[1]["cwe_class"], "Cryptographic Failures")
        self.assertEqual(rows[1]["ground_truth"], "false_positive")

    def test_zap(self):
        rows = self.run_cli(None, "zap", ZAP)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["finding_cwe"], "89")
        self.assertIn("SQL may be injected", rows[0]["query"])
        self.assertNotIn("<p>", rows[0]["query"])

if __name__ == "__main__":
    unittest.main()
