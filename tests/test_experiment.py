"""End to end: fake Ollama server + small index + run_experiment + summary."""
import csv, json, os, subprocess, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import run_experiment
from generation import ollama
from retrieval.index import build_index
from tests.test_retrieval import LengthReranker, WordEmbedder, make_chunks

REPLY = ("VERDICT: TRUE_POSITIVE\nSEVERITY: High, input reaches the query [E1]\n"
         "REMEDIATION:\n1. Use parameterised queries [E1]\n2. Validate input [E2]\n")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body["stream"] is False and body["options"]["temperature"] == 0.0
        data = json.dumps({"response": REPLY, "eval_count": 30}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(data)

    def log_message(self, *a): pass


class ExperimentTest(unittest.TestCase):
    def test_run_resume_and_summary(self):
        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}/api/generate"
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            d = Path(d)
            for s in ("fixed_window", "structure_aware"):
                build_index(s, make_chunks(), WordEmbedder(), d / "db")
            with open(d / "items.csv", "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["item_id", "cwe_class", "query", "finding_cwe", "ground_truth"])
                w.writerow(["a1", "Injection", "sql injection query", "89", "true_positive"])
                w.writerow(["a2", "Injection", "weak hash", "328", "false_positive"])
            args = ["--items", str(d / "items.csv"), "--model", "fake", "--db", str(d / "db"),
                    "--out", str(d / "out" / "runs.jsonl"), "--winner", "structure_aware",
                    "--conditions", "BASE", "S1_fixed", "S2_rerank"]
            with mock.patch.object(ollama, "DEFAULT_URL", url), \
                 mock.patch.object(ollama.OllamaGenerator.__init__, "__defaults__",
                                   (42, 0.0, 4096, 400, url, 900)), \
                 mock.patch.object(run_experiment, "Embedder", WordEmbedder), \
                 mock.patch.object(run_experiment, "Reranker", LengthReranker):
                run_experiment.main(args)
                run_experiment.main(args)          # second call must add nothing
            recs = [json.loads(l) for l in open(d / "out" / "runs.jsonl")]
            self.assertEqual(len(recs), 6)
            base = [r for r in recs if r["condition"] == "BASE"][0]
            self.assertEqual(base["evidence"], [])
            grounded = [r for r in recs if r["condition"] == "S2_rerank"][0]
            self.assertEqual(grounded["strategy"], "structure_aware")
            self.assertTrue(grounded["evidence"][0]["text"])
            self.assertTrue(grounded["validation"]["all_citations_valid"])
            root = Path(__file__).resolve().parent.parent
            out = subprocess.run([sys.executable, str(root / "summarise_runs.py"),
                                  str(d / "out" / "runs.jsonl"), str(d / "out" / "s.csv")],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            rows = list(csv.DictReader(open(d / "out" / "s.csv")))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["triage_accuracy"], "0.5")
        server.shutdown()


if __name__ == "__main__":
    unittest.main()
