"""Make the blind hand-scoring sheet and the RAGAs export from runs.jsonl.

hand_sheet.csv : N outputs sampled across conditions, shuffled, with no
                 condition shown. Fill the score column (1 to 4, Table 3.8).
hand_key.csv   : the key linking sheet_id to condition and item. Do not open
                 it until scoring is finished.
ragas_input.jsonl : question, answer, contexts, one line per grounded output,
                 for the separate hosted judge.
"""
import csv, json, random, sys
from pathlib import Path

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
runs = [json.loads(l) for l in open("output/runs.jsonl", encoding="utf-8")]
random.Random(7).shuffle(runs)
sample = runs[:N]
with open("output/hand_sheet.csv", "w", newline="", encoding="utf-8") as f, \
     open("output/hand_key.csv", "w", newline="", encoding="utf-8") as k:
    w = csv.writer(f); kw = csv.writer(k)
    w.writerow(["sheet_id", "finding", "code", "evidence", "output", "score_1_to_4", "notes"])
    kw.writerow(["sheet_id", "condition", "item_id"])
    for i, r in enumerate(sample, 1):
        ev = "\n\n".join(f"[{e['label']}] {e.get('text', '')}" for e in r["evidence"])
        w.writerow([i, r["finding"], r.get("code", ""), ev, r["output"], "", ""])
        kw.writerow([i, r["condition"], r["item_id"]])
with open("output/ragas_input.jsonl", "w", encoding="utf-8") as f:
    for r in runs:
        if not r["evidence"]:
            continue
        f.write(json.dumps({"condition": r["condition"], "item_id": r["item_id"],
                            "question": r["finding"], "answer": r["output"],
                            "contexts": [e.get("text", "") for e in r["evidence"]],
                            "context_ids": [e["chunk_id"] for e in r["evidence"]]}) + "\n")
print(f"hand sheet: {len(sample)} rows; ragas input written")
