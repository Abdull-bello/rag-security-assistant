"""Task-level and citation summary of output/runs.jsonl, per condition.

Triage accuracy, and precision and recall of the true-positive class, use
items whose ground_truth is true_positive or false_positive. An UNCERTAIN
verdict counts as wrong for accuracy and as a miss for recall.
"""
import csv, json, sys
from generation.validate import validate
from collections import defaultdict
from statistics import mean, median

path = sys.argv[1] if len(sys.argv) > 1 else "output/runs.jsonl"
out = sys.argv[2] if len(sys.argv) > 2 else "output/run_summary.csv"
# Verdicts are read from the items file when it exists, so labels added or
# corrected after a run are used without running the generator again.
truth = {}
items_path = sys.argv[3] if len(sys.argv) > 3 else "data/test_items.csv"
try:
    with open(items_path, newline="", encoding="utf-8-sig") as f:
        truth = {r["item_id"]: r.get("ground_truth", "") for r in csv.DictReader(f)}
except FileNotFoundError:
    pass

by_cond = defaultdict(list)
for line in open(path, encoding="utf-8"):
    r = json.loads(line)
    r["ground_truth"] = truth.get(r["item_id"], r.get("ground_truth", ""))
    # Re-check citations with the current validator, so a fix to the checker
    # applies to outputs generated before it.
    r["validation"] = validate(r["output"], len(r["evidence"]), grounded=bool(r["evidence"]))
    by_cond[r["condition"]].append(r)

rows = []
for cond, recs in sorted(by_cond.items()):
    judged = [r for r in recs if r["ground_truth"] in ("true_positive", "false_positive")]
    pred_tp = [r for r in judged if r["validation"]["verdict"] == "TRUE_POSITIVE"]
    real_tp = [r for r in judged if r["ground_truth"] == "true_positive"]
    hit = [r for r in pred_tp if r["ground_truth"] == "true_positive"]
    correct = [r for r in judged
               if (r["validation"]["verdict"] == "TRUE_POSITIVE") == (r["ground_truth"] == "true_positive")
               and r["validation"]["verdict"] in ("TRUE_POSITIVE", "FALSE_POSITIVE")]
    g = [r["validation"] for r in recs if "citation_coverage" in r["validation"]]
    rows.append({
        "condition": cond, "outputs": len(recs), "judged_items": len(judged),
        "triage_accuracy": round(len(correct) / len(judged), 4) if judged else "",
        "tp_precision": round(len(hit) / len(pred_tp), 4) if pred_tp else "",
        "tp_recall": round(len(hit) / len(real_tp), 4) if real_tp else "",
        "format_ok_share": round(mean(r["validation"]["format_ok"] for r in recs), 4),
        "citation_coverage": round(mean(v["citation_coverage"] for v in g), 4) if g else "",
        "all_citations_valid_share": round(mean(v["all_citations_valid"] for v in g), 4) if g else "",
        "median_seconds": median(r["seconds"] for r in recs),
    })
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
for r in rows:
    print(r)
