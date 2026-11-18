"""Turn Semgrep and ZAP JSON reports into candidate test items.

Usage (from the project folder):
  python build_items.py --semgrep output/semgrep_benchmark.json --app benchmark \
      --expected data/expectedresults-1.2.csv --cwe-csv data/1000.csv
  python build_items.py --zap output/zap_juice.json --app juiceshop --cwe-csv data/1000.csv

Writes output/candidates_<app>_<tool>.csv. You then review it by hand, mark
ground_truth (Juice Shop, WebGoat), keep 20 per class, and save the final
60 rows as data/test_items.csv.
"""
import argparse, csv, json, re, sys
from pathlib import Path

# OWASP class by CWE. Edit this table if your supervisor wants a different split.
CLASSES = {
    "Injection": {"74", "77", "78", "79", "89", "90", "91", "94", "95", "643", "564"},
    "Cryptographic Failures": {"310", "311", "319", "326", "327", "328", "330",
                               "331", "338", "759", "760", "916", "614", "1004"},
    "Broken Access Control": {"22", "23", "36", "73", "352", "601", "918"},
}
# Semgrep and the Benchmark answer key name some weaknesses differently.
# Each pair below is treated as the same test category.
SAME_TEST = {"326": "327", "23": "22", "36": "22"}

FIELDS = ["item_id", "cwe_class", "query", "finding_cwe", "tool", "app",
          "location", "rule", "snippet", "ground_truth"]


def cwe_class(num):
    for name, ids in CLASSES.items():
        if num in ids:
            return name
    return ""


def first_cwe(raw):
    """'CWE-89: Improper ...' or 89 or 'CWE-89' -> ('89', 'Improper ...')."""
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    m = re.search(r"(\d+)", str(raw))
    if not m:
        return "", ""
    name = str(raw).split(":", 1)[1].strip() if ":" in str(raw) else ""
    return m.group(1), name


def load_cwe_names(path):
    names = {}
    if not path or not Path(path).exists():
        return names
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("CWE-ID") and row.get("Name"):
                names[row["CWE-ID"].strip()] = row["Name"].strip()
    return names


def load_expected(path):
    """Benchmark expectedresults: test name -> (category, real vulnerability,
    cwe). Each Benchmark file tests one weakness only."""
    out = {}
    if not path:
        return out
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#") or len(row) < 3:
                continue
            cwe = row[3].strip() if len(row) > 3 else ""
            out[row[0].strip()] = (row[1].strip(), row[2].strip().lower(), cwe)
    return out


def make_query(message, cwe_name):
    # Option 2: finding message plus CWE name.
    message = " ".join(message.split())
    return f"{message} ({cwe_name})" if cwe_name else message


def from_semgrep(data, names):
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        num, inline = first_cwe(meta.get("cwe"))
        if not num:
            continue
        yield {"cwe": num, "name": names.get(num) or inline,
               "message": r["extra"].get("message", ""),
               "location": f"{r['path']}:{r['start']['line']}",
               "rule": r.get("check_id", ""),
               "snippet": "" if "requires login" in (r["extra"].get("lines") or "")
               else (r["extra"].get("lines") or "").strip()[:300]}


def from_zap(data, names):
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            num, _ = first_cwe(a.get("cweid"))
            if not num or num == "0":
                continue
            inst = (a.get("instances") or [{}])[0]
            yield {"cwe": num, "name": names.get(num, ""),
                   "message": a.get("name", "") + ". " + re.sub(r"<[^>]+>", "", a.get("desc", "")),
                   "location": inst.get("uri", ""),
                   "rule": str(a.get("pluginid", "")),
                   "snippet": (inst.get("evidence") or "")[:300]}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--semgrep"); p.add_argument("--zap")
    p.add_argument("--app", required=True)
    p.add_argument("--expected"); p.add_argument("--cwe-csv")
    p.add_argument("--out-dir", default="output")
    a = p.parse_args(argv)
    if bool(a.semgrep) == bool(a.zap):
        sys.exit("Give exactly one of --semgrep or --zap.")
    names = load_cwe_names(a.cwe_csv)
    expected = load_expected(a.expected)
    tool, path, reader = (("semgrep", a.semgrep, from_semgrep) if a.semgrep
                          else ("zap", a.zap, from_zap))
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    rows, seen, skipped, mismatched = [], set(), 0, 0
    for f in reader(data, names):
        cls = cwe_class(f["cwe"])
        if not cls:
            skipped += 1
            continue
        key = (f["cwe"], f["location"])   # two rules on one line are one finding
        if key in seen:
            continue
        seen.add(key)
        truth = ""
        m = re.search(r"(BenchmarkTest\d+)", f["location"])
        if m and m.group(1) in expected:
            # The answer key covers one weakness per file. A finding for a
            # different weakness in that file has no ground truth.
            _, real, tested = expected[m.group(1)]
            if SAME_TEST.get(f["cwe"], f["cwe"]) == SAME_TEST.get(tested, tested):
                truth = "true_positive" if real == "true" else "false_positive"
            else:
                mismatched += 1
        rows.append({"item_id": "", "cwe_class": cls,
                     "query": make_query(f["message"], f["name"]),
                     "finding_cwe": f["cwe"], "tool": tool, "app": a.app,
                     "location": f["location"], "rule": f["rule"],
                     "snippet": f["snippet"], "ground_truth": truth})
    for i, r in enumerate(rows, 1):
        r["item_id"] = f"{a.app[:3]}-{tool[:3]}-{i:04d}"
    out = Path(a.out_dir); out.mkdir(exist_ok=True)
    dest = out / f"candidates_{a.app}_{tool}.csv"
    with open(dest, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    counts = {c: sum(r["cwe_class"] == c for r in rows) for c in CLASSES}
    print(f"{len(rows)} candidates written to {dest}")
    print("per class:", counts, "| skipped (CWE outside the three classes):", skipped)
    if expected:
        labelled = sum(bool(r["ground_truth"]) for r in rows)
        print(f"with Benchmark ground truth: {labelled} | finding CWE differs from "
              f"the weakness the file tests (left unlabelled): {mismatched}")


if __name__ == "__main__":
    main()
