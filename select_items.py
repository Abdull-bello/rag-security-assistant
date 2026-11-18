"""Draw a balanced draft test set from the candidate files.

  python select_items.py --per-class 20 --from-other-apps 10

For each class:
  1. up to --from-other-apps items come from Juice Shop and WebGoat, taking
     turns between (app, CWE) groups so no single weakness fills the class;
  2. the rest come from OWASP Benchmark, using only findings that have a
     ground-truth verdict, taking turns between CWEs and between true and
     false positives where both exist.
The draw uses a fixed seed, so it can be repeated. Writes
data/test_items_draft.csv and prints what was drawn.
"""
import argparse, csv, glob, random
from collections import Counter, defaultdict
from pathlib import Path


def take_turns(groups, n, rng):
    """Round-robin over the groups until n rows are taken or all are empty."""
    keys = sorted(groups)
    rng.shuffle(keys)
    for k in keys:
        rng.shuffle(groups[k])
    out = []
    while len(out) < n and any(groups[k] for k in keys):
        for k in keys:
            if groups[k] and len(out) < n:
                out.append(groups[k].pop())
    return out


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--per-class", type=int, default=20)
    p.add_argument("--from-other-apps", type=int, default=10)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--pattern", default="output/candidates_*.csv")
    p.add_argument("--out", default="data/test_items_draft.csv")
    p.add_argument("--exclude", help="items file whose findings must not be drawn again "
                                     "(use it to draw formative items apart from the test set)")
    a = p.parse_args(argv)

    rows = []
    for path in sorted(glob.glob(a.pattern)):
        with open(path, newline="", encoding="utf-8") as f:
            rows += list(csv.DictReader(f))
    if not rows:
        raise SystemExit(f"no candidate rows found for {a.pattern}")
    if a.exclude:
        with open(a.exclude, newline="", encoding="utf-8-sig") as f:
            used = {(r["app"], r["location"], r["rule"]) for r in csv.DictReader(f)}
        before = len(rows)
        rows = [r for r in rows if (r["app"], r["location"], r["rule"]) not in used]
        print(f"excluded {before - len(rows)} findings already in {a.exclude}")
    rng = random.Random(a.seed)
    picked = []
    for cls in sorted({r["cwe_class"] for r in rows}):
        others, bench = defaultdict(list), defaultdict(list)
        for r in rows:
            if r["cwe_class"] != cls:
                continue
            if r["app"] == "benchmark":
                if r["ground_truth"]:
                    bench[(r["finding_cwe"], r["ground_truth"])].append(r)
            else:
                others[(r["app"], r["finding_cwe"])].append(r)
        chosen = take_turns(others, a.from_other_apps, rng)
        chosen += take_turns(bench, a.per_class - len(chosen), rng)
        picked += chosen
        mix = Counter((c["app"], c["finding_cwe"], c["ground_truth"] or "to label") for c in chosen)
        print(f"{cls}: {len(chosen)} items")
        for (app, cwe, truth), n in sorted(mix.items()):
            print(f"    {n:2d}  {app:10s} CWE-{cwe:5s} {truth}")
    for i, r in enumerate(picked, 1):
        r["item_id"] = f"{'F' if a.exclude else 'T'}{i:03d}"
    Path(a.out).parent.mkdir(exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(picked)
    print(f"{len(picked)} rows written to {a.out}")


if __name__ == "__main__":
    main()
