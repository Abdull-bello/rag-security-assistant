"""Fill the snippet column of an items file with the source lines around
each finding. Run it where the scanned source code is (the Kali machine).

  python3 add_snippets.py --items test_items.csv \
      --root benchmark=~/rag-targets/BenchmarkJava \
      --root juiceshop=~/rag-targets/juice-shop \
      --root webgoat=~/rag-targets/WebGoat

The scanner saw each application mounted at /src, so a location such as
/src/routes/login.ts:34 is read from <root>/routes/login.ts, line 34.
The flagged line is marked with >>. Standard library only.
"""
import argparse, csv, os


def snippet(path, line, before, after, max_chars):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    lo, hi = max(1, line - before), min(len(lines), line + after)
    out = [f"{'>>' if n == line else '  '} {n:4d} {lines[n - 1].rstrip()}"
           for n in range(lo, hi + 1) if lines[n - 1].strip()]
    while len("\n".join(out)) > max_chars and len(out) > after + 2:
        out.pop(0)                      # drop the earliest lines first
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--items", required=True)
    p.add_argument("--root", action="append", required=True, help="app=path")
    p.add_argument("--before", type=int, default=30)
    p.add_argument("--after", type=int, default=5)
    p.add_argument("--max-chars", type=int, default=1500)
    a = p.parse_args(argv)
    roots = {k: os.path.expanduser(v) for k, v in (r.split("=", 1) for r in a.root)}

    with open(a.items, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    done = missing = 0
    for r in rows:
        loc, _, line = r["location"].rpartition(":")
        rel = loc[len("/src/"):] if loc.startswith("/src/") else loc.lstrip("/")
        path = os.path.join(roots.get(r["app"], ""), rel)
        if r["app"] in roots and os.path.isfile(path) and line.isdigit():
            r["snippet"] = snippet(path, int(line), a.before, a.after, a.max_chars)
            done += 1
        else:
            r["snippet"] = ""
            missing += 1
            print("not found:", r["item_id"], path)
    with open(a.items, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"{done} snippets written, {missing} not found, file updated: {a.items}")


if __name__ == "__main__":
    main()
