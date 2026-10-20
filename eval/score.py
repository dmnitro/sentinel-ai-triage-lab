"""Score agent verdicts against hand labels.

  python eval/score.py v1                     grid + counts for one run
  python eval/score.py v1 v1-r2 v1-r3         also checks consistency across repeat runs
  python eval/score.py base                   score the rule-based baseline the same way, to compare

labels.csv columns: incident,run_id,truth,category,split   (split = dev or holdout)
"""
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = ("true_positive", "benign", "needs_human")


def load(here=HERE):
    labels = {r["incident"]: r for r in csv.DictReader((here / "labels.csv").open(encoding="utf-8"))}
    rows = list(csv.DictReader((here / "agent_verdicts.csv").open(encoding="utf-8")))
    return labels, rows


def score(tag, labels, rows):
    got = {r["incident"]: r for r in rows if r["run_tag"] == tag and r["incident"] in labels}
    grid = Counter((labels[i]["truth"], r["verdict"]) for i, r in got.items())
    by_cat = defaultdict(Counter)
    for i, r in got.items():
        by_cat[labels[i].get("category", "?")][r["verdict"]] += 1
    cost = sum(float(r.get("cost_usd") or 0) for r in got.values())
    return got, grid, by_cat, cost


def report(tags, labels, rows):
    tag = tags[0]
    got, grid, by_cat, cost = score(tag, labels, rows)
    mal = sum(n for (t, _), n in grid.items() if t == "malicious")
    ben = sum(n for (t, _), n in grid.items() if t == "benign")
    out = [f"# Results for {tag} ({len(got)} incidents)", "",
           "| truth \\ verdict | " + " | ".join(ORDER) + " |", "|---|---|---|---|"]
    for t in ("malicious", "benign"):
        out.append(f"| {t} | " + " | ".join(str(grid[(t, v)]) for v in ORDER) + " |")
    out += ["",
            f"- Attacks caught: {grid[('malicious', 'true_positive')]} of {mal}",
            f"- **Attacks wrongly dismissed as benign: {grid[('malicious', 'benign')]}** (target 0)",
            f"- Benign correctly dismissed: {grid[('benign', 'benign')]} of {ben}",
            f"- Sent to a human: {sum(n for (_, v), n in grid.items() if v == 'needs_human')}",
            f"- Model cost for the run: ${cost:.4f}"
            + (f" (${cost / len(got):.4f} per incident)" if got else ""),
            "", "## By category", "", "| category | " + " | ".join(ORDER) + " |", "|---|---|---|---|"]
    for cat in sorted(by_cat):
        out.append(f"| {cat} | " + " | ".join(str(by_cat[cat][v]) for v in ORDER) + " |")
    splits = sorted({labels[i].get("split") or "all" for i in got})
    if len(splits) > 1:
        out += ["", "## Dev vs held-out", "",
                "Tune prompts on dev only. The held-out rows are the honest number.", "",
                "| split | incidents | attacks caught | attacks dismissed as benign | benign dismissed correctly |",
                "|---|---|---|---|---|"]
        for sp in splits:
            ids = [i for i in got if (labels[i].get("split") or "all") == sp]
            g = Counter((labels[i]["truth"], got[i]["verdict"]) for i in ids)
            m = sum(n for (tr, _), n in g.items() if tr == "malicious")
            b = sum(n for (tr, _), n in g.items() if tr == "benign")
            out.append(f"| {sp} | {len(ids)} | {g[('malicious', 'true_positive')]} of {m} | "
                       f"{g[('malicious', 'benign')]} | {g[('benign', 'benign')]} of {b} |")
    if len(tags) > 1:
        runs = [score(t, labels, rows)[0] for t in tags]
        common = set.intersection(*(set(r) for r in runs))
        same = sum(1 for i in common if len({r[i]["verdict"] for r in runs}) == 1)
        out += ["", "## Consistency", "",
                f"- Same verdict in all {len(tags)} runs ({', '.join(tags)}): {same} of {len(common)} incidents"]
        for i in sorted(common):
            vs = [r[i]["verdict"] for r in runs]
            if len(set(vs)) > 1:
                out.append(f"  - incident {i}: {' / '.join(vs)}")
    return "\n".join(out)


def main(argv):
    tags = argv[1:] or ["v1"]
    labels, rows = load()
    text = report(tags, labels, rows)
    (HERE / f"RESULTS-{tags[0]}.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main(sys.argv)
