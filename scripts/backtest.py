"""Backtest the likelihood model by replaying CISA KEV.

For each month M: score every component using only KEV entries added before M,
then check where the components that actually got new KEV entries during M
landed in the ranking. Compare against three naive baselines:

  install_base   rank by the install_base prior alone
  prior          rank by the full structural prior alone
  recency        rank by count of KEV entries in the previous 90 days

If the model doesn't beat `recency`, the extra machinery isn't earning its
keep on this data, and you should say so before trusting the dashboard.

Scope limits (be honest about these when you share results):
  - Exercises prior + activity + exploit only. KEV has no attack-surface tags
    and no dependency labels, so spillover and inherited are NOT tested here.
    Testing them needs a labeled history of Claude extractions, which
    accumulates as the app runs.
  - Signals carry no history, so baseline subtraction runs in cold-start mode
    (beta = 0). Don't pass history_days to enable it; the replay has no
    baseline window to subtract against.
  - Exposure is ignored; this tests the global forecast, not your estate's priority.
  - KEV listing is a lagging, US-government-curated label of exploitation,
    not ground truth for "a vuln appeared".

Usage (offline; download the catalog first):
  curl -sSo kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  python -m scripts.backtest kev.json --start 2025-01 --end 2026-10 --k 10
"""
from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timedelta, timezone

from app.config import load_yaml
from app.matching import Matcher
from app.scoring import prior_score, score_all


def month_starts(start: str, end: str):
    y, m = map(int, start.split("-"))
    ey, em = map(int, end.split("-"))
    while (y, m) < (ey, em):
        yield datetime(y, m, 1, tzinfo=timezone.utc)
        m += 1
        if m == 13:
            y, m = y + 1, 1


def kev_events(catalog: dict, matcher: Matcher) -> list[tuple[datetime, str, str]]:
    out = []
    for v in catalog.get("vulnerabilities", []):
        try:
            d = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        for cid in matcher.match_kev(v.get("vendorProject", ""), v.get("product", "")):
            out.append((d, cid, v.get("cveID", "")))
    return sorted(out)


def evaluate(rankings: dict[str, list[str]], hits: set[str], k: int) -> dict:
    res = {}
    for name, order in rankings.items():
        pos = {cid: i + 1 for i, cid in enumerate(order)}
        ranks = [pos[h] for h in hits if h in pos]
        res[name] = {
            "hit_at_k": sum(r <= k for r in ranks) / len(ranks) if ranks else None,
            "mrr": statistics.mean(1 / r for r in ranks) if ranks else None,
        }
    return res


def run(catalog: dict, start: str, end: str, k: int, lookback_days: int = 120) -> dict:
    components = load_yaml("components.yaml")
    cfg = load_yaml("scoring.yaml")
    matcher = Matcher(components)
    events = kev_events(catalog, matcher)
    names = ("model", "recency", "prior", "install_base")
    per_month, agg = [], {n: {"hit_at_k": [], "mrr": []} for n in names}

    for ms in month_starts(start, end):
        me = (ms + timedelta(days=32)).replace(day=1)
        hits = {cid for d, cid, _ in events if ms <= d < me}
        if not hits:
            continue
        past = [(d, cid, cve) for d, cid, cve in events if ms - timedelta(days=lookback_days) <= d < ms]
        signals = [{"component_id": cid, "cve": cve, "kev": True, "exploitation": "confirmed",
                    "confidence": 0.95, "observed_at": d.isoformat(), "surfaces": []}
                   for d, cid, cve in past]
        # Empty inventory makes exposure constant, so priority order == likelihood order.
        model = [r["component_id"] for r in score_all(components, signals, {}, cfg, now=ms)]
        recent = {cid: 0 for cid in components}
        for d, cid, _ in past:
            if d >= ms - timedelta(days=90):
                recent[cid] += 1
        rankings = {
            "model": model,
            "recency": sorted(components, key=lambda c: (-recent[c], -prior_score(components[c]["priors"]))),
            "prior": sorted(components, key=lambda c: -prior_score(components[c]["priors"])),
            "install_base": sorted(components, key=lambda c: -components[c]["priors"].get("install_base", 0)),
        }
        ev = evaluate(rankings, hits, k)
        per_month.append({"month": ms.strftime("%Y-%m"), "hits": sorted(hits), **ev})
        for n in names:
            for metric in ("hit_at_k", "mrr"):
                if ev[n][metric] is not None:
                    agg[n][metric].append(ev[n][metric])

    summary = {n: {m: (round(statistics.mean(v), 3) if v else None) for m, v in agg[n].items()} for n in names}
    return {"months": per_month, "summary": summary, "k": k, "components": len(components)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kev_json")
    ap.add_argument("--start", default="2025-01")
    ap.add_argument("--end", default="2026-10")
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--json", action="store_true", help="print full JSON result")
    a = ap.parse_args()
    with open(a.kev_json, encoding="utf-8") as f:
        result = run(json.load(f), a.start, a.end, a.k)
    if a.json:
        print(json.dumps(result, indent=1))
        return
    print(f"{len(result['months'])} months with catalog KEV hits, {result['components']} components, k={a.k}\n")
    print(f"{'ranking':14} {'hit@k':>7} {'MRR':>7}")
    for n, m in result["summary"].items():
        hk = "n/a" if m["hit_at_k"] is None else f"{m['hit_at_k']:.3f}"
        mr = "n/a" if m["mrr"] is None else f"{m['mrr']:.3f}"
        print(f"{n:14} {hk:>7} {mr:>7}")
    print("\nSpillover and inherited are not exercised by a KEV replay; activity ran in cold-start mode. "
          "See module docstring.")


if __name__ == "__main__":
    main()
