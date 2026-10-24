"""Replay the forecast over stored history to get accuracy numbers today
instead of waiting a month for live snapshots to age.

    python -m scripts.replay_eval --days 180

For each UTC day D in the range, rescore using only signals observed on or
before D, then judge that ranking against what happened in (D, D+horizon]
with the same evaluation used live. Results are stored with source=replay;
a live evaluation for the same day takes precedence once it exists.

What a replay cannot see, so read the numbers with this in mind:
  - Surface tags come from Claude and mostly exist on recent signals, so
    spillover is under-represented for older days. Inherited is not: catalog
    edges apply to history.
  - EPSS values are current, not as-of D. They are stripped here so the
    exploit term only sees KEV and exploitation flags.
  - Signals carry today's confidence, including Claude's later boosts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from app.db import iso, utcnow
from app.evaluation import evaluate_snapshot, summarize
from app.pipeline import Ctx
from app.scoring import _parse, score_all


def replay(days: int, quiet: bool = False) -> dict:
    ctx = Ctx()
    cfg = ctx.scoring["evaluation"]
    horizon = int(cfg["horizon_days"])
    max_age = ctx.scoring.get("max_signal_age_days", 180)
    now = utcnow()
    signals = ctx.db.signals_until(iso(now))
    for s in signals:
        s["epss"] = None
    if not signals:
        return {"days": 0}
    hist = ctx.db.get_kv("nvd_history_from")
    hist_dt = datetime.fromisoformat(hist) if hist else None
    if hist_dt and not hist_dt.tzinfo:
        hist_dt = hist_dt.replace(tzinfo=timezone.utc)
    first = max(min(_parse(s["observed_at"]) for s in signals) + timedelta(days=1), now - timedelta(days=days))
    day = first.replace(hour=0, minute=0, second=0, microsecond=0)
    last = (now - timedelta(days=horizon)).replace(hour=0, minute=0, second=0, microsecond=0)
    results = []
    while day <= last:
        past = [s for s in signals if 0 <= (day - _parse(s["observed_at"])).days <= max_age]
        history_days = (day - hist_dt).days if hist_dt else None
        rows = score_all(ctx.components, past, {}, ctx.scoring, now=day, history_days=history_days)
        res = evaluate_snapshot(rows, signals, day, cfg, ctx.components)
        ctx.db.write_eval(res, "replay")
        results.append(res)
        if not quiet:
            fmt = lambda v: " n/a" if v is None else f"{v:.2f}"
            parts = []
            for name, p in res["profiles"].items():
                m = p["metrics"]
                parts.append(f"{name}: {len(p['event_components']):>2} comps, hit@{res['k']} model {fmt(m['model']['hit_at_k'])} "
                             f"recency {fmt(m['recency']['hit_at_k'])}, predictive {p['cohorts']['predictive']['hits']}/{p['cohorts']['predictive']['n']}")
            print(f"{day:%Y-%m-%d}  " + " | ".join(parts))
        day += timedelta(days=1)
    summary = summarize(list(reversed(results)))
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days", type=int, default=180)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    s = replay(a.days, a.quiet)
    if not s.get("n"):
        print("nothing to replay")
        return
    print(f"\n{s['n']} days replayed ({s['first']} .. {s['last']})")
    for name, prof in s["profiles"].items():
        r = prof["rankings"]
        print(f"\n== {name}: {prof['distinct_events']} distinct events ==")
        print(f"{'ranking':10} {'hit@k':>7} {'prec@k':>7}")
        for nm in ("model", "recency", "prior", "chance"):
            h, p = r[nm]["hit_at_k"], r[nm]["precision_at_k"]
            print(f"{nm:10} {('n/a' if h is None else f'{h:.3f}'):>7} {('n/a' if p is None else f'{p:.3f}'):>7}")
        if prof["lift_vs_recency"] is not None:
            print(f"lift vs recency: {prof['lift_vs_recency']:+.3f}")
        for nm, label in (("predictive", "predictive-only picks (spillover/inherited, no direct activity)"),
                          ("quiet", "quiet components (nothing driving them)"),
                          ("active", "already active (direct activity or exploitation)")):
            v = prof["cohorts"][nm]
            rate = "n/a" if v["rate"] is None else f"{100 * v['rate']:.0f}%"
            print(f"  {label:<66} {v['hits']:>4} of {v['n']:<5} {rate:>5}")
    print("\nReplay caveats: spillover under-represented (surface tags are recent), EPSS stripped. See module docstring.")


if __name__ == "__main__":
    main()
