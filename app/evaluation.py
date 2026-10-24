"""Running accuracy of the forecast: did the components we ranked high go on
to have a serious event?

A prediction is a snapshot's ranking at time T. An outcome is an event on a
component in (T, T + horizon] that was not known for that component before
T. Outcome profiles live in scoring.yaml evaluation.outcomes; each is judged
separately, because "a new CVSS 9" and "exploited in the wild" are different
questions with very different base rates.

Every number is reported next to baselines (recency, prior, chance) because
an absolute hit rate means nothing on its own, and next to per-term cohorts:
components that had spillover or inherited points at T but no direct
activity are the model's genuinely predictive picks, and their outcome rate
against quiet components is the honest test of the predictive terms.

This is a monitor, not a training signal. Don't tune weights to it.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta

from .scoring import _parse, prior_score

PROFILE_NAMES = ("serious", "exploited")
RANKING_NAMES = ("model", "recency", "prior", "chance")
COHORT_NAMES = ("predictive", "quiet", "active")


def seen_before(signals: list[dict], start: datetime) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """(component, cve) pairs known before start, and the subset known exploited."""
    known: set[tuple[str, str]] = set()
    exploited: set[tuple[str, str]] = set()
    for s in signals:
        cve = s.get("cve") or ""
        if not cve or _parse(s["observed_at"]) > start:
            continue
        key = (s["component_id"], cve)
        known.add(key)
        if s.get("kev") or s.get("exploitation") == "confirmed":
            exploited.add(key)
    return known, exploited


def outcome_events(signals: list[dict], start: datetime, end: datetime, known: set, exploited: set,
                   oc: dict) -> dict[str, list[dict]]:
    """Per component, the events under outcome profile `oc` first seen in (start, end]."""
    found: dict[str, dict[str, dict]] = {}
    for s in signals:
        t = _parse(s["observed_at"])
        if not (start < t <= end):
            continue
        cid, cve = s["component_id"], s.get("cve") or ""
        key = (cid, cve)
        is_exploited = (bool(s.get("kev")) and oc.get("kev", True)) or \
                       (s.get("exploitation") == "confirmed" and oc.get("confirmed", True))
        is_severe = s.get("cvss") is not None and float(s["cvss"]) >= float(oc.get("min_cvss", 9.0))
        kind = None
        if is_exploited and (not cve or key not in exploited):
            kind = "exploited"
        elif is_severe and (not cve or key not in known):
            kind = "severe"
        if kind:
            dedupe = cve or s.get("intel_id") or s["observed_at"]
            found.setdefault(cid, {}).setdefault(dedupe, {"cve": cve or None, "kind": kind, "at": s["observed_at"]})
    return {cid: list(v.values()) for cid, v in found.items()}


def rankings(rows: list[dict], signals: list[dict], start: datetime, cfg: dict,
             components: dict[str, dict]) -> dict[str, list[str]]:
    """The model's order and the naive orders it must beat."""
    cids = [r["component_id"] for r in rows]
    window = start - timedelta(days=cfg.get("recency_window_days", 90))
    recent: dict[str, set[str]] = {c: set() for c in cids}
    for s in signals:
        t = _parse(s["observed_at"])
        if window < t <= start and s["component_id"] in recent:
            recent[s["component_id"]].add(s.get("cve") or s.get("intel_id") or s["observed_at"])
    pri = {c: prior_score((components.get(c) or {}).get("priors")) for c in cids}
    return {
        "model": [r["component_id"] for r in sorted(rows, key=lambda r: -r["likelihood"])],
        "recency": sorted(cids, key=lambda c: (-len(recent[c]), -pri[c])),
        "prior": sorted(cids, key=lambda c: -pri[c]),
    }


def score_ranking(order: list[str], hits: set[str], k: int) -> dict:
    pos = {cid: i + 1 for i, cid in enumerate(order)}
    ranks = [pos[h] for h in hits if h in pos]
    top = set(order[:k])
    return {
        "hit_at_k": (sum(r <= k for r in ranks) / len(ranks)) if ranks else None,
        "precision_at_k": len(top & hits) / k if k else None,
        "mrr": statistics.mean(1 / r for r in ranks) if ranks else None,
    }


def cohorts(rows: list[dict], hits: set[str], cfg: dict) -> dict:
    """Outcome rate by what drove the score at T. 'predictive' components had
    only spillover/inherited points; 'quiet' had nothing; 'active' had direct
    activity or exploitation evidence already."""
    thr = float(cfg.get("cohort_min_points", 5))
    out: dict[str, list[str]] = {name: [] for name in COHORT_NAMES}
    for r in rows:
        p = r["points"]
        if p.get("activity", 0) > 0 or p.get("exploit", 0) > 0:
            out["active"].append(r["component_id"])
        elif p.get("spillover", 0) + p.get("inherited", 0) >= thr:
            out["predictive"].append(r["component_id"])
        else:
            out["quiet"].append(r["component_id"])
    return {name: {"n": len(cids), "hits": sum(c in hits for c in cids), "components": cids}
            for name, cids in out.items()}


def evaluate_snapshot(rows: list[dict], signals: list[dict], start: datetime, cfg: dict,
                      components: dict[str, dict]) -> dict:
    """Judge one snapshot (rows as produced by score_all at `start`) against
    what happened in the following horizon, under every outcome profile.
    `signals` must include everything up to start + horizon."""
    horizon = int(cfg.get("horizon_days", 30))
    k = int(cfg.get("k", 10))
    end = start + timedelta(days=horizon)
    known, exploited = seen_before(signals, start)
    orders = rankings(rows, signals, start, cfg, components)
    n = len(rows) or 1
    profiles = {}
    for name, oc in (cfg.get("outcomes") or {}).items():
        events = outcome_events(signals, start, end, known, exploited, oc)
        hits = set(events)
        metrics = {rk: score_ranking(order, hits, k) for rk, order in orders.items()}
        metrics["chance"] = {"hit_at_k": k / n, "precision_at_k": len(hits) / n, "mrr": None}
        profiles[name] = {
            "events": sum(len(v) for v in events.values()),
            "event_keys": sorted(f"{cid}:{e['cve'] or e['at'][:10]}" for cid, evs in events.items() for e in evs),
            "event_components": sorted(hits),
            "metrics": metrics, "cohorts": cohorts(rows, hits, cfg),
        }
    return {"ts": start.isoformat(), "horizon_days": horizon, "k": k, "profiles": profiles}


def summarize(evals: list[dict]) -> dict:
    """Aggregate stored evaluations into the numbers the dashboards show.
    Events are counted once across overlapping windows."""
    if not evals:
        return {"n": 0}
    out = {"n": len(evals), "first": min(e["ts"] for e in evals)[:10], "last": max(e["ts"] for e in evals)[:10],
           "sources": sorted({e.get("source", "live") for e in evals}), "profiles": {}}
    names = sorted({p for e in evals for p in (e.get("profiles") or {})})
    for name in names:
        agg = {rk: {"hit_at_k": [], "precision_at_k": []} for rk in RANKING_NAMES}
        coh = {c: {"n": 0, "hits": 0} for c in COHORT_NAMES}
        distinct: set[str] = set()
        for e in evals:
            p = (e.get("profiles") or {}).get(name)
            if not p:
                continue
            distinct.update(p.get("event_keys") or [])
            for rk in RANKING_NAMES:
                m = p["metrics"].get(rk) or {}
                for metric in ("hit_at_k", "precision_at_k"):
                    if m.get(metric) is not None:
                        agg[rk][metric].append(m[metric])
            for c in coh:
                cc = p["cohorts"].get(c) or {}
                coh[c]["n"] += cc.get("n", 0)
                coh[c]["hits"] += cc.get("hits", 0)
        rankings_out = {rk: {m: (round(statistics.mean(v), 3) if v else None) for m, v in agg[rk].items()} for rk in RANKING_NAMES}
        model, rec = rankings_out["model"]["hit_at_k"], rankings_out["recency"]["hit_at_k"]
        out["profiles"][name] = {
            "distinct_events": len(distinct),
            "rankings": rankings_out,
            "lift_vs_recency": round(model - rec, 3) if model is not None and rec is not None else None,
            "cohorts": {c: {**v, "rate": (round(v["hits"] / v["n"], 3) if v["n"] else None)} for c, v in coh.items()},
        }
    return out
