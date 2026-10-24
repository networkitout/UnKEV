"""Deterministic scoring. Pure functions, stdlib only, no I/O.

likelihood (0-100): how likely this component produces an exploitable,
    newsworthy vuln in the near term. Global, not estate-specific.
exposure (0-1): how much of it your estate runs, per inventory + declared appliances.
priority: likelihood scaled by exposure, with a floor so an unknown or
    low-exposure component still shows up on the forecast.

Every score carries its term breakdown and the signals that drove it, so
the dashboard can always answer "why is this ranked here?".
"""
from __future__ import annotations

import math
from datetime import datetime, timezone


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def decay(age_days: float, half_life: float) -> float:
    return 0.5 ** (max(age_days, 0.0) / half_life)


def saturate(x: float) -> float:
    return 1.0 - math.exp(-max(x, 0.0))


def sev_weight(cvss: float | None) -> float:
    if cvss is None:
        return 0.5
    if cvss >= 9.0:
        return 1.0
    if cvss >= 7.0:
        return 0.6
    if cvss >= 4.0:
        return 0.3
    return 0.15


def prior_score(priors: dict) -> float:
    p = priors or {}
    return (0.30 * min(p.get("memory_unsafe", 0), 1)
            + 0.25 * p.get("preauth", 0) / 3
            + 0.20 * p.get("install_base", 0) / 3
            + 0.15 * p.get("embedding", 0) / 3
            + 0.10 * p.get("legacy_tail", 0) / 3)


def exposure_score(inv: dict | None, cfg: dict) -> tuple[float, str]:
    ecfg = cfg["exposure"]
    if not inv or inv.get("status") == "unknown":
        return ecfg["unknown_default"], "unknown"
    hosts = int(inv.get("hosts", 0))
    if hosts <= 0:
        return ecfg["none_value"], "none"
    inet = int(inv.get("internet_facing", 0))
    crit = int(inv.get("critical", 0))
    e = (0.50 * min(1.0, math.log10(1 + hosts) / 3)
         + 0.35 * min(1.0, inet / 5)
         + 0.15 * min(1.0, crit / 3))
    return max(e, 0.10), inv.get("status", "known")


def _label(s: dict) -> str:
    flags = [f for f, on in (("KEV", s.get("kev")), ("emergency", s.get("emergency")),
                             ("PoC public", s.get("poc_public")), ("embargo broke", s.get("embargo_broken")))
             if on]
    if s.get("exploitation") in ("attempts", "confirmed") and not s.get("kev"):
        flags.append(f"exploitation {s['exploitation']}")
    head = s.get("cve") or (s.get("title") or "signal")[:60]
    return head + (f" ({', '.join(flags)})" if flags else "")


def score_all(components: dict[str, dict], signals: list[dict], inventory: dict[str, dict],
              cfg: dict, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    w = cfg["weights"]
    hl = cfg["half_life_days"]
    bonus = cfg["bonuses"]
    lv = cfg["exploit_levels"]
    wsum = sum(w.values())
    max_age = cfg.get("max_signal_age_days", 180)

    activity = {cid: 0.0 for cid in components}
    spill = {cid: 0.0 for cid in components}
    exploit = {cid: 0.0 for cid in components}
    drivers: dict[str, list[tuple[float, dict]]] = {cid: [] for cid in components}
    surface_heat: dict[str, float] = {}

    surf_index: dict[str, set[str]] = {}
    for cid, c in components.items():
        for s in c.get("surfaces") or []:
            surf_index.setdefault(s, set()).add(cid)

    for s in signals:
        cid = s["component_id"]
        if cid not in components:
            continue
        age = (now - _parse(s["observed_at"])).total_seconds() / 86400
        if age > max_age:
            continue
        conf = float(s.get("confidence", 0.7))

        a = sev_weight(s.get("cvss"))
        a += bonus["emergency_release"] * bool(s.get("emergency"))
        a += bonus["poc_public"] * bool(s.get("poc_public"))
        a += bonus["embargo_broken"] * bool(s.get("embargo_broken"))
        a *= decay(age, hl["activity"]) * conf
        activity[cid] += a

        level = 1.0 if s.get("kev") else lv.get(s.get("exploitation") or "unknown", 0.0)
        if s.get("epss") is not None:
            level = max(level, cfg["epss_weight"] * float(s["epss"]))
        e = level * decay(age, hl["exploit"])
        exploit[cid] = max(exploit[cid], e)
        drivers[cid].append((a + e, {"kind": "direct", "label": _label(s), "url": s.get("url"),
                                     "origin": s.get("origin"), "observed_at": s["observed_at"],
                                     "evidence": s.get("evidence")}))

        surfaces = [x for x in s.get("surfaces") or [] if x in surf_index]
        if surfaces:
            push = cfg["spillover_per_signal"] * decay(age, hl["spillover"]) * conf * (0.5 + 0.5 * sev_weight(s.get("cvss")))
            for surf in surfaces:
                surface_heat[surf] = surface_heat.get(surf, 0.0) + push
            for other in components:
                if other == cid:
                    continue
                shared = set(surfaces) & set(components[other].get("surfaces") or [])
                if not shared:
                    continue
                p = push * len(shared) / len(surfaces)
                spill[other] += p
                drivers[other].append((p, {
                    "kind": "spillover",
                    "label": f"{', '.join(sorted(shared))} broke in {components[cid]['name']} ({s.get('cve') or 'no CVE'})",
                    "url": s.get("url"), "origin": s.get("origin"), "observed_at": s["observed_at"],
                    "evidence": None}))

    results = []
    for cid, c in components.items():
        terms = {
            "prior": prior_score(c.get("priors")),
            "activity": saturate(activity[cid]),
            "spillover": saturate(spill[cid]),
            "exploit": min(exploit[cid], 1.0),
        }
        points = {k: round(100 * w[k] * v / wsum, 1) for k, v in terms.items()}
        likelihood = round(sum(points.values()), 1)
        exp, status = exposure_score(inventory.get(cid), cfg)
        floor = cfg["exposure"]["floor"]
        factor = floor + (1 - floor) * exp
        priority = round(likelihood * factor, 1)
        top = [d for _, d in sorted(drivers[cid], key=lambda x: -x[0])[:5]]
        results.append({
            "component_id": cid, "name": c["name"], "ecosystem": c.get("ecosystem"),
            "likelihood": likelihood, "exposure": round(exp, 3), "exposure_status": status,
            "priority": priority, "points": points, "drivers": top,
            "exposure_factor": round(factor, 3),
            "term_max": {k: round(100 * w[k] / wsum, 1) for k in terms},
            "surfaces": c.get("surfaces") or [],
            "inventory": inventory.get(cid) or {"status": "unknown"},
            "signal_count": sum(1 for d in drivers[cid] if d[1]["kind"] == "direct"),
        })
    results.sort(key=lambda r: -r["priority"])
    for i, r in enumerate(results, 1):
        r["rank"] = i
    return results


def surface_heat(signals: list[dict], cfg: dict, now: datetime | None = None,
                 window_days: int = 30) -> dict[str, float]:
    """Decayed heat per attack surface, for the spillover grid."""
    now = now or datetime.now(timezone.utc)
    heat: dict[str, float] = {}
    for s in signals:
        age = (now - _parse(s["observed_at"])).total_seconds() / 86400
        if age > window_days:
            continue
        for surf in s.get("surfaces") or []:
            heat[surf] = heat.get(surf, 0.0) + decay(age, cfg["half_life_days"]["spillover"]) * sev_weight(s.get("cvss"))
    return heat
