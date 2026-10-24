"""Builds template context from the DB. No FastAPI imports, so the static
preview script can reuse it."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from markupsafe import Markup, escape

from .db import iso, utcnow
from .evaluation import summarize
from .scoring import surface_heat
from .vocab import SURFACE_LABELS, SURFACES


_TAG = re.compile(r"\[(verified|vendor|reported)(?::\s*([a-z0-9 _.&/-]{1,32}))?\]|\[(inferred)\]", re.I)


def brief_html(text: str | None) -> Markup:
    """Escape Claude's text FIRST, then wrap known markers. Never trust model output as HTML."""
    safe = str(escape(text or ""))

    def sub(m: re.Match) -> str:
        kind = (m.group(1) or m.group(3)).lower()
        label = kind + (f": {m.group(2)}" if m.group(2) else "")
        return f'<span class="tag {kind}">{label}</span>'
    return Markup(_TAG.sub(sub, safe))


def summ(detail: str | None, limit: int = 110) -> str:
    """Flatten a run's JSON detail into 'key value' pairs for the health table."""
    try:
        d = json.loads(detail or "")
    except ValueError:
        return (detail or "")[:limit]
    if not isinstance(d, dict):
        return str(d)[:limit]
    parts = []
    for k, v in d.items():
        if isinstance(v, dict):
            v = " ".join(f"{a} {b}" for a, b in v.items() if not isinstance(b, (dict, list)))
        elif isinstance(v, list):
            v = f"[{len(v)}]"
        parts.append(f"{k} {v}")
    return ", ".join(parts)[:limit]


def brief_blocks(text: str | None) -> list[tuple[str, object]]:
    """Split the brief into paragraphs and bullet lists for readable rendering.
    Every piece goes through brief_html, so it is escaped before any markup."""
    blocks: list[tuple[str, object]] = []
    for para in re.split(r"\n\s*\n", (text or "").strip()):
        lines = [l.rstrip() for l in para.splitlines() if l.strip()]
        if not lines:
            continue
        if all(re.match(r"^\s*(?:[-•*]|\d+[.)])\s+", l) for l in lines):
            blocks.append(("ul", [brief_html(re.sub(r"^\s*(?:[-•*]|\d+[.)])\s+", "", l)) for l in lines]))
        else:
            blocks.append(("p", brief_html(" ".join(l.strip() for l in lines))))
    return blocks


def register_filters(env) -> None:
    env.filters["brief_html"] = brief_html
    env.filters["brief_blocks"] = brief_blocks
    env.filters["summ"] = summ
    env.globals["origin_label"] = origin_label


ORIGINS = {"kev": "CISA KEV", "nvd": "NVD", "osv": "OSV", "llm": "news, extracted by Claude", "seed": "seed data"}


def origin_label(o: str | None) -> str:
    return ORIGINS.get(o or "", o or "")


def band(priority: float) -> str:
    if priority >= 60:
        return "crit"
    if priority >= 45:
        return "high"
    if priority >= 30:
        return "med"
    return "low"


BAND_WORDS = {"crit": "Critical", "high": "High", "med": "Medium", "low": "Low"}


def shorten(text: str, limit: int = 80) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:.")
    return cut + "…"


def why_now(r: dict) -> str:
    """One plain-language sentence for the top driver, for readers who don't
    know the model's terms. Falls back to the raw label on old snapshots."""
    d = r["drivers"][0] if r.get("drivers") else None
    if not d:
        reason = "No recent activity; this is structural risk only"
    elif d["kind"] == "inherited" and "source" in d:
        reason = f"Bundles {d['source']}, which just had a serious flaw"
        if d.get("cve"):
            reason += f" ({d['cve']})"
        if not d.get("confirmed"):
            reason += ", vendor impact not yet confirmed"
    elif d["kind"] == "spillover" and "source" in d:
        reason = f"The same kind of flaw just hit {d['source']} ({', '.join(d.get('surfaces') or [])})"
    elif d["kind"] == "direct" and "flags" in d:
        f, cve = d["flags"], d.get("cve")
        subject = cve or shorten(d.get("title") or "a reported flaw")
        if f.get("kev"):
            reason = f"Exploited in the wild, per CISA KEV: {subject}"
        elif d.get("exploitation") == "confirmed":
            reason = f"Exploitation confirmed in the wild: {subject}"
        elif d.get("exploitation") == "attempts":
            reason = f"Exploitation attempts reported: {subject}"
        elif f.get("emergency"):
            reason = f"Emergency patch released: {subject}"
        elif f.get("poc_public"):
            reason = f"Public exploit code available: {subject}"
        else:
            reason = f"New serious flaw: {subject}"
    else:
        reason = d["label"]
    ratio = r.get("activity_ratio")
    if ratio is not None and ratio >= 1.5:
        reason += f". {ratio:.1f}× its usual rate of new flaws"
    return reason


def exposure_phrase(r: dict) -> tuple[str, str]:
    """(short, long) description of what the estate runs."""
    inv, st = r.get("inventory") or {}, r.get("exposure_status")
    if st == "unknown":
        return "Unknown", "Not visible in inventory"
    if st == "none":
        return "Not found", "Inventory shows none"
    hosts, ext = int(inv.get("hosts", 0)), int(inv.get("internet_facing", 0))
    short = f"{hosts} host{'s' if hosts != 1 else ''}"
    long = short + (f", {ext} internet-facing" if ext else "")
    if st == "declared":
        long += " (declared, not verified)"
    return short, long


def estate_phrase(e: dict, by_id: dict[str, dict]) -> tuple[str, str]:
    """For an exploited item: (class, text) answering 'does this touch us?'"""
    comps = [by_id[c] for c in e.get("components") or [] if c in by_id]
    if not comps:
        return "na", "Not in our catalog"
    known = [c for c in comps if c["exposure_status"] in ("known", "declared")]
    if known:
        hosts = sum(int(c["inventory"].get("hosts", 0)) for c in known)
        return "yes", f"Yes, {hosts} host{'s' if hosts != 1 else ''}"
    if all(c["exposure_status"] == "none" for c in comps):
        return "no", "No"
    return "unknown", "Unknown"


def ago(ts: str | None) -> str:
    if not ts:
        return "never"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ts
    s = (utcnow() - dt).total_seconds()
    if s < 90:
        return "just now"
    if s < 5400:
        return f"{int(s // 60)}m ago"
    if s < 172800:
        return f"{int(s // 3600)}h ago"
    return f"{int(s // 86400)}d ago"


def spill_grid(ctx, rows: list[dict], signals: list[dict], max_surfaces: int = 8, max_cols: int = 14) -> dict:
    heat = surface_heat(signals, ctx.scoring)
    surfaces = [s for s, _ in sorted(heat.items(), key=lambda x: -x[1])[:max_surfaces]]
    if not surfaces:
        return {"surfaces": [], "cols": [], "cells": {}}
    hmax = max(heat[s] for s in surfaces) or 1.0
    origin = {(s["component_id"], surf) for s in signals for surf in s.get("surfaces") or []}
    ranked = sorted((r for r in rows if set(r["surfaces"]) & set(surfaces)),
                    key=lambda r: -(r["points"]["spillover"] + r["points"]["activity"]))
    cols = ranked[:max_cols]
    cells = {}
    for surf in surfaces:
        for r in cols:
            if surf in r["surfaces"]:
                cells[(surf, r["component_id"])] = {
                    "heat": round(heat[surf] / hmax, 2),
                    "origin": (r["component_id"], surf) in origin,
                }
    return {"surfaces": [{"id": s, "label": SURFACE_LABELS.get(s, s), "desc": SURFACES.get(s, ""),
                          "heat": round(heat[s] / hmax, 2)} for s in surfaces],
            "cols": cols, "cells": cells}


def dashboard_context(ctx, selected: str | None = None) -> dict:
    ts, rows = ctx.db.latest_snapshot()
    prev = ctx.db.snapshot_before(iso(utcnow() - timedelta(days=7)))
    for r in rows:
        r["band"] = band(r["priority"])
        p = prev.get(r["component_id"])
        r["delta"] = None if p is None else round(r["priority"] - p, 1)
    since = iso(utcnow() - timedelta(days=30))
    signals = ctx.db.signals_since(since)
    brief = ctx.db.latest_brief()
    sel = next((r for r in rows if r["component_id"] == selected), rows[0] if rows else None)
    runs = [dict(r) for r in ctx.db.last_runs()]
    for r in runs:
        try:
            r["detail_obj"] = json.loads(r["detail"]) if r["detail"] and r["detail"].startswith("{") else None
        except ValueError:
            r["detail_obj"] = None
    unknown = [r for r in rows if r["exposure_status"] == "unknown"]
    exploited = ctx.db.exploited_recent(30)
    for e in exploited:
        e["component_names"] = [ctx.components.get(c, {}).get("name", c) for c in e["components"]]
    return {
        "exploited": exploited,
        "record": track_record(ctx),
        "evals": ctx.db.evals(since_iso=iso(utcnow() - timedelta(days=60)))[:30],
        "ts": ts, "ts_ago": ago(ts), "rows": rows, "sel": sel,
        "brief": dict(brief) if brief else None,
        "brief_ago": ago(brief["ts"]) if brief else None,
        "grid": spill_grid(ctx, rows, signals),
        "unmapped": [dict(u) for u in ctx.db.top_unmapped(12)],
        "embed_candidates": [dict(e) for e in ctx.db.embed_candidates(12)],
        "runs": runs,
        "signals_30d": len(signals),
        "unknown_top": [r for r in unknown if r["rank"] <= 15],
        "ago": ago,
    }


def pct(v: float | None) -> str:
    return "n/a" if v is None else f"{round(100 * v)}%"


def track_record(ctx, days: int = 90) -> dict:
    """How the forecast has fared over the last N judged days, in plain terms."""
    evals = ctx.db.evals(since_iso=iso(utcnow() - timedelta(days=days + 30)))
    s = summarize(evals)
    if not s.get("n"):
        return {"n": 0}
    k = evals[0].get("k", 10)
    out = {"n": s["n"], "first": s["first"], "last": s["last"], "k": k,
           "replayed": "replay" in s["sources"], "live_days": sum(1 for e in evals if e["source"] == "live"),
           "profiles": {}}
    for name, p in s["profiles"].items():
        r, c = p["rankings"], p["cohorts"]
        out["profiles"][name] = {
            "events": p["distinct_events"],
            "model": pct(r["model"]["hit_at_k"]), "recency": pct(r["recency"]["hit_at_k"]),
            "chance": pct(r["chance"]["hit_at_k"]),
            "lift": p["lift_vs_recency"],
            "lift_word": ("beats" if p["lift_vs_recency"] > 0.02 else "trails" if p["lift_vs_recency"] < -0.02 else "matches")
                         if p["lift_vs_recency"] is not None else None,
            "predictive": c["predictive"], "quiet": c["quiet"], "active": c["active"],
            "predictive_pct": pct(c["predictive"]["rate"]), "quiet_pct": pct(c["quiet"]["rate"]),
        }
    return out


def exec_context(ctx, top_n: int = 10) -> dict:
    """Leadership view: posture, summary, top risks in plain language, what is
    exploited and whether it touches us, blind spots, movers."""
    ts, rows = ctx.db.latest_snapshot()
    prev = ctx.db.snapshot_before(iso(utcnow() - timedelta(days=7)))
    by_id = {r["component_id"]: r for r in rows}
    for r in rows:
        r["band"] = band(r["priority"])
        r["band_word"] = BAND_WORDS[r["band"]]
        p = prev.get(r["component_id"])
        r["delta"] = None if p is None else round(r["priority"] - p, 1)
        r["why"] = why_now(r)
        r["exposure_short"], r["exposure_long"] = exposure_phrase(r)
    exploited = ctx.db.exploited_recent(30)
    for e in exploited:
        e["component_names"] = [ctx.components.get(c, {}).get("name", c) for c in e["components"]]
        e["estate_class"], e["estate"] = estate_phrase(e, by_id)
    top = rows[:top_n]
    watch = [r for r in rows if r["rank"] <= 15]
    moved = [r for r in rows if r["delta"] is not None]
    brief = ctx.db.latest_brief()
    signals = ctx.db.signals_since(iso(utcnow() - timedelta(days=30)))
    return {
        "ts": ts, "ts_ago": ago(ts),
        "grid": spill_grid(ctx, rows, signals, max_surfaces=8, max_cols=12),
        "record": track_record(ctx),
        "kpis": {
            "high": sum(1 for r in rows if r["band"] in ("crit", "high")),
            "crit": sum(1 for r in rows if r["band"] == "crit"),
            "exploited": len(exploited),
            "exploited_us": sum(1 for e in exploited if e["estate_class"] == "yes"),
            "rising": sum(1 for r in moved if r["delta"] > 5),
            "blind": sum(1 for r in watch if r["exposure_status"] == "unknown"),
            "watch": len(watch),
        },
        "brief": dict(brief) if brief else None,
        "brief_ago": ago(brief["ts"]) if brief else None,
        "top": top,
        "exploited": exploited[:10], "exploited_total": len(exploited),
        "blind": [r for r in watch if r["exposure_status"] == "unknown"],
        "up": sorted((r for r in moved if r["delta"] > 0.5), key=lambda r: -r["delta"])[:5],
        "down": sorted((r for r in moved if r["delta"] < -0.5), key=lambda r: r["delta"])[:5],
        "baseline_ready": bool(rows and rows[0].get("baseline_ready")),
    }
