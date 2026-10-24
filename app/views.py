"""Builds template context from the DB. No FastAPI imports, so the static
preview script can reuse it."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from markupsafe import Markup, escape

from .db import iso, utcnow
from .scoring import surface_heat
from .vocab import SURFACES


_TAG = re.compile(r"\[(verified|reported)(?::\s*([a-z0-9 _-]{1,24}))?\]|\[(inferred)\]", re.I)


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


def register_filters(env) -> None:
    env.filters["brief_html"] = brief_html
    env.filters["summ"] = summ
    env.globals["origin_label"] = origin_label


ORIGINS = {"kev": "CISA KEV", "nvd": "NVD", "llm": "news, extracted by Claude", "seed": "seed data"}


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
    return {"surfaces": [{"id": s, "desc": SURFACES.get(s, ""), "heat": round(heat[s] / hmax, 2)} for s in surfaces],
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
        "ts": ts, "ts_ago": ago(ts), "rows": rows, "sel": sel,
        "brief": dict(brief) if brief else None,
        "brief_ago": ago(brief["ts"]) if brief else None,
        "grid": spill_grid(ctx, rows, signals),
        "unmapped": [dict(u) for u in ctx.db.top_unmapped(12)],
        "embed_candidates": [dict(e) for e in ctx.db.embed_candidates(12)],
        "runs": runs,
        "tokens_today": ctx.db.usage_today(),
        "token_budget": ctx.settings.llm_daily_token_budget,
        "signals_30d": len(signals),
        "unknown_top": [r for r in unknown if r["rank"] <= 15],
        "ago": ago,
    }
