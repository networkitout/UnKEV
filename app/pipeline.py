"""Job orchestration. Each job records a run row so feed health is visible."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from . import llm
from .collectors.epss import collect_epss
from .collectors.kev import collect_kev
from .collectors.nvd import collect_nvd
from .collectors.osv import collect_osv
from .collectors.rss import collect_rss
from .config import get_settings, load_yaml
from .db import DB, iso, utcnow
from .evaluation import evaluate_snapshot
from .inventory import sync_inventory
from .matching import Matcher
from .scoring import score_all, validate_config

log = logging.getLogger("unkev")
_lock = asyncio.Lock()


class Ctx:
    def __init__(self):
        self.settings = get_settings()
        self.db = DB(self.settings.db_path)
        self.components = load_yaml("components.yaml")
        self.feeds = load_yaml("feeds.yaml")
        self.scoring = load_yaml("scoring.yaml")
        validate_config(self.scoring)
        self.inventory_cfg = load_yaml("inventory.yaml")
        self.appliances = load_yaml("appliances.yaml").get("appliances") or []
        self.packages = load_yaml("packages.yaml").get("packages") or []
        self.matcher = Matcher(self.components, self.feeds.get("prefilter_terms") or [])

    def client(self, **kw):
        import httpx  # lazy so pure modules and scripts import without it
        return httpx.AsyncClient(timeout=self.settings.http_timeout, follow_redirects=True,
                                 headers={"User-Agent": self.settings.user_agent}, **kw)


async def _job(ctx: Ctx, name: str, coro):
    rid = ctx.db.start_run(name)
    try:
        detail = await coro
        ctx.db.finish_run(rid, True, json.dumps(detail, default=str))
        return detail
    except Exception as e:
        log.exception("job %s failed", name)
        ctx.db.finish_run(rid, False, f"{type(e).__name__}: {e}")
        return None


async def job_collect(ctx: Ctx):
    f = ctx.feeds
    async with ctx.client() as c:
        if f.get("kev", {}).get("enabled"):
            await _job(ctx, "kev", collect_kev(c, ctx.db, ctx.matcher, f["kev"]))
        if f.get("nvd", {}).get("enabled"):
            await _job(ctx, "nvd", collect_nvd(c, ctx.db, ctx.matcher, f["nvd"], ctx.settings.nvd_api_key))
        if f.get("osv", {}).get("enabled"):
            await _job(ctx, "osv", collect_osv(c, ctx.db, f["osv"], ctx.packages, ctx.components))
        if f.get("rss", {}).get("enabled"):
            await _job(ctx, "rss", collect_rss(c, ctx.db, ctx.matcher, f["rss"]))


def _catalog_edge(components: dict, host: str, upstream: str) -> bool:
    return any(e.get("component") == upstream for e in (components.get(host) or {}).get("embeds") or [])


def apply_findings(ctx: Ctx, rows_by_ref: dict, findings: list[dict]) -> dict:
    stats = {"relevant": 0, "signals": 0, "tagged": 0, "edges": 0}
    done = set()
    for f in findings:
        row = rows_by_ref[f["item_ref"]]
        done.add(f["item_ref"])
        for name in f["unmapped_names"]:
            ctx.db.note_unmapped(name, "llm", row["url"])
        if not f["relevant"]:
            ctx.db.mark_intel(row["id"], "extracted")
            continue
        stats["relevant"] += 1
        # Dependency edges are proposals only; a human adds them to components.yaml.
        for host in f["components"]:
            for up in f.get("upstream_components") or []:
                if up == host or _catalog_edge(ctx.components, host, up):
                    continue
                ctx.db.note_embed_candidate(host, up, row["url"], f.get("evidence"))
                stats["edges"] += 1
        if row["source"] in ("nvd", "osv"):
            # Deterministic signals already exist; Claude only adds surface tags.
            stats["tagged"] += ctx.db.tag_signals_for_intel(row["id"], f["surfaces"], f["confidence"], f["components"])
        else:
            observed = row["published_at"] or iso(utcnow())
            for cid in f["components"]:
                for cve in (f["cves"] or [""]):
                    ctx.db.add_signal(
                        intel_id=row["id"], component_id=cid, origin="llm", cve=cve,
                        surfaces=f["surfaces"], exploitation=f["exploitation"],
                        emergency=f["emergency_release"], poc_public=f["poc_public"],
                        embargo_broken=f["embargo_broken"], cvss=f["cvss"],
                        confidence=f["confidence"], observed_at=observed, title=row["title"],
                        url=row["url"], evidence=f["evidence"])
                    stats["signals"] += 1
        ctx.db.mark_intel(row["id"], "extracted")
    for ref, row in rows_by_ref.items():
        if ref not in done:
            ctx.db.mark_intel(row["id"], "failed", "no finding returned")
    return stats


def budget_exhausted(ctx: Ctx) -> bool:
    """True when today's Claude usage has hit the daily cap. A cap of 0 means no cap."""
    cap = ctx.settings.llm_daily_token_budget
    return bool(cap) and ctx.db.usage_today() >= cap


async def job_extract(ctx: Ctx, max_batches: int = 10):
    s = ctx.settings
    if not s.anthropic_api_key:
        return {"skipped": "ANTHROPIC_API_KEY not set"}
    total = {"batches": 0, "relevant": 0, "signals": 0, "tagged": 0, "edges": 0, "tokens": 0}
    async with ctx.client() as c:
        for _ in range(max_batches):
            if budget_exhausted(ctx):
                total["stopped"] = "daily token budget reached"
                break
            rows = ctx.db.pending_intel(s.llm_batch_size)
            if not rows:
                break
            by_ref = {f"d{i}": r for i, r in enumerate(rows)}
            items = [{"ref": ref, "source": r["source"], "title": r["title"] or "", "text": r["raw_text"] or ""}
                     for ref, r in by_ref.items()]
            try:
                findings, tin, tout = await llm.extract(c, s, items, ctx.components)
            except Exception as e:
                for r in rows:
                    ctx.db.mark_intel(r["id"], "failed", str(e)[:300])
                total["error"] = str(e)[:300]
                break
            ctx.db.add_usage(tin, tout)
            st = apply_findings(ctx, by_ref, findings)
            total["batches"] += 1
            total["tokens"] += tin + tout
            for k in ("relevant", "signals", "tagged", "edges"):
                total[k] += st[k]
    return total


async def job_enrich(ctx: Ctx):
    async with ctx.client() as c:
        return await collect_epss(c, ctx.db, ctx.feeds["epss"])


async def job_inventory(ctx: Ctx):
    verify = ctx.inventory_cfg.get("verify_tls", True)
    async with ctx.client(verify=verify) as c:
        inv, stats = await sync_inventory(c, ctx.inventory_cfg, ctx.matcher, ctx.components, ctx.appliances)
    ctx.db.replace_inventory(inv)
    return stats


def history_days(db: DB) -> int | None:
    """Days of NVD history the signal store covers, from kv nvd_history_from
    (written by scripts/backfill_nvd.py and by the first NVD run). None until then."""
    v = db.get_kv("nvd_history_from")
    if not v:
        return None
    dt = datetime.fromisoformat(v)
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return (utcnow() - dt).days


def job_score_sync(ctx: Ctx) -> dict:
    since = iso(utcnow() - timedelta(days=ctx.scoring.get("max_signal_age_days", 180)))
    hist = history_days(ctx.db)
    results = score_all(ctx.components, ctx.db.signals_since(since), ctx.db.inventory(), ctx.scoring,
                        history_days=hist)
    ctx.db.write_snapshot(iso(utcnow()), results)
    return {"components": len(results), "history_days": hist,
            "baseline_ready": bool(results and results[0]["baseline_ready"]),
            "top": [r["component_id"] for r in results[:5]]}


async def job_score(ctx: Ctx):
    return job_score_sync(ctx)


def job_evaluate_sync(ctx: Ctx) -> dict:
    """Judge every daily snapshot whose horizon has elapsed and isn't judged yet."""
    cfg = ctx.scoring["evaluation"]
    horizon = int(cfg["horizon_days"])
    due = ctx.db.daily_snapshots(iso(utcnow() - timedelta(days=horizon)))
    done = ctx.db.evaluated_ts("live")
    pending = [ts for ts in due if ts not in done]
    if not pending:
        return {"evaluated": 0, "total": len(due)}
    signals = ctx.db.signals_until(iso(utcnow()))
    n = 0
    for ts in pending:
        rows = ctx.db.snapshot_rows(ts)
        if not rows:
            continue
        ctx.db.write_eval(evaluate_snapshot(rows, signals, datetime.fromisoformat(ts), cfg, ctx.components), "live")
        n += 1
    return {"evaluated": n, "total": len(due)}


async def job_evaluate(ctx: Ctx):
    return job_evaluate_sync(ctx)


async def job_brief(ctx: Ctx):
    s = ctx.settings
    if not s.anthropic_api_key:
        return {"skipped": "ANTHROPIC_API_KEY not set"}
    if budget_exhausted(ctx):
        return {"skipped": "daily token budget reached"}
    _, rows = ctx.db.latest_snapshot()
    if not rows:
        return {"skipped": "no scores yet"}
    async with ctx.client() as c:
        text, tin, tout = await llm.brief(c, s, rows)
    ctx.db.add_usage(tin, tout)
    ctx.db.save_brief(s.brief_model, text, tin, tout)
    return {"words": len(text.split()), "tokens": tin + tout}


JOBS = {
    "collect": job_collect, "extract": job_extract, "enrich": job_enrich,
    "inventory": job_inventory, "score": job_score, "evaluate": job_evaluate, "brief": job_brief,
}


async def run(job: str) -> bool:
    """Run one job or 'all'. Returns False if another run holds the lock."""
    if _lock.locked():
        return False
    async with _lock:
        ctx = Ctx()
        order = ["collect", "extract", "enrich", "inventory", "score", "evaluate", "brief"] if job == "all" else [job]
        for name in order:
            if name in ("collect",):
                await JOBS[name](ctx)          # records its own sub-runs
            else:
                await _job(ctx, name, JOBS[name](ctx))
    return True
