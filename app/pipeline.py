"""Job orchestration. Each job records a run row so feed health is visible."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import timedelta

from . import llm
from .collectors.epss import collect_epss
from .collectors.kev import collect_kev
from .collectors.nvd import collect_nvd
from .collectors.rss import collect_rss
from .config import get_settings, load_yaml
from .db import DB, iso, utcnow
from .inventory import sync_inventory
from .matching import Matcher
from .scoring import score_all

log = logging.getLogger("unkev")
_lock = asyncio.Lock()


class Ctx:
    def __init__(self):
        self.settings = get_settings()
        self.db = DB(self.settings.db_path)
        self.components = load_yaml("components.yaml")
        self.feeds = load_yaml("feeds.yaml")
        self.scoring = load_yaml("scoring.yaml")
        self.inventory_cfg = load_yaml("inventory.yaml")
        self.appliances = load_yaml("appliances.yaml").get("appliances") or []
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
        if f.get("rss", {}).get("enabled"):
            await _job(ctx, "rss", collect_rss(c, ctx.db, ctx.matcher, f["rss"]))


def apply_findings(ctx: Ctx, rows_by_ref: dict, findings: list[dict]) -> dict:
    stats = {"relevant": 0, "signals": 0, "tagged": 0}
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
        if row["source"] == "nvd":
            # Deterministic signals already exist; Claude only adds surface tags.
            stats["tagged"] += ctx.db.tag_signals_for_intel(row["id"], f["surfaces"], f["confidence"])
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


async def job_extract(ctx: Ctx, max_batches: int = 10):
    s = ctx.settings
    if not s.anthropic_api_key:
        return {"skipped": "ANTHROPIC_API_KEY not set"}
    total = {"batches": 0, "relevant": 0, "signals": 0, "tagged": 0, "tokens": 0}
    async with ctx.client() as c:
        for _ in range(max_batches):
            if ctx.db.usage_today() >= s.llm_daily_token_budget:
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
            for k in ("relevant", "signals", "tagged"):
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


def job_score_sync(ctx: Ctx) -> dict:
    since = iso(utcnow() - timedelta(days=ctx.scoring.get("max_signal_age_days", 180)))
    results = score_all(ctx.components, ctx.db.signals_since(since), ctx.db.inventory(), ctx.scoring)
    ctx.db.write_snapshot(iso(utcnow()), results)
    return {"components": len(results), "top": [r["component_id"] for r in results[:5]]}


async def job_score(ctx: Ctx):
    return job_score_sync(ctx)


async def job_brief(ctx: Ctx):
    s = ctx.settings
    if not s.anthropic_api_key:
        return {"skipped": "ANTHROPIC_API_KEY not set"}
    if ctx.db.usage_today() >= s.llm_daily_token_budget:
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
    "inventory": job_inventory, "score": job_score, "brief": job_brief,
}


async def run(job: str) -> bool:
    """Run one job or 'all'. Returns False if another run holds the lock."""
    if _lock.locked():
        return False
    async with _lock:
        ctx = Ctx()
        order = ["collect", "extract", "enrich", "inventory", "score", "brief"] if job == "all" else [job]
        for name in order:
            if name in ("collect",):
                await JOBS[name](ctx)          # records its own sub-runs
            else:
                await _job(ctx, name, JOBS[name](ctx))
    return True
