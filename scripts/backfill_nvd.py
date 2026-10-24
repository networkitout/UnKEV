"""Backfill NVD history so the activity baseline can warm up.

    python -m scripts.backfill_nvd --days 180

Walks backward from now in windows of at most MAX_WINDOW_DAYS, using NVD's
publication dates so each window yields the CVEs published in it. Reuses the
collector's page loop, so matching, queueing for Claude surface tagging and
the "not in catalog" list behave exactly as in a normal run. Signals upsert on
their unique key, so re-running is safe.

Writes kv nvd_history_from to the earliest window start (never later than an
existing value). job_score reads it to decide whether the baseline is ready.

Mind the Claude budget: matched CVEs at or above feeds.yaml llm_tag_min_cvss
are queued for surface tagging. Fresh items are processed first, and the
daily token cap still applies, but a long backfill can keep the extractor
busy for days.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone

from app.collectors.nvd import MAX_WINDOW_DAYS, fetch_nvd_window, nvd_pause
from app.db import utcnow
from app.pipeline import Ctx


async def backfill(days: int) -> None:
    ctx = Ctx()
    cfg = ctx.feeds["nvd"]
    key = ctx.settings.nvd_api_key
    if not key:
        print("NVD_API_KEY is not set; running at the unauthenticated rate limit, this will be slow")
    end = utcnow().replace(microsecond=0)
    earliest = end - timedelta(days=days)
    grand = {"seen": 0, "matched": 0, "queued": 0, "unmapped": 0}
    async with ctx.client() as c:
        cur_end = end
        while cur_end > earliest:
            cur_start = max(earliest, cur_end - timedelta(days=MAX_WINDOW_DAYS))
            t = await fetch_nvd_window(c, ctx.db, ctx.matcher, cfg, key, cur_start, cur_end, date_field="pub")
            print(f"{cur_start:%Y-%m-%d} .. {cur_end:%Y-%m-%d}  seen {t['seen']:>5}  matched {t['matched']:>4}  "
                  f"queued {t['queued']:>4}  unmapped {t['unmapped']:>4}")
            for k in grand:
                grand[k] += t[k]
            cur_end = cur_start
            if cur_end > earliest:
                await asyncio.sleep(nvd_pause(key))
    prev = ctx.db.get_kv("nvd_history_from")
    prev_dt = datetime.fromisoformat(prev) if prev else None
    if prev_dt and not prev_dt.tzinfo:
        prev_dt = prev_dt.replace(tzinfo=timezone.utc)
    if not prev_dt or earliest < prev_dt:
        ctx.db.set_kv("nvd_history_from", earliest.isoformat())
    print(f"\ntotal  seen {grand['seen']}  matched {grand['matched']}  queued {grand['queued']}  "
          f"unmapped {grand['unmapped']}")
    print(f"nvd_history_from = {ctx.db.get_kv('nvd_history_from')}")
    need = ctx.scoring["activity_baseline"]["min_history_days"]
    print(f"baseline is {'ready' if days >= need else f'not ready: needs {need} days'}; rescore to apply")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days", type=int, default=180, help="how far back to fetch (default 180)")
    a = ap.parse_args()
    if a.days <= 0:
        ap.error("--days must be positive")
    asyncio.run(backfill(a.days))


if __name__ == "__main__":
    main()
