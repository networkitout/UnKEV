"""Scheduler loop. Run as its own process (python -m app.worker) so multiple
uvicorn workers don't each start a scheduler."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from .config import get_settings
from .db import DB, iso, utcnow
from .pipeline import run

log = logging.getLogger("unkev.worker")


def mark_next_cycle(db: DB, minutes: int) -> str:
    """Persist when the next cycle is due, as kv `next_run_at`. The web process
    reads it from the shared store even when the worker runs separately."""
    due = iso(utcnow() + timedelta(minutes=minutes))
    db.set_kv("next_run_at", due)
    log.info("next cycle at %s", due)
    return due


def brief_is_stale(db: DB, hours: int = 20) -> bool:
    b = db.latest_brief()
    return not b or datetime.fromisoformat(b["ts"]) < utcnow() - timedelta(hours=hours)


async def loop_forever():
    s = get_settings()
    db = DB(s.db_path)
    while True:
        for job in ("collect", "extract", "enrich", "inventory", "score", "evaluate"):
            await run(job)
        if brief_is_stale(db):
            await run("brief")
        log.info("cycle complete; sleeping %s min", s.interval_minutes)
        mark_next_cycle(db, s.interval_minutes)
        await asyncio.sleep(s.interval_minutes * 60)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(loop_forever())
