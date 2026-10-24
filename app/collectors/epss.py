"""FIRST EPSS enrichment for CVEs already in signals.
API: GET https://api.first.org/data/v1/epss?cve=CVE-a,CVE-b  -> data[{cve, epss, percentile, date}]
(verify batch limits at https://www.first.org/epss/api)."""
from __future__ import annotations

from datetime import timedelta

from ..db import DB, iso, utcnow


async def collect_epss(client, db: DB, cfg: dict) -> dict:
    since = iso(utcnow() - timedelta(days=180))
    stale = (utcnow() - timedelta(hours=20)).date().isoformat()
    cves = db.cves_needing_epss(since, stale)
    n = cfg.get("batch_size", 50)
    updated = 0
    for i in range(0, len(cves), n):
        r = await client.get(cfg["url"], params={"cve": ",".join(cves[i:i + n])})
        r.raise_for_status()
        for row in r.json().get("data") or []:
            try:
                db.set_epss(row["cve"], float(row["epss"]), row.get("date") or stale)
                updated += 1
            except (KeyError, ValueError):
                continue
    return {"requested": len(cves), "updated": updated}
