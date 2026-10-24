"""CISA KEV. Authoritative for exploitation; mapped deterministically."""
from __future__ import annotations

from datetime import timedelta

from ..db import DB, item_id, utcnow


def process_kev(data: dict, db: DB, matcher, lookback_days: int) -> dict:
    cutoff = (utcnow() - timedelta(days=lookback_days)).date().isoformat()
    stats = {"seen": 0, "mapped": 0, "unmapped": 0}
    for v in data.get("vulnerabilities", []):
        added = v.get("dateAdded", "")
        if added < cutoff:
            continue
        stats["seen"] += 1
        cve = v.get("cveID", "")
        vendor, product = v.get("vendorProject", ""), v.get("product", "")
        iid = item_id("kev", cve)
        title = f"{vendor} {product}: {v.get('vulnerabilityName', '')}"
        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        db.upsert_intel(id=iid, source="kev", url=url, title=title, published_at=added,
                        raw_text=v.get("shortDescription"), status="extracted")
        comps = matcher.match_kev(vendor, product)
        if not comps:
            stats["unmapped"] += 1
            db.note_unmapped(f"{vendor} {product}", "kev", url)
            continue
        stats["mapped"] += 1
        for cid in comps:
            db.add_signal(intel_id=iid, component_id=cid, origin="kev", cve=cve, kev=True,
                          exploitation="confirmed", observed_at=f"{added}T00:00:00+00:00",
                          confidence=0.95, title=title, url=url,
                          evidence=(v.get("shortDescription") or "")[:300])
    return stats


async def collect_kev(client, db: DB, matcher, cfg: dict) -> dict:
    r = await client.get(cfg["url"])
    r.raise_for_status()
    return process_kev(r.json(), db, matcher, cfg.get("lookback_days", 120))
