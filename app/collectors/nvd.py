"""NVD CVE API 2.0, incremental by lastModified window.

With AI-driven discovery, CVE volume is high and NVD enrichment (CPE configs)
lags. So: match on CPE when present, fall back to description aliases, and
only send high-severity matches to Claude for surface tagging.

Verify against https://nvd.nist.gov/developers/vulnerabilities before relying
on it: date format, 120-day max window, resultsPerPage cap (2000), and rate
limits (roughly 5 req/30s without a key, 50 with).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from ..db import DB, iso, item_id, utcnow


def best_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def cpe_criteria(cve: dict) -> list[str]:
    out = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and m.get("criteria"):
                    out.append(m["criteria"])
    return out


def process_nvd_page(vulns: list[dict], db: DB, matcher, cfg: dict) -> dict:
    stats = {"seen": 0, "matched": 0, "queued": 0, "unmapped": 0}
    for wrap in vulns:
        cve = wrap.get("cve") or {}
        cid_str = cve.get("id", "")
        stats["seen"] += 1
        desc = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        cvss = best_cvss(cve.get("metrics") or {})
        crit = cpe_criteria(cve)
        comps = sorted({c for x in crit for c in matcher.match_cpe(x)})
        conf = 0.9
        if not comps:
            comps = matcher.match_text(desc)
            conf = 0.6
        url = f"https://nvd.nist.gov/vuln/detail/{cid_str}"
        published = cve.get("published") or iso(utcnow())
        if not published.endswith("+00:00") and "+" not in published[10:]:
            published = published.split(".")[0] + "+00:00"
        if not comps:
            if cvss is not None and cvss >= cfg.get("unmapped_min_cvss", 9.0):
                vp = {":".join(x.split(":")[3:5]) for x in crit}
                db.note_unmapped(", ".join(sorted(vp)) or desc[:80], "nvd", url)
                stats["unmapped"] += 1
            continue
        stats["matched"] += 1
        iid = item_id("nvd", cid_str)
        queue = cvss is not None and cvss >= cfg.get("llm_tag_min_cvss", 8.0)
        db.upsert_intel(id=iid, source="nvd", url=url, title=cid_str, published_at=published,
                        raw_text=desc, status="new" if queue else "extracted")
        stats["queued"] += int(queue)
        for c in comps:
            db.add_signal(intel_id=iid, component_id=c, origin="nvd", cve=cid_str, cvss=cvss,
                          exploitation="unknown", observed_at=published, confidence=conf,
                          title=cid_str, url=url, evidence=desc[:300])
    return stats


# TODO(verify) NVD caps a date range at 120 days; 119 leaves slack for clock skew.
MAX_WINDOW_DAYS = 119


def nvd_pause(api_key: str | None) -> float:
    """Seconds between requests. TODO(verify) roughly 5 req/30s without a key, 50 with."""
    return 0.7 if api_key else 6.5


def _nvd_ts(dt: datetime) -> str:
    # TODO(verify) NVD 2.0 date format, including the required milliseconds and offset.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


async def fetch_nvd_window(client, db: DB, matcher, cfg: dict, api_key: str | None,
                           start: datetime, end: datetime, date_field: str = "lastMod") -> dict:
    """Page through one [start, end] window and process every result.

    date_field selects which NVD date the window applies to: "lastMod" for
    incremental sync (anything touched since last run), "pub" for backfill
    (anything published in the window). TODO(verify) the parameter names.
    """
    if end - start > timedelta(days=MAX_WINDOW_DAYS):
        raise ValueError(f"NVD window {start}..{end} exceeds {MAX_WINDOW_DAYS} days")
    headers = {"apiKey": api_key} if api_key else {}
    total = {"seen": 0, "matched": 0, "queued": 0, "unmapped": 0}
    idx = 0
    while True:
        params = {
            f"{date_field}StartDate": _nvd_ts(start), f"{date_field}EndDate": _nvd_ts(end),
            "resultsPerPage": 2000, "startIndex": idx,
        }
        r = await client.get(cfg["url"], params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
        s = process_nvd_page(data.get("vulnerabilities") or [], db, matcher, cfg)
        for k in total:
            total[k] += s[k]
        idx += int(data.get("resultsPerPage") or 0)
        if not data.get("resultsPerPage") or idx >= int(data.get("totalResults") or 0):
            break
        await asyncio.sleep(nvd_pause(api_key))
    return total


async def collect_nvd(client, db: DB, matcher, cfg: dict, api_key: str | None) -> dict:
    end = utcnow().replace(microsecond=0)
    last = db.get_kv("nvd_last_end")
    start = (datetime.fromisoformat(last) if last
             else end - timedelta(days=cfg.get("initial_lookback_days", 14)))
    start = max(start, end - timedelta(days=MAX_WINDOW_DAYS))
    total = await fetch_nvd_window(client, db, matcher, cfg, api_key, start, end)
    db.set_kv("nvd_last_end", end.isoformat())
    if not db.get_kv("nvd_history_from"):
        # First run: history begins here. The backfill script moves it earlier.
        db.set_kv("nvd_history_from", start.isoformat())
    return total
