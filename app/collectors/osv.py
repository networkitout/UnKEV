"""OSV (osv.dev) for packages the catalog tracks at package level.

Queried per package from config/packages.yaml, never crawled, so network
volume is one small POST per package per run. Matching is exact: the
package IS the component, so confidence is high and no text matching runs.

API. Request and response shape verified with a live query on 2026-10-23:
  POST https://api.osv.dev/v1/query  {"package": {"name": ..., "ecosystem": ...}}
  -> {"vulns": [...]}. Each vuln: id, aliases[], summary, details, published,
  modified, withdrawn, severity[{type: CVSS_V3 | CVSS_V4, score: <vector>}],
  database_specific{severity: CRITICAL|HIGH|MODERATE|LOW, cwe_ids[]} on GHSA records.
  TODO(verify) pagination: "next_page_token" / "page_token" were not exercised
  (both tracked packages fit in one page). https://google.github.io/osv.dev/api/

CVSS: OSV carries vectors, not numbers. v3 vectors are scored here with the
CVSS 3.1 specification formula. GHSA advisories since 2025 carry v4 only, and
v4's MacroVector table isn't worth reimplementing to land in a severity
bucket; for those the advisory's own qualitative severity is mapped to the
bottom of its CVSS band through feeds.yaml osv.severity_bands. The scoring
buckets (>=9, >=7, >=4) are exactly those bands, so the effect is faithful
to the source. Without that config v4-only records keep cvss None.
"""
from __future__ import annotations

import asyncio
import math

from ..db import DB, iso, item_id, utcnow
from ..matching import CVE_RE

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    # CVSS 3.1 Appendix A: integer arithmetic so 4.0000001 rounds to 4.0, not 4.1.
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    """Base score from a CVSS:3.0 or 3.1 vector string. None if unparseable."""
    parts = (vector or "").split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in parts[1:])
        changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1.0) * (impact + expl), 10.0))


def best_cvss(vuln: dict, bands: dict | None = None) -> float | None:
    """Exact v3 base score when a v3 vector exists; else the advisory's
    qualitative severity mapped through bands; else None."""
    for s in vuln.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            score = cvss3_base(s.get("score") or "")
            if score is not None:
                return score
    band = (vuln.get("database_specific") or {}).get("severity")
    if bands and band:
        v = bands.get(str(band).upper())
        return float(v) if v is not None else None
    return None


def cve_of(vuln: dict) -> str:
    for x in [vuln.get("id") or ""] + list(vuln.get("aliases") or []):
        if CVE_RE.fullmatch(x):
            return x.upper()
    return ""


def _ts(s: str | None) -> str | None:
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    return s if "+" in s[10:] else s.split(".")[0] + "+00:00"


def process_osv_vulns(vulns: list[dict], db: DB, component: str, label: str, cfg: dict) -> dict:
    stats = {"seen": 0, "signals": 0, "queued": 0, "withdrawn": 0, "malicious": 0}
    for v in vulns:
        stats["seen"] += 1
        oid = str(v.get("id") or "")
        if v.get("withdrawn"):
            stats["withdrawn"] += 1
            continue
        if oid.startswith("MAL-"):
            # A malicious version of the package is a supply-chain event, not a parser bug.
            stats["malicious"] += 1
            continue
        cve = cve_of(v)
        iid = item_id("osv", cve or oid)   # GHSA and CVE records for one bug collapse here
        cvss = best_cvss(v, cfg.get("severity_bands"))
        published = _ts(v.get("published")) or iso(utcnow())
        title = f"{label}: {v.get('summary') or oid}"[:200]
        url = f"https://osv.dev/vulnerability/{oid}"
        text = v.get("details") or v.get("summary") or ""
        queue = cvss is not None and cvss >= cfg.get("llm_tag_min_cvss", 8.0)
        new = db.upsert_intel(id=iid, source="osv", url=url, title=title, published_at=published,
                              raw_text=text[:6000], status="new" if queue else "extracted")
        db.add_signal(intel_id=iid, component_id=component, origin="osv", cve=cve, cvss=cvss,
                      exploitation="unknown", observed_at=published, confidence=0.9,
                      title=title, url=url, evidence=text[:300])
        stats["signals"] += 1
        stats["queued"] += int(queue and new)
    return stats


async def fetch_package(client, cfg: dict, ecosystem: str, name: str) -> list[dict]:
    body: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    out: list[dict] = []
    for _ in range(50):   # hard stop on runaway pagination
        r = await client.post(cfg["url"], json=body)
        r.raise_for_status()
        data = r.json()
        out.extend(data.get("vulns") or [])
        token = data.get("next_page_token")
        if not token:
            break
        body["page_token"] = token
    return out


async def collect_osv(client, db: DB, cfg: dict, packages: list[dict], components: dict) -> dict:
    total = {"packages": 0, "seen": 0, "signals": 0, "queued": 0, "withdrawn": 0, "malicious": 0,
             "skipped": []}
    for i, p in enumerate(packages or []):
        cid = p.get("component")
        if cid not in components:
            total["skipped"].append(f"{p.get('ecosystem')} {p.get('name')}: component {cid!r} not in catalog")
            continue
        if i:
            await asyncio.sleep(float(cfg.get("pause_seconds", 0.2)))
        vulns = await fetch_package(client, cfg, p["ecosystem"], p["name"])
        s = process_osv_vulns(vulns, db, cid, f"{p['ecosystem']} {p['name']}", cfg)
        total["packages"] += 1
        for k in ("seen", "signals", "queued", "withdrawn", "malicious"):
            total[k] += s[k]
    return total
