"""Inventory adapter: any CMDB or asset API that returns per-host records.

Config-driven (config/inventory.yaml) so no route or schema is pinned here.
Records are normalized to {host, name, version, os, internet_facing,
criticality}, matched to catalog components, and aggregated.

Exposure status semantics:
  known     source returned records and at least one host matched
  none      source returned records and nothing matched (confirmed absent)
  unknown   source not configured / failed / doesn't cover this component type
  declared  only appliances.yaml says it's present
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from .config import ROOT


def dig(obj, path: str | None):
    if not path:
        return None
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _truthy(v) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "y", "external", "internet")


# Host application inventory (Falcon Discover, Intune, etc.) usually lists
# applications and OS packages, not libraries vendored inside other software
# or npm/PyPI packages inside applications. For these ecosystems a miss is
# "unknown", never "none".
LIBRARY_ECOSYSTEMS = {"compression", "archive", "parser", "codec", "dns-lib", "system-lib",
                      "crypto-lib", "client-lib", "embedded-db", "package"}


def absence_means(component: dict) -> str:
    inv = component.get("inventory") or {}
    if inv.get("absence_means") in ("none", "unknown"):
        return inv["absence_means"]
    return "unknown" if component.get("ecosystem") in LIBRARY_ECOSYSTEMS else "none"


def normalize(records: list[dict], fields: dict) -> list[dict]:
    return [{k: dig(r, p) for k, p in fields.items()} for r in records]


def aggregate(software: list[dict] | None, hosts: list[dict] | None, matcher,
              components: dict, critical_values: list[str]) -> dict[str, dict]:
    crit_vals = {str(c).lower() for c in critical_values}
    hits: dict[str, dict[str, dict]] = defaultdict(dict)   # cid -> host -> rec
    versions: dict[str, Counter] = defaultdict(Counter)

    for rec in software or []:
        for cid in matcher.match_software(str(rec.get("name") or "")):
            hits[cid][str(rec.get("host"))] = rec
            if rec.get("version"):
                versions[cid][str(rec["version"])] += 1
    for rec in hosts or []:
        for cid in matcher.match_os(str(rec.get("os") or "")):
            hits[cid][str(rec.get("host"))] = rec
            if rec.get("os"):
                versions[cid][str(rec["os"])] += 1

    sw_covered = software is not None
    os_covered = hosts is not None
    out = {}
    for cid, c in components.items():
        inv_cfg = c.get("inventory") or {}
        covered = (sw_covered and inv_cfg.get("software")) or (os_covered and inv_cfg.get("os"))
        recs = hits.get(cid, {})
        if recs:
            out[cid] = {
                "status": "known", "hosts": len(recs),
                "internet_facing": sum(_truthy(r.get("internet_facing")) for r in recs.values()),
                "critical": sum(str(r.get("criticality") or "").lower() in crit_vals for r in recs.values()),
                "detail": {"versions": versions[cid].most_common(6)},
            }
        elif covered and absence_means(c) == "none":
            out[cid] = {"status": "none", "hosts": 0, "internet_facing": 0, "critical": 0, "detail": {}}
        else:
            out[cid] = {"status": "unknown", "hosts": 0, "internet_facing": 0, "critical": 0, "detail": {}}
    return out


def merge_appliances(inv: dict[str, dict], appliances: list[dict], crit_vals: list[str]) -> dict[str, dict]:
    crit = {str(c).lower() for c in crit_vals}
    for a in appliances or []:
        targets = [a.get("component")] + list(a.get("embeds") or [])
        for cid in filter(None, targets):
            cur = inv.setdefault(cid, {"status": "unknown", "hosts": 0, "internet_facing": 0,
                                       "critical": 0, "detail": {}})
            if cur["status"] in ("unknown", "none"):
                cur["status"] = "declared"
            cur["hosts"] += int(a.get("count", 1))
            cur["internet_facing"] += int(a.get("internet_facing", 0))
            cur["critical"] += int(a.get("count", 1)) if str(a.get("criticality", "")).lower() in crit else 0
            cur["detail"].setdefault("declared", []).append({
                "name": a.get("name"), "via": "embedded" if cid != a.get("component") else "appliance",
                "evidence": a.get("evidence") or "unverified"})
    return inv


async def _fetch_source(client, cfg: dict, src: dict) -> list[dict]:
    token = os.environ.get(cfg["auth"]["token_env"], "")
    headers = {cfg["auth"]["header"]: f'{cfg["auth"].get("scheme", "")} {token}'.strip()} if token else {}
    pag = src.get("pagination") or {"type": "none"}
    params = dict(src.get("params") or {})
    url = cfg["base_url"].rstrip("/") + src["path"]
    out: list[dict] = []
    for _ in range(1000):  # hard stop on runaway pagination
        r = await client.get(url, params=params, headers=headers)
        r.raise_for_status()
        body = r.json()
        page = dig(body, src.get("items_path")) if src.get("items_path") else body
        page = page or []
        out.extend(page)
        if pag["type"] == "offset":
            size = int(params.get(pag.get("size_param", "limit"), len(page)) or 0)
            if len(page) < size or not page:
                break
            params[pag["param"]] = int(params.get(pag["param"], 0)) + len(page)
        elif pag["type"] == "cursor":
            nxt = dig(body, pag["next_path"])
            if not nxt:
                break
            params[pag["param"]] = nxt
        else:
            break
    return out


async def sync_inventory(client, cfg: dict, matcher, components: dict, appliances: list[dict]) -> tuple[dict, dict]:
    sources = cfg.get("sources") or {}
    raw: dict[str, list[dict] | None] = {"software": None, "hosts": None}
    errors = {}
    if cfg.get("mode") == "fixture":
        data = json.loads((ROOT / cfg["fixture_path"]).read_text())
        for k in raw:
            if k in data and k in sources:
                raw[k] = normalize(data[k], sources[k]["fields"])
    else:
        for k in raw:
            if k not in sources:
                continue
            try:
                raw[k] = normalize(await _fetch_source(client, cfg, sources[k]), sources[k]["fields"])
            except Exception as e:
                errors[k] = f"{type(e).__name__}: {str(e)[:200]}"
    inv = aggregate(raw["software"], raw["hosts"], matcher, components, cfg.get("critical_values") or [])
    inv = merge_appliances(inv, appliances, cfg.get("critical_values") or [])
    stats = {"software_records": len(raw["software"] or []), "host_records": len(raw["hosts"] or []),
             "known": sum(v["status"] == "known" for v in inv.values()),
             "unknown": sum(v["status"] == "unknown" for v in inv.values()), "errors": errors}
    return inv, stats
