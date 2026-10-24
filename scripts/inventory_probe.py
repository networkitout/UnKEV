"""Check the inventory adapter mapping before trusting exposure scores.

Fetches ONE page per configured source (no pagination), then prints:
  - the raw keys of the first record (so you can fix field paths)
  - each configured field and what it resolved to (None = wrong path)
  - which catalog components the sample matched

    python -m scripts.inventory_probe            # uses mode from inventory.yaml
    python -m scripts.inventory_probe --fixture  # force fixture mode
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os

from app.config import ROOT, load_yaml
from app.inventory import dig, normalize
from app.matching import Matcher


async def fetch_one(cfg: dict, src: dict) -> list[dict]:
    import httpx
    token = os.environ.get(cfg["auth"]["token_env"], "")
    if not token:
        print(f"  warning: {cfg['auth']['token_env']} is not set; request will go unauthenticated")
    headers = {cfg["auth"]["header"]: f'{cfg["auth"].get("scheme", "")} {token}'.strip()} if token else {}
    async with httpx.AsyncClient(timeout=30, verify=cfg.get("verify_tls", True)) as c:
        r = await c.get(cfg["base_url"].rstrip("/") + src["path"], params=src.get("params") or {}, headers=headers)
        print(f"  GET {r.request.url} -> {r.status_code} {r.headers.get('content-type', '')}")
        r.raise_for_status()
        body = r.json()
    page = dig(body, src.get("items_path")) if src.get("items_path") else body
    if not isinstance(page, list):
        top = list(body)[:12] if isinstance(body, dict) else type(body).__name__
        raise SystemExit(f"  items_path '{src.get('items_path')}' did not resolve to a list. Top-level keys: {top}")
    return page


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", action="store_true")
    ap.add_argument("--n", type=int, default=3)
    a = ap.parse_args()
    cfg = load_yaml("inventory.yaml")
    components = load_yaml("components.yaml")
    matcher = Matcher(components)
    mode = "fixture" if a.fixture else (cfg.get("mode") or "none")
    if mode == "none":
        print("mode: none. No inventory source is configured, so every component reads \"unknown\".\n"
              "Set mode: api and the routes in config/inventory.yaml, then re-run. Or --fixture for demo data.")
        return
    fixture = mode == "fixture"
    data = json.loads((ROOT / cfg["fixture_path"]).read_text()) if fixture else None
    print(f"mode: {mode}\n")

    for name, src in (cfg.get("sources") or {}).items():
        print(f"[{name}]")
        try:
            raw = (data or {}).get(name, []) if fixture else asyncio.run(fetch_one(cfg, src))
        except SystemExit as e:
            print(e)
            continue
        except Exception as e:
            print(f"  failed: {type(e).__name__}: {e}")
            continue
        print(f"  records in first page: {len(raw)}")
        if not raw:
            continue
        print(f"  raw keys: {sorted(raw[0])[:25]}")
        missing = set()
        for rec, norm in list(zip(raw, normalize(raw, src["fields"])))[: a.n]:
            print("  ---")
            for field, path in src["fields"].items():
                val = norm[field]
                if val is None:
                    missing.add(field)
                print(f"  {field:16} <- {path:28} = {val!r}"[:140])
            hits = matcher.match_software(str(norm.get("name") or "")) + matcher.match_os(str(norm.get("os") or ""))
            print(f"  matched components: {hits or 'none'}")
        if missing:
            print(f"  fix these field paths in inventory.yaml: {sorted(missing)}")
        print()


if __name__ == "__main__":
    main()
