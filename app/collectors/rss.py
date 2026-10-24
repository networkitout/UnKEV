"""RSS 2.0 / Atom collector. defusedxml because feeds are hostile input
(yes, XML parsers are on our own forecast list)."""
from __future__ import annotations

from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

from ..db import DB, item_id

ATOM = "{http://www.w3.org/2005/Atom}"


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data):
        self.parts.append(data)


def strip_html(s: str) -> str:
    p = _Text()
    try:
        p.feed(s or "")
    except Exception:
        return s or ""
    return " ".join(" ".join(p.parts).split())


def _date(s: str | None) -> str | None:
    if not s:
        return None
    try:
        return parsedate_to_datetime(s).isoformat()
    except (TypeError, ValueError):
        return s.strip()[:25]


def parse_feed(xml_bytes: bytes) -> list[dict]:
    from defusedxml import ElementTree as ET  # lazy: keeps scoring tests stdlib-only
    root = ET.fromstring(xml_bytes)
    items = []
    for it in root.iter("item"):
        items.append({
            "title": (it.findtext("title") or "").strip(),
            "url": (it.findtext("link") or "").strip(),
            "guid": (it.findtext("guid") or it.findtext("link") or "").strip(),
            "summary": strip_html(it.findtext("description") or ""),
            "published": _date(it.findtext("pubDate")),
        })
    for e in root.iter(f"{ATOM}entry"):
        link = e.find(f"{ATOM}link")
        href = link.get("href") if link is not None else ""
        items.append({
            "title": (e.findtext(f"{ATOM}title") or "").strip(),
            "url": href,
            "guid": e.findtext(f"{ATOM}id") or href,
            "summary": strip_html(e.findtext(f"{ATOM}summary") or e.findtext(f"{ATOM}content") or ""),
            "published": e.findtext(f"{ATOM}updated") or e.findtext(f"{ATOM}published"),
        })
    return items


async def collect_rss(client, db: DB, matcher, cfg: dict) -> dict:
    stats = {"feeds": 0, "new": 0, "queued": 0, "errors": []}
    for feed in cfg.get("feeds", []):
        try:
            r = await client.get(feed["url"])
            r.raise_for_status()
            items = parse_feed(r.content)[: cfg.get("max_items_per_feed", 40)]
        except Exception as e:  # one bad feed shouldn't stop the run
            stats["errors"].append(f"{feed['name']}: {type(e).__name__}: {str(e)[:120]}")
            continue
        stats["feeds"] += 1
        for it in items:
            text = f"{it['title']}\n{it['summary']}"
            queue = matcher.passes_prefilter(text)
            is_new = db.upsert_intel(id=item_id("rss", it["guid"] or it["url"]), source=feed["name"],
                                     url=it["url"], title=it["title"], published_at=it["published"],
                                     raw_text=it["summary"][:8000], status="new" if queue else "skipped")
            stats["new"] += int(is_new)
            stats["queued"] += int(is_new and queue)
    return stats
