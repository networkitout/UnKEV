"""Load demo data so the dashboard renders without API keys or network.

Signals are this week's real headlines (Oct 13-21, 2026), entered by hand
with origin='seed'. CVSS is only set where a source stated it. Inventory is
synthetic (fixtures/inventory.json). The brief is a hand-written
sample, labeled as such.

    python -m scripts.seed_demo
"""
from __future__ import annotations

import asyncio
import json
from datetime import timedelta

from app.db import DB, iso, item_id, utcnow
from app.inventory import sync_inventory
from app.pipeline import Ctx
from app.scoring import score_all

S = [
    # component, cve, date, cvss, surfaces, exploitation, kev, emergency, poc, embargo, conf, url, evidence
    ("php", "CVE-2026-109618", "2026-10-21", 9.2, ["session-state", "multipart-upload", "http-parsing"],
     "attempts", False, True, True, True, 0.9,
     "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching",
     "PHP2Shell: unauthenticated RCE via OOM corruption; fixed in 8.5.12/8.4.27/8.3.36/8.2.35; embargo leaked."),
    ("php", "CVE-2026-109619", "2026-10-21", 9.2, ["session-state", "multipart-upload"],
     "attempts", False, True, True, True, 0.9,
     "https://www.bleepingcomputer.com/news/security/php-warns-admins-of-two-critical-flaws-emergency-patches-coming-tomorrow/",
     "PHP2Shell: RCE via stale global state, session upload-progress path on mod_php and PHP-FPM."),
    ("nodejs", "CVE-2026-111497", "2026-10-21", None, ["compression"], "unknown", False, False, False, False, 0.85,
     "https://www.getastra.com/blog/security-advisory/nodejs-october-2026-security-patches/",
     "Brotli decoder out-of-bounds write, RCE; 26.x/24.x/22.x."),
    ("nodejs", "CVE-2026-105482", "2026-10-21", None, ["dns"], "unknown", False, False, False, False, 0.85,
     "https://www.getastra.com/blog/security-advisory/nodejs-october-2026-security-patches/",
     "dns.resolve name truncation, rated high."),
    ("nodejs", "CVE-2026-105483", "2026-10-21", None, ["ip-canonicalization", "tls-validation"], "unknown",
     False, False, False, False, 0.85, "https://cybersecuritynews.com/node-js-releases-security-updates/",
     "TLS hostname verification bypass with full-width digit IPs; 26.x/24.x."),
    ("nodejs", "CVE-2026-106069", "2026-10-21", None, ["ip-canonicalization", "tls-validation"], "unknown",
     False, False, False, False, 0.85, "https://lilting.ch/en/articles/nodejs-tls-dns-brotli-security-release",
     "TLS hostname checks bypassed with alternate IPv4 spellings."),
    ("nextjs", "CVE-2026-96889", "2026-10-14", 9.5, ["image-codec"], "unknown", False, False, False, False, 0.85,
     "https://brandefense.io/security-news/next-js-node-js-security-updates-october-2026/",
     "RCE in Image Optimization API via SVG; fixed 15.5.28 / 16.4.1."),
    ("curl", "CVE-2026-19931", "2026-10-14", 9.8, ["auth-session-reuse"], "unknown", False, False, False, False, 0.8,
     "https://www.action1.com/patch-tuesday/vulnerability-digest-october-2026-third-party-updates/",
     "libcurl reuses a Negotiate-authenticated connection across users. Date approximate (monthly digest)."),
    ("windows", "CVE-2026-69639", "2026-10-13", 9.8, ["archive"], "unknown", False, False, False, False, 0.85,
     "https://senserva.com/patch-tuesday.html", "Windows libarchive RCE, October Patch Tuesday."),
    ("libarchive", "CVE-2026-69639", "2026-10-13", 9.8, ["archive"], "unknown", False, False, False, False, 0.5,
     "https://senserva.com/patch-tuesday.html",
     "Windows ships libarchive; upstream impact not confirmed from this source."),
    ("windows", "CVE-2026-96951", "2026-10-13", 8.8, [], "confirmed", True, False, False, False, 0.95,
     "https://www.rapid7.com/blog/post/em-patch-tuesday-october-2026/",
     "Windows Shell MOTW bypass, exploited in the wild."),
    ("panos", "", "2026-10-14", None, ["vpn-gateway", "mgmt-plane"], "confirmed", False, True, False, False, 0.7,
     "https://tech-insider.org/microsoft-patch-tuesday-1413-cves-zero-day-2026/",
     "Exploited PAN-OS RCE zero-day patched the same week as Patch Tuesday (secondary source)."),
    ("cisco-asyncos", "", "2026-10-14", None, ["mgmt-plane"], "confirmed", False, True, False, False, 0.7,
     "https://tech-insider.org/microsoft-patch-tuesday-1413-cves-zero-day-2026/",
     "Exploited Secure Email Gateway flaw allowing root command execution (secondary source)."),
    ("ivanti-ics", "", "2026-10-14", None, ["vpn-gateway"], "confirmed", False, False, False, False, 0.7,
     "https://tech-insider.org/microsoft-patch-tuesday-1413-cves-zero-day-2026/",
     "CISA pushed immediate remediation of an exploited Connect Secure flaw (secondary source)."),
]

DEMO_APPLIANCES = [
    {"name": "Demo ADC pair", "component": "netscaler", "count": 2, "internet_facing": 2,
     "criticality": "critical", "embeds": [], "evidence": "demo entry"},
]

SAMPLE_BRIEF = """Sample brief, hand-written for the demo. The live one is generated by Claude from the scored data.

PHP leads on both axes. Two CVSS 9.2 pre-auth RCEs shipped as an emergency release after the embargo leaked [verified: seed], with exploitation attempts reported on honeypots [reported: seed]. 6 hosts run PHP-FPM, 2 internet-facing, and the fixture shows 7.4.x, which gets no upstream fix.

Node.js moved on four high-severity fixes. The IP-canonicalization pair is the forecast signal: alternate IPv4 spellings and full-width digits bypassing TLS hostname checks [verified: seed]. That surface is shared by curl and CPython in the catalog, so expect variant hunting in their URL/IP parsers [inferred].

Exposure is unknown for zlib, Brotli and libarchive. Host inventory doesn't see bundled libraries, so treat this as a visibility gap [inferred].

- Patch or confirm PHP 8.2.35+ on the two internet-facing web hosts; plan a 7.4 retirement.
- Upgrade Node 18.x hosts; 18 is outside the patched lines.
- Request SBOMs for the ADC pair and email gateway to fill embedded-component exposure."""


def main():
    ctx = Ctx()
    db = ctx.db
    for (cid, cve, date, cvss, surf, expl, kev, emerg, poc, emb, conf, url, ev) in S:
        iid = item_id("seed", cid, cve or ev[:40])
        db.upsert_intel(id=iid, source="seed", url=url, title=cve or ev[:60], published_at=date,
                        raw_text=ev, status="extracted")
        db.add_signal(intel_id=iid, component_id=cid, origin="seed", cve=cve, cvss=cvss, surfaces=surf,
                      exploitation=expl, kev=kev, emergency=emerg, poc_public=poc, embargo_broken=emb,
                      confidence=conf, observed_at=f"{date}T14:00:00+00:00", title=cve or ev[:60],
                      url=url, evidence=ev)

    inv, stats = asyncio.run(sync_inventory(None, ctx.inventory_cfg | {"mode": "fixture"}, ctx.matcher,
                                            ctx.components, DEMO_APPLIANCES))
    db.replace_inventory(inv)

    now = utcnow()
    signals = db.signals_since(iso(now - timedelta(days=180)))
    week_ago = now - timedelta(days=7)
    past = [s for s in signals if s["observed_at"] <= iso(week_ago)]
    db.write_snapshot(iso(week_ago), score_all(ctx.components, past, inv, ctx.scoring, now=week_ago))
    db.write_snapshot(iso(now), score_all(ctx.components, signals, inv, ctx.scoring, now=now))
    db.save_brief("sample, not generated", SAMPLE_BRIEF, 0, 0)
    rid = db.start_run("seed")
    db.finish_run(rid, True, json.dumps({"signals": len(S), "inventory": stats}))
    print(f"seeded {len(S)} signals; inventory {stats}")


if __name__ == "__main__":
    main()
