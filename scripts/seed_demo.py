"""Load demo data so the dashboard renders without API keys or network.

Signals are real headlines from Oct 13-23, 2026, entered by hand with
origin='seed'. CVSS is only set where a source stated it for that product.
Inventory is synthetic (fixtures/inventory.json). The brief is a
hand-written sample, labeled as such.

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
     "https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/",
     "PHP2Shell: unauthenticated RCE via OOM corruption; fixed in 8.5.12/8.4.27/8.3.36/8.2.35; embargo leaked. "
     "Attempts seen from 2026-10-17 (Amazon), before the patch. VulnCheck reports a working ASLR-bypass "
     "exploit against unpatched 8.4."),
    ("php", "CVE-2026-109619", "2026-10-21", 9.2, ["session-state", "multipart-upload"],
     "attempts", False, True, True, True, 0.9,
     "https://labs.beazley.security/advisories/BSL-A1233",
     "PHP2Shell: RCE via stale global state, session upload-progress path on mod_php and PHP-FPM. "
     "Attempts seen from 2026-10-17 (Amazon), before the patch. VulnCheck reports a working ASLR-bypass "
     "exploit against unpatched 8.4."),
    ("php", "CVE-2026-115560", "2026-10-23", None, ["session-state", "serialization", "multipart-upload"],
     "none", False, False, False, False, 0.85,
     "https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html",
     "Third PHP RCE path: session upload progress plus runtime switch of serialize_handler to php before "
     "session_start(). Not fixed by the Oct 21 releases; fix in regular release. "
     "Mitigation: session.upload_progress.enabled=0."),
    ("panos", "", "2026-10-22", None, ["mgmt-plane"], "none", False, False, False, False, 0.85,
     "https://www.helpnetsecurity.com/2026/10/22/php2shell-vulnerability-fortinet-cisco-palo-alto-networks/",
     "Vendor: all PAN-OS 10.2-12.2 and Panorama affected by PHP2Shell (bundled PHP), no fix ETA; "
     "scored CVSS-B 8.7 availability-only; restrict mgmt interface."),
    ("cisco-expressway", "", "2026-10-22", None, ["mgmt-plane"], "none", False, False, False, False, 0.8,
     "https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/",
     "Expressway and Expressway Select affected by PHP2Shell (CSCwx37062), Critical, fixed in 15.5.21, "
     "no workaround."),
    ("f5-bigip", "", "2026-10-23", None, ["mgmt-plane"], "none", False, False, False, False, 0.7,
     "https://mallory.ai/blog/php-rce-rapid-response",
     "Configuration utility affected by PHP2Shell per K000163821 (secondary report), not fixed."),
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
    {"name": "Demo Panorama", "component": "panos", "count": 1, "internet_facing": 0,
     "criticality": "critical", "embeds": ["php"], "evidence": "demo entry"},
]

SAMPLE_BRIEF = """Sample brief, hand-written for the demo. The live one is generated by Claude from the scored data.

PHP leads on both axes. Two CVSS 9.2 pre-auth RCEs (PHP2Shell) shipped as an emergency release after the embargo leaked; attempts were seen from Oct 17, before the patch, and a working ASLR-bypass exploit is reported against unpatched 8.4 [verified: seed]. A third RCE path, CVE-2026-115560 via session upload progress, is not fixed by the Oct 21 releases; set session.upload_progress.enabled=0 until the regular release [verified: seed]. 7 hosts run PHP, 2 internet-facing, and the fixture shows 7.4.x, which has only minimal source backports from the PHP team (no official release); distro and LTS vendors, cPanel and Plesk ship builds.

PAN-OS and Panorama inherit PHP2Shell: all PAN-OS 10.2-12.2 and every Panorama version are affected, no fix ETA [verified: seed]. That catalog edge is unconfirmed until someone reads the vendor advisory; treat the inherited term as provisional and restrict the management interface now [inferred].

Node.js moved on four high-severity fixes. The IP-canonicalization pair is the forecast signal: alternate IPv4 spellings and full-width digits bypass TLS hostname checks [verified: seed]. curl and CPython share that surface [inferred].

zlib, Brotli and libarchive are exposure-unknown: host inventory doesn't see bundled libraries [inferred].

- Patch PHP to 8.2.35+ on the two internet-facing hosts; apply the INI mitigation everywhere.
- Restrict PAN-OS and Panorama management to the admin network; confirm the advisory and flip the catalog edge.
- Upgrade Node 18.x hosts; 18 is outside the patched lines."""


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
