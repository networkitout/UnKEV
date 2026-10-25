# Changelog

## 0.2.0 (2026-10-23)

Out of a forecast review on 2026-10-23: PHP2Shell propagated along *dependency* edges (PAN-OS, F5 BIG-IP, Cisco Expressway, Broadcom endpoint servers all bundle PHP) and the model couldn't see it; chronic-churn components pinned the top on raw CVE count; and recent KEV additions mostly landed outside the catalog and were invisible.

### Renamed kevcast to UnKEV

- `KEVCAST_*` env vars are now `UNKEV_*`; the DB default is `unkev.db`; Docker image, user and volume are `unkev`. `compose.yaml` carries a volume-migration note.
- Display name UnKEV; wordmark split Un/KEV so KEV stays orange across the product family.

### Inherited risk along dependency edges (new scoring term)

- `components.yaml` entries may declare `embeds`: a list of `{component, evidence, confirmed}` edges meaning "this product line bundles X". A signal on X now raises every host's likelihood through the new **inherited** term, scaled by the host's new `vendor_lag` prior (0-3, judgment calls) and down-weighted by `inherited.unconfirmed_edge_weight` (0.6) until a human confirms the edge against the vendor advisory. 45-day half-life. No self-edges.
- Exploitation is deliberately not inherited: exploitability inside the host product often differs (Palo Alto scored PHP2Shell on PAN-OS as availability-only, CVSS-B 8.7).
- Catalog `embeds` (drives likelihood) is distinct from `appliances.yaml` `embeds` (our box contains X; drives exposure). Both are documented in the README.
- New components: `f5-bigip`, `cisco-expressway`, `symantec-sepm`, `cb-app-control`. `mgmt-server` is a new ecosystem whose absence from host inventory is meaningful. `panos` and `netscaler` gain unconfirmed PHP edges.
- Claude may propose edges via `upstream_components` in `record_findings` (enum-constrained, validated, dropped if off-catalog). Proposals land in the new `embed_candidates` table and the "Proposed dependency edges" dashboard panel. There is no apply button; a human edits `components.yaml`.
- The brief prompt names the bundled upstream component for inherited drivers and says whether the edge is unconfirmed.

### Baseline-relative activity

- Activity now reacts to a change in a component's CVE rate, not the level. Recent severity mass (last 30 days, decayed) has the expected mass from the 30..180-day baseline subtracted before saturation; the expected mass is scaled by the window's mean decay so β = 1.0 cancels exactly the usual rate. Emergency, PoC and embargo bonuses are never subtracted. Config in `scoring.yaml` `activity_baseline`.
- Until the signal store covers `min_history_days` (150) of NVD history, β is forced to 0 (cold start) and results carry `baseline_ready: false`; the detail panel says "baseline warming up". History coverage comes from the kv `nvd_history_from`, set by the first NVD run and moved earlier by the new `scripts/backfill_nvd.py --days 180`, which walks back in ≤119-day windows on publication date.
- Results gain `activity_recent`, `activity_expected` and `activity_ratio`, both masses undecayed so the ratio is a true rate ratio (1.0 = its usual rate). The detail panel shows "N.N× its usual CVE rate" at ≥ 1.5.
- `validate_config` fails loudly if `max_signal_age_days` < `baseline_window_days`.
- The NVD page loop is shared between the collector and the backfill (`fetch_nvd_window`).

### "Exploited in the last 30 days" panel

- `db.exploited_recent` lists KEV entries from the last 30 days whether or not they map to the catalog, plus signals with confirmed exploitation, one row per CVE, newest first. Unmapped products read "not in catalog".
- Shown to the right of the forecast/detail split on wide screens, under it otherwise. No scoring change: this separates exploitation pressure from the discovery pressure the ranking models.

### OSV collector for package-level parsers

- New `config/packages.yaml` allowlist maps npm/PyPI packages to catalog components. OSV is queried per listed package (`POST /v1/query`), never crawled. Starter set: `ip-address` and `fast-uri`, as new `ecosystem: package` components carrying the `ip-canonicalization` surface.
- OSV carries CVSS vectors, not scores: v3 vectors are scored with the CVSS 3.1 formula; v4-only records (GHSA since 2025) take the advisory's own qualitative severity mapped to the bottom of its CVSS band via `osv.severity_bands`.
- Withdrawn and `MAL-` records are skipped; GHSA and CVE records for one bug collapse into one signal. Entries at or above 7.0 are queued for Claude surface tagging so package bugs can spill onto shared surfaces.
- `package` joins the library ecosystems: absence from host inventory is a visibility gap, not absence.

### Weight rebalance

| term | 0.1 | 0.2 |
|---|---|---|
| prior | 0.25 | 0.20 |
| activity | 0.30 | 0.25 |
| spillover | 0.20 | 0.15 |
| exploit | 0.25 | 0.25 |
| inherited | — | 0.15 |

Half-lives: inherited 45 days (new); others unchanged.

### Seed and demo corrections

- PHP2Shell rows keep `exploitation: attempts` (no confirmed compromise and not in KEV as of 2026-10-23) and record the pre-patch attempts and the reported ASLR-bypass exploit.
- Added CVE-2026-115560 (third PHP RCE path, unpatched, INI mitigation) and vendor PHP2Shell impact rows for PAN-OS, Cisco Expressway and F5 BIG-IP. CVSS is unset wherever no source stated one for that product.
- Demo appliances gain a Panorama that embeds PHP.
- The sample brief drops the false claim that PHP 7.4 gets no upstream fix (it has minimal source backports; distro and LTS vendors, cPanel and Plesk ship builds), and mentions CVE-2026-115560 and the unconfirmed PAN-OS edge.

### Running accuracy

- `app/evaluation.py` judges each day's snapshot 30 days later under two outcome profiles (serious new flaw; exploited in the wild), against recency, prior and chance baselines, and by cohort: components whose score came only from spillover/inherited are the predictive-only picks whose outcome rate is the honest test of the map. Stored in `forecast_eval`; the nightly `evaluate` job keeps it current; `scripts/replay_eval.py` judges stored history so there are numbers on day one. Shown as a "Track record" panel on both views.
- Description-fallback matching is off for PHP, Node.js, Perl, Apache httpd, nginx and Windows (`description_match: false`): 58% of all stored signals were application CVEs mentioning a runtime. Claude's surface tags now apply only to the components Claude named.
- NVD page fetches retry transport errors as well as 5xx, with a 120 s page timeout.

### Executive view

- `/` is now a leadership view: posture tiles, today's summary as readable paragraphs, the top ten risks with a plain-language *why now* and *our exposure* and a weekly trend, actively exploited items with an *in our estate?* answer, blind spots, and movers. Light theme, system font, every section titled, subtitled and ruled.
- Dark theme: follows the system preference, with an Auto / Dark / Light toggle in the masthead remembered per browser and applied before first paint. Every color is a token, so both themes share one layout.
- The previous dashboard is the analyst view at `/analyst`, minus the Claude token counter.
- Drivers carry structured fields (`cve`, `flags`, `exploitation`, `source`, `surfaces`, `confirmed`) so views can phrase them without parsing labels.

### Live-run fixes

- The 5.5 flagship models reject forced `tool_choice`. The extractor now tries the forced tool first and falls back to `auto` per model, discarding any response that doesn't call `record_findings`; both jobs default to `claude-opus-5-5`. Extraction gets 8000 output tokens of headroom for adaptive thinking.
- The brief sees all five stored drivers per component, so inherited drivers aren't crowded out by direct ones.
- Default user agent carries the repo URL: CISA's edge returns 403 to bot agents without a contact link.

### Other

- The inventory adapter is named for what it is: `app/inventory.py`, `config/inventory.yaml`, `scripts/inventory_probe.py`, `fixtures/inventory.json`, `INVENTORY_API_TOKEN`. It works against any CMDB or asset API returning per-host software/OS records.
- CSV export includes the inherited term.
- Extraction stats report `edges` proposed per batch.
- New `AGENTS.md` and `docs/agents/` for the engineering skills (GitHub issue tracker, triage labels, domain docs).

### Fact-check corrections (2026-10-25)

A validation pass against vendor sources fixed three catalog claims that did not hold, plus the backtest scope note:

- `fortios` PHP edge kept open, now `confirmed: false`: Fortinet has 12 products under investigation and none confirmed affected, and FortiOS is on its confirmed not-impacted list — the 9.8 CVSS v3 score is the advisory's for the products under investigation.
- `panos` PHP edge: removed the WildFire WF-500/WF-500-B claim, which the vendor corrected to not impacted on 2026-10-23. Evidence now cites the mitigation record: Threat IDs 543004 + 97622-97678 in content versions 9162-9164, hotfix ETAs 2026-10-26..30.
- `ivanti-ics` PHP edge removed: "Ivanti appliances are PHP-based (press)" had no traceable source. Re-add only with vendor or source-code evidence.
- `scripts/backtest.py` docstring and footer, the README backtest note and both `docs/backtest-*.txt` no longer claim a KEV replay doesn't exercise inherited: it does, along the catalog's `embeds` edges (ablating the inherited weight moves model MRR 0.529 → 0.502 at the same 0.728 hit@k). Spillover still is not exercised: replay signals carry no surfaces. Both docs are re-run against the current 39-component catalog, the 0.1 doc with its Phase-1 weight vector.
- `config/feeds.yaml` disables the CISA advisories `all.xml` feed (403 on every 2026-10-25 probe) and the README's feed-verification note is date-stamped. The checked-in `preview-analyst.html` is re-rendered from the corrected catalog.

### Update schedule in the masthead (2026-10-25)

- The worker persists its next cycle as kv `next_run_at` (`app/worker.mark_next_cycle`, right before it sleeps). Both views show a **Next update** chip in the masthead: the absolute time with a JS countdown (`static/nextrun.js`, CSP-safe, no new dependencies). Overdue shows **due now** — which can also mean the scheduler isn't running; the tooltip says so. With no schedule yet (fresh install) the chip is hidden, and static previews stay honest (they render neither chip nor button: `live=false`).
- The executive view gains an **Update now** button posting the existing `/run/all` (same HX header CSRF guard, same `#run-status` message as the analyst run buttons); htmx now loads there too.
- The button's response is a live run pill: a pulsing dot with "Updating all…", re-requesting `GET /run-status` every 4 s (htmx poll, `Cache-Control: no-store`), then flipping to "Done — scores from just now" or, when the run produced no new snapshot, "Done — nothing new scored." The terminal fragment drops the poller, so polling stops by itself. Clicking while another run is in flight joins the live pill instead of saying "already in progress". State logic lives in `app/views.run_status_html` / `run_status_text` (tested); `main.py` stays thin.
- Tests: contexts carry `next_run`; new `NextRun` case covers fresh-install/scheduled/overdue.
