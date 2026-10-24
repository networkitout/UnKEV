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

### Other

- The inventory adapter is named for what it is: `app/inventory.py`, `config/inventory.yaml`, `scripts/inventory_probe.py`, `fixtures/inventory.json`, `INVENTORY_API_TOKEN`. It works against any CMDB or asset API returning per-host software/OS records.
- CSV export includes the inherited term.
- Extraction stats report `edges` proposed per batch.
- New `AGENTS.md` and `docs/agents/` for the engineering skills (GitHub issue tracker, triage labels, domain docs).
