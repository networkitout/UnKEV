# UnKEV 0.2: implementation brief

You are working in the repo previously named **kevcast**. This brief renames it to **UnKEV** and makes four model and UI changes that came out of a forecast review on 2026-10-23. Work through the phases in order. Commit after each phase. Run the test suite after each phase, and do not continue on a red suite.

The repo may have drifted from what this brief assumes. Before editing, read the current code and adapt. Functions are referenced by name, not line number. If something here conflicts with what you find, stop and report the conflict instead of guessing.

---

## Standing rules for this task

1. **The scoring layer stays deterministic.** Claude (the LLM layer in `app/llm.py`) may produce *signals* and *proposals*. It must never write scores, weights, or the catalog (`config/components.yaml`). Any new LLM output field follows the existing pattern:
   - enum-constrained in the tool schema
   - validated in `validate_findings`
   - dropped if off-schema
2. **No new runtime dependencies** without asking first. Stdlib is preferred. No npm.
3. **Do not invent vulnerability data.** Seed and demo data use only the facts listed in Phase 5, which were sourced from vendor advisories and security press on 2026-10-21 to 2026-10-23. If you need a fact that isn't listed, leave a `TODO(verify)` comment instead.
4. **Model changes stay in config.** Any new weight, half-life, or threshold goes in `config/scoring.yaml`, not in code or templates.
5. Every new scoring term must appear in each result's `points` and `term_max`, and in the detail panel's breakdown. Every new driver kind must render in the "Why it's ranked here" list.
6. **Tests:** `python -m unittest discover -s tests -t . -v`. Add tests for every behavior change listed below.
7. **Preview check:**
   ```bash
   rm -f *.db* && python -m scripts.seed_demo && python -m scripts.render_preview preview.html
   ```
   Check the result visually if you can.

---

## Phase 0: Orient (no code changes)

1. Run the test suite and record the result.
2. If `kev.json` exists, run `python -m scripts.backtest kev.json --start 2025-01 --end 2026-10 --k 10`. Save the summary table to `docs/backtest-0.1.txt`. If it doesn't exist, skip this and say so in your Phase 7 report.
3. List every occurrence of `kevcast`, `KEVCAST` and `KevCast`, case-insensitive:
   ```bash
   grep -rni kevcast .
   ```

---

## Phase 1: Rename to UnKEV

**Identifiers**

| Old | New |
|---|---|
| `kevcast` (prose, logger names, titles, filenames, image and volume names) | `unkev` |
| `KEVCAST_*` env vars | `UNKEV_*` (e.g. `UNKEV_PASSWORD`, `UNKEV_DB`, `UNKEV_EXTRACT_MODEL`) |
| Display name | **UnKEV** |

**Files to update**

- `app/config.py`: every env var name. Default DB path becomes `unkev.db`. User-Agent becomes `unkev/0.2 (+internal threat forecast)`. `UNKEV_CONFIG_DIR` replaces `KEVCAST_CONFIG_DIR`.
- `Dockerfile`: `ENV UNKEV_DB=/data/unkev.db`, and the user name `unkev`.
- `compose.yaml`: `image: unkev:local`, volume `unkev-data`, env var names. Add a comment at the top:
  ```yaml
  # Migrating from kevcast? The named volume changed. Copy data first:
  #   docker run --rm -v <old_project>_kevcast-data:/from -v <new_project>_unkev-data:/to \
  #     alpine sh -c 'cp -a /from/. /to/ && mv /to/kevcast.db /to/unkev.db 2>/dev/null; true'
  ```
  WAL files (`-wal`, `-shm`) belong with the DB. Stop the containers before copying.
- `.env.example`, `README.md`, the `scripts/*` docstrings, the `app/main.py` FastAPI title, the CSV download filename (`unkev-scores.csv`), the `logging.getLogger` names, and the `app/static/app.css` header comment.
- `.gitignore`: add `unkev.db*`. Keep the `kevcast.db*` patterns too, so old local DBs aren't committed.

**Wordmark** (`app/templates/dashboard.html`): two-color split, matching the KEV/LAR convention. "Un" uses `.b` (Docker blue, `--blue`) and "KEV" uses `.a` (burnt orange, `--accent`), so "KEV" stays orange across the product family.

```html
<div class="mark"><span class="b">Un</span><span class="a">KEV</span></div>
```

Update `<title>` in `base.html` to `UnKEV`.

**Acceptance**

- `grep -rni kevcast .` returns only the migration comment in `compose.yaml` and the `.gitignore` legacy pattern.
- The test suite is green.

---

## Phase 2: Inherited risk along dependency edges (largest change)

**Why.** PHP2Shell propagated along *dependency* edges: PAN-OS/Panorama, F5 BIG-IP, Cisco Expressway and Broadcom endpoint servers all bundle PHP. UnKEV's spillover term only follows *shared attack surfaces*, and `appliances.yaml` `embeds` only affects *exposure*. Today, a PHP emergency never raises PAN-OS's likelihood. Fix that with a fifth scoring term.

### 2a. Catalog schema (`config/components.yaml`)

Add an optional `embeds` list to a component. Each edge records evidence and whether a human has confirmed it against the vendor's own advisory:

```yaml
panos:
  # ...existing fields...
  priors: {memory_unsafe: 1, preauth: 3, install_base: 2, embedding: 0, legacy_tail: 2, vendor_lag: 2}
  embeds:
    - component: php
      evidence: "Palo Alto PHP2Shell advisory: PAN-OS 10.2-12.2 and all Panorama versions affected, fix ETA TBD (reported 2026-10-22)"
      confirmed: false   # flip to true after reading the vendor advisory yourself
```

Also add a new prior, `vendor_lag` (0-3), to appliance components. It's an analyst estimate of how slowly the vendor ships fixes for bundled upstream bugs. It is used only by the inherited term, not by `prior_score`. Defaults, which are judgment calls (mark them as such in the file header):

| component | vendor_lag |
|---|---|
| panos | 2 |
| netscaler | 2 |
| ivanti-ics | 3 |
| fortios | 2 |
| cisco-asyncos | 2 |
| f5-bigip (new) | 2 |
| cisco-expressway (new) | 2 |
| symantec-sepm (new) | 2 |
| cb-app-control (new) | 1 |

Add these new components. All are `ecosystem: appliance` unless noted. Use `inventory: {}` (declared-only), same as the other appliances.

```yaml
f5-bigip:
  name: F5 BIG-IP
  ecosystem: appliance
  priors: {memory_unsafe: 1, preauth: 3, install_base: 2, embedding: 0, legacy_tail: 3, vendor_lag: 2}
  surfaces: [mgmt-plane, http-parsing, vpn-gateway]
  aliases: ["BIG-IP", "F5 BIG-IP", "TMUI"]
  cpe: ["f5:big-ip_local_traffic_manager", "f5:big-ip_access_policy_manager"]   # TODO(verify) CPE product names
  kev: [["^f5$", "big-ip"]]
  inventory: {}
  embeds:
    - {component: php, evidence: "F5 K000163821: Configuration utility affected, 21.1.0, 17.5.0-17.5.1, 17.1.0-17.1.3, not fixed (secondary report 2026-10-23)", confirmed: false}

cisco-expressway:
  name: Cisco Expressway
  ecosystem: appliance
  priors: {memory_unsafe: 1, preauth: 3, install_base: 1, embedding: 0, legacy_tail: 2, vendor_lag: 2}
  surfaces: [mgmt-plane, http-parsing]
  aliases: ["Expressway", "Expressway Select"]
  cpe: ["cisco:expressway"]   # TODO(verify)
  kev: [["cisco", "expressway"]]
  inventory: {}
  embeds:
    - {component: php, evidence: "Cisco CSCwx37062: Expressway and Expressway Select affected, Critical, fixed in 15.5.21, no workaround (reported 2026-10-22)", confirmed: false}

symantec-sepm:
  name: Symantec Endpoint Protection Manager
  ecosystem: mgmt-server
  priors: {memory_unsafe: 1, preauth: 2, install_base: 1, embedding: 0, legacy_tail: 3, vendor_lag: 2}
  surfaces: [mgmt-plane, http-parsing]
  aliases: ["SEPM", "Symantec Endpoint Protection Manager"]
  cpe: ["broadcom:symantec_endpoint_protection_manager"]   # TODO(verify)
  kev: [["broadcom|symantec", "endpoint protection"]]
  inventory: {software: ["symantec endpoint protection manager"]}
  embeds:
    - {component: php, evidence: "Broadcom advisory 39421: SEPM listed Affected by PHP2Shell (2026-10-22)", confirmed: false}

cb-app-control:
  name: Carbon Black App Control Server
  ecosystem: mgmt-server
  priors: {memory_unsafe: 1, preauth: 2, install_base: 1, embedding: 0, legacy_tail: 2, vendor_lag: 1}
  surfaces: [mgmt-plane, http-parsing]
  aliases: ["App Control Server", "Carbon Black App Control"]
  cpe: ["vmware:carbon_black_app_control"]   # TODO(verify)
  kev: [["vmware|broadcom", "carbon black app control"]]
  inventory: {software: ["carbon black app control"]}
  embeds:
    - {component: php, evidence: "Broadcom advisories 39404/39411: App Control Server Affected; updated-PHP builds 8.12.2 and 8.13.2 (2026-10-22)", confirmed: false}
```

On `netscaler`, add:

```yaml
  embeds:
    - {component: php, evidence: "SINGLE SECONDARY SOURCE: tracker lists NetScaler management interfaces as not fixed for PHP2Shell (2026-10-23). No Citrix advisory seen yet.", confirmed: false}
```

`mgmt-server` is a new ecosystem value. Do **not** add it to `LIBRARY_ECOSYSTEMS` in `app/inventory.py`, because absence from host inventory is meaningful for it.

Keep `appliances.yaml` `embeds` as it is. It answers a different question: does your specific box contain X? That drives exposure. Document the difference in the README:

- **catalog `embeds`** = the product line bundles X, which drives *likelihood*
- **`appliances.yaml` `embeds`** = our deployed box contains X, which drives *exposure*

### 2b. Scoring (`app/scoring.py`, `config/scoring.yaml`)

Add to `scoring.yaml`:

```yaml
weights:
  prior: 0.20
  activity: 0.25
  spillover: 0.15
  exploit: 0.25
  inherited: 0.15
half_life_days:
  # ...existing...
  inherited: 45          # vendor fixes for bundled components lag; decay slower than activity
inherited:
  unconfirmed_edge_weight: 0.6
  lag_factor_min: 0.5    # lag_factor = min + (1 - min) * vendor_lag / 3
```

In `score_all`, build a reverse index once: upstream component → list of `(host_component, edge)` from the catalog `embeds`. For each signal on component X, compute the same per-signal activity value `a` already computed for the direct term (`sev_weight(cvss)` plus the emergency/PoC/embargo bonuses), before decay and confidence. Then, for each host H that embeds X:

```
edge_w   = 1.0 if edge.confirmed else cfg.inherited.unconfirmed_edge_weight
lag      = min + (1 - min) * H.priors.vendor_lag / 3     # vendor_lag missing -> 0
contrib  = a * decay(age, hl.inherited) * confidence * edge_w * lag
inherited[H] += contrib
```

Term value: `saturate(inherited[H])`.

- Add a driver with `kind: "inherited"` and the label `"{X.name} {cve or 'signal'} bundled in {H.name}"`, followed by `" (unconfirmed edge)"` when the edge isn't confirmed.
- **Do not inherit exploitation.** Exploitability of the bundled component often differs inside the product: Palo Alto scored PHP2Shell on PAN-OS as availability-only, CVSS-B 8.7. Add a comment saying this.
- **No self-edges.** If H embeds X and X == H, skip it.

In the templates:

- **Detail panel** (`partials/detail.html`): iterate `r.points` in a fixed order `['prior','activity','spillover','inherited','exploit']`, not the hardcoded four. Style the `.kind-inherited` driver label with `--accent`. Keep it sparing: it's a one-line label, not a fill.
- **Forecast table:** no change.

### 2c. Proposed edges from intel (LLM proposes, human disposes)

Vendor advisories are exactly where new dependency edges show up ("Product A is affected because it bundles PHP"). Capture them as **proposals only**.

- `app/llm.py` tool schema: add `upstream_components`, an array of the catalog-ID enum. Description: "If the document says a product is affected because it bundles or embeds another component, list the bundled component here; list the product itself in components."
- Validate it in `validate_findings` with the same catalog filter as `components`.
- Add one line to `EXTRACT_SYSTEM`'s rules covering `upstream_components`, with the same "do not guess" standard.
- New table in `app/db.py`:
  ```sql
  CREATE TABLE IF NOT EXISTS embed_candidates (
    host TEXT NOT NULL, upstream TEXT NOT NULL, first_seen TEXT, last_seen TEXT,
    mentions INTEGER NOT NULL DEFAULT 1, example_url TEXT, evidence TEXT,
    PRIMARY KEY (host, upstream));
  ```
- In `pipeline.apply_findings`, for each (host in `components`) × (upstream in `upstream_components`) pair, upsert a row. Skip pairs that already exist in the catalog `embeds`.
- New dashboard panel under "Not in the catalog", titled **"Proposed dependency edges"**. Columns: host, bundles, mentions, last seen, evidence link. Add an empty state. There is **no** "apply" button: a human edits `components.yaml`. Say so in the panel subtitle.
- Brief prompt (`BRIEF_SYSTEM`): add the rule "For inherited drivers, name the bundled upstream component and say whether the evidence is an unconfirmed edge."

### Phase 2 tests

- A signal on `php` raises `panos.points.inherited` above 0, and leaves `nginx.points.inherited` at 0.
- With the edge set to `confirmed: true`, the inherited points are higher than with the same edge unconfirmed.
- `vendor_lag: 3` yields higher inherited points than `vendor_lag: 0`.
- A KEV signal on `php` does **not** change `panos.points.exploit`.
- `sum(points) ≈ likelihood` still holds with 5 terms.
- `validate_findings` drops an `upstream_components` entry that isn't a catalog ID.
- `apply_findings` creates an `embed_candidates` row, and skips it if the edge is already in the catalog.

---

## Phase 3: Baseline-relative activity (stop rewarding chronic churn)

**Why.** ImageMagick and libxml2 ship CVSS 9.x memory bugs every month. Raw-count activity pins them near the top forever, which is noise. The forecast should react to a *change in rate*, not the level.

`scoring.yaml`:

```yaml
activity_baseline:
  recent_window_days: 30
  baseline_window_days: 180      # baseline = signals aged recent_window..baseline_window
  beta: 1.0                      # how much of the expected mass to subtract
  min_history_days: 150          # below this, beta is forced to 0 (cold start)
```

In `score_all`, per component:

```
W, B = recent_window_days, baseline_window_days
R_base   = Σ over signals with age < W of  sev_weight(cvss) * conf * decay(age, hl.activity)
R_bonus  = Σ over signals with age < W of  (emergency/poc/embargo bonuses) * conf * decay(age, hl.activity)
B_mass   = Σ over signals with W ≤ age < B of  sev_weight(cvss) * conf          # no decay
expected = B_mass * W / (B - W)
activity = saturate( max(0, R_base - beta * expected) + R_bonus )
```

- **Bonuses are never baseline-subtracted.** An emergency release is anomalous by definition.
- **History coverage:** `score_all` gains an optional `history_days: int | None` parameter. If it is `None` or below `min_history_days`, use `beta = 0` and set `result["baseline_ready"] = False`. `pipeline.job_score_sync` passes `history_days` computed from a new kv key, `nvd_history_from` (an ISO date, written by the backfill script and by the first NVD run).
- **Breakdown fields:** add `activity_recent`, `activity_expected`, and `activity_ratio` (recent / expected, or `null` if expected == 0).
- **Detail panel:** under the terms, show "N.N× its usual CVE rate" when the ratio is not null and ≥ 1.5. Show "baseline warming up" in `--muted` when `baseline_ready` is false.
- `max_signal_age_days` must stay ≥ `baseline_window_days`. Assert this at config load and fail loudly.

New script, `scripts/backfill_nvd.py`:

- Usage: `python -m scripts.backfill_nvd --days 180`
- Walks backward in ≤119-day windows. Reuses `process_nvd_page` and the pagination loop from `collect_nvd`; refactor that loop into a shared function rather than copying it.
- Respects the NVD rate-limit pause.
- Writes kv `nvd_history_from` as the earliest window start.
- Idempotent: signals already upsert on their unique key.
- Prints totals per window.
- Add `TODO(verify)` next to the NVD date format and the 120-day max window. Both came from memory, not from current NVD docs.

### Phase 3 tests

- **Chronic churn:** component A has 6 signals at CVSS 9.0 every 30 days for 180 days, and component B has the same 6 signals only in the last 30 days. With `history_days=180`, B's activity points are clearly greater than A's.
- **Cold start:** with `history_days=None`, A and B have equal activity, and `baseline_ready` is false.
- An emergency-flagged signal on A still raises A's activity above A's own non-emergency baseline case.
- `activity_ratio` is null when there's no baseline mass.

---

## Phase 4: "Exploited now" panel (separate exploitation pressure from discovery pressure)

**Why.** Recent KEV additions landed mostly outside the catalog: Plex, Ahsay, Atlassian, Collabora/Nextcloud, Siemens, SiteGuard. The ranked forecast models *discovery pressure* on foundational components. Attackers' current entry points are a separate question, so show them separately rather than forcing them into the ranking.

- `app/db.py`: add `exploited_recent(days=30)`. It returns KEV intel items from the last N days, plus LLM signals with `exploitation='confirmed'`, deduplicated by CVE, newest first. Each row includes the mapped component ID or `null`.
- `app/views.py`: add `exploited` to `dashboard_context`.
- Dashboard: a new panel to the right of the forecast/detail split, or stacked under it on narrow screens. Title: **"Exploited in the last 30 days"**, subtitle "CISA KEV and confirmed reports; includes products outside the catalog". Columns: date, CVE (link), vendor/product, catalog component, or "not in catalog" in `--muted`. Show 20 rows maximum and add an empty state.
- No scoring change in this phase.

### Phase 4 test

- With one mapped and one unmapped KEV item seeded, `exploited_recent` returns both, and the unmapped one has `component: None`.

---

## Phase 5: Seed and demo corrections (`scripts/seed_demo.py`)

Use **only** these facts. Each URL is the source to put on the signal.

**Update the existing PHP2Shell rows**

- Keep `exploitation: "attempts"`. Do not use `"confirmed"`: as of 2026-10-23 no successful compromise had been confirmed, and neither CVE was in KEV.
- Append to the evidence: "Attempts seen from 2026-10-17 (Amazon), before the patch. VulnCheck reports a working ASLR-bypass exploit against unpatched 8.4."
- Sources: https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/ and https://labs.beazley.security/advisories/BSL-A1233

**Add these signals**

| component | cve | date | cvss | surfaces | exploitation | flags | conf | url | evidence |
|---|---|---|---|---|---|---|---|---|---|
| php | CVE-2026-115560 | 2026-10-23 | None | [session-state, serialization, multipart-upload] | none | — | 0.85 | https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html | Third PHP RCE path: session upload progress plus runtime switch of serialize_handler to php before session_start(). Not fixed by the Oct 21 releases; fix in regular release. Mitigation: session.upload_progress.enabled=0. |
| panos | "" | 2026-10-22 | None | [mgmt-plane] | none | — | 0.85 | https://www.helpnetsecurity.com/2026/10/22/php2shell-vulnerability-fortinet-cisco-palo-alto-networks/ | Vendor: all PAN-OS 10.2-12.2 and Panorama affected by PHP2Shell (bundled PHP), no fix ETA; scored CVSS-B 8.7 availability-only; restrict mgmt interface. |
| cisco-expressway | "" | 2026-10-22 | None | [mgmt-plane] | none | — | 0.8 | https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/ | Expressway and Expressway Select affected by PHP2Shell (CSCwx37062), Critical, fixed in 15.5.21, no workaround. |
| f5-bigip | "" | 2026-10-23 | None | [mgmt-plane] | none | — | 0.7 | https://mallory.ai/blog/php-rce-rapid-response | Configuration utility affected by PHP2Shell per K000163821 (secondary report), not fixed. |

Leave `emergency`, `poc_public` and `embargo_broken` false on the four new rows. CVSS stays `None` everywhere a source didn't state a base score for that product.

**Demo appliances.** Keep the existing demo ADC pair. Add:

```python
{"name": "Demo Panorama", "component": "panos", "count": 1, "internet_facing": 0,
 "criticality": "critical", "embeds": ["php"], "evidence": "demo entry"}
```

**Sample brief.** Replace `SAMPLE_BRIEF` so it:

- **Removes** the claim that PHP 7.4 "gets no upstream fix". Correct version: "7.4 has only minimal source backports from the PHP team (no official release); distro and LTS vendors, cPanel and Plesk ship builds."
- Mentions CVE-2026-115560 and the one-line INI mitigation [verified: seed].
- Mentions PAN-OS/Panorama inheriting PHP2Shell with no fix ETA [verified: seed], and that the edge is unconfirmed until the vendor advisory is checked.
- Keeps the "hand-written for the demo" first line and stays under 250 words.

**Acceptance.** In the seeded demo:

- `panos` shows a non-zero inherited term, with a "PHP … bundled in Palo Alto PAN-OS (unconfirmed edge)" driver.
- The "Proposed dependency edges" panel shows its empty state, since the seed doesn't go through Claude.
- The "Exploited in the last 30 days" panel lists the seeded KEV-flagged Windows row.

---

## Phase 6 (stretch; ask before starting): OSV collector for package-level parsers

**Why.** The IP-canonicalization activity lives in npm packages (ip-address, fast-uri). The catalog can't see them.

Proposed approach (endpoints from memory, **all TODO(verify)**):

- Pull per-ecosystem OSV dumps (e.g. `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`), or query `https://api.osv.dev/v1/query` per tracked package.
- Track an allowlist of packages in a new `config/packages.yaml`, mapped to catalog components or to new `ecosystem: package` components.

Do not start this phase without confirmation. It adds network volume and a larger design surface.

---

## Phase 7: Docs, changelog, backtest comparison

- **`CHANGELOG.md`**: create it with a `0.2.0` entry covering the rename, the inherited term, baseline-relative activity, the exploited-now panel, the seed corrections, and the weight rebalance. List the new and old weights side by side.
- **README:**
  - Update the architecture diagram: add the inherited edge and the embed-candidates flow.
  - Update the scoring section to five terms with the baseline formula.
  - Document catalog `embeds` vs `appliances.yaml` `embeds`.
  - Document the backfill script.
  - Add a "Known limits" note: the KEV backtest exercises prior, activity and exploit, but not spillover or inherited, since KEV has no surface or dependency labels.
- **Backtest:** if `kev.json` exists, rerun with the same arguments as Phase 0 and save the result to `docs/backtest-0.2.txt`. Report both tables in your final summary. Don't tune weights to win the comparison; just report.
  - Note: the backtest feeds only KEV signals with no history, so baseline subtraction runs in cold-start mode (`beta = 0`). Say so in the report rather than enabling it.

**Final report to the user**

- per-phase status
- test count
- the backtest before/after numbers, or why they're missing
- every `TODO(verify)` you added
- anything in this brief you deviated from, and why
