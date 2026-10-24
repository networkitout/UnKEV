# UnKEV

Emerging-vulnerability forecast for your estate. UnKEV ingests KEV, NVD, EPSS and security news, and uses Claude to turn the news into structured signals. It then ranks catalog components by how likely they are to break soon, scaled by how much of each you actually run, according to your inventory.

The ranking is deterministic and reproducible. Claude extracts facts and writes the daily brief. It never sets a score or a weight.

```
 KEV ──────────┐ deterministic map (vendor/product regex)
 NVD 2.0 ──────┤ deterministic map (CPE, then description aliases)
 RSS/Atom ─────┤ local prefilter ─► Claude: record_findings (forced tool, enums)
 EPSS ─────────┘                         │ validated, off-vocab dropped
                                         ├─► embed_candidates ─► "Proposed dependency edges"
                                         │                        (a human edits components.yaml)
                                         ▼
   "Exploited in the last 30 days" ◄── signals ──► scoring.py ◄── inventory ◄── inventory API / CMDB
   (KEV + confirmed, catalog or not)      ▲           ▲   ▲                 ◄── appliances.yaml (exposure)
                                          │           │   └── components.yaml embeds (inherited term)
      scripts/backfill_nvd.py ────────────┘           └────── nvd_history_from (activity baseline ready?)
                                                      ▼
                                        snapshots ─► dashboard / JSON / CSV
                                                     └──► Claude: daily brief (escaped text)
```

## Quick start (demo, no keys, no network)

```bash
python -m venv .venv && . .venv/bin/activate
pip-compile --generate-hashes -o requirements.txt requirements.in
pip install --require-hashes -r requirements.txt
python -m scripts.seed_demo                 # this week's real signals + synthetic inventory
python -m scripts.render_preview preview.html   # static render, no server
UNKEV_PASSWORD=change-me uvicorn app.main:app --port 8080
```

## Going live

1. `cp .env.example .env`, then set `ANTHROPIC_API_KEY` and `UNKEV_PASSWORD`. `NVD_API_KEY` is optional but raises rate limits about 10x.
2. Point `config/inventory.yaml` at your inventory API and set `mode: api`. Then run `python -m scripts.inventory_probe` until every field resolves (see below).
3. Verify each feed URL in `config/feeds.yaml`. They came from memory.
4. Lock dependencies once with `./lock.sh`. It writes a hash-pinned `requirements.txt` using the same base image as the build.
5. Start it:
   ```bash
   docker compose up -d web worker
   ```
   For the demo instead: `docker compose --profile demo run --rm seed && docker compose up -d web`.

   The containers run with a read-only root filesystem, as a non-root user (uid 10001), with all capabilities dropped and no-new-privileges set. The only writable state is the `/data` volume. Front the web container with your TLS/SSO proxy; it binds to 127.0.0.1 only. If you swap the named volume for a bind mount, `chown 10001` the host directory first.

Egress needed: `api.anthropic.com`, `www.cisa.gov`, `services.nvd.nist.gov`, `api.first.org`, your RSS hosts, and your inventory API.

## Wiring inventory

Exposure comes from whatever returns per-host software or OS records: a CMDB, an asset system, an EDR exposure API. The adapter is config-driven so no route or schema is pinned. Each source declares:

- `path` and `items_path`
- the pagination style
- dotted field paths for host, name, version, OS, internet_facing and criticality

`inventory_probe` prints the raw keys and what each path resolved to, so a wrong path shows up as `None`.

Exposure status means:

| status | meaning |
|---|---|
| known | inventory matched at least one host |
| none | the source covers this kind of thing and found nothing |
| unknown | no source covers it. **This is a visibility gap, not absence.** Libraries such as zlib, Brotli and libarchive default here, because host app inventory doesn't see vendored libraries. |
| declared | only `appliances.yaml` says it's there |

Runtime components such as PHP and Node need per-host *application* inventory, for example Falcon Discover apps. If your inventory only has host/OS records, they will read "unknown".

## Scoring model (`config/scoring.yaml`)

`likelihood` (0-100) is the sum of five weighted terms:

| term | weight | what it measures |
|---|---|---|
| prior | 0.20 | structural risk from `components.yaml`: memory safety, pre-auth parsing, install base, embedding, legacy tail. Analyst estimates; tune with the backtest. |
| activity | 0.25 | CVEs on the component in the last 30 days, weighted by severity, **relative to its own baseline rate** (below). Emergency release, public PoC and broken embargo add bonuses that are never baseline-subtracted. 21-day half-life. |
| spillover | 0.15 | the surface term. When an attack surface (for example `ip-canonicalization`) breaks in one component, every other component sharing that surface gets a decayed bump. 30-day half-life. |
| inherited | 0.15 | the dependency term. When a component breaks, every product whose catalog entry `embeds` it gets a decayed bump, scaled by the product's `vendor_lag` prior and down-weighted while the edge is unconfirmed. 45-day half-life. Exploitation is never inherited: exploitability inside the host product often differs. |
| exploit | 0.25 | the maximum of KEV, confirmed or attempted exploitation, and EPSS. 45-day half-life. |

### Baseline-relative activity

Chronic churn (ImageMagick, libxml2 shipping CVSS 9.x memory bugs every month) used to pin those components near the top forever. Activity now reacts to a change in rate, not the level:

```
recent    = Σ severity × confidence × decay        over signals aged < 30 days
bonuses   = Σ (emergency + PoC + embargo) × conf × decay   over the same signals
baseline  = Σ severity × confidence                over signals aged 30..180 days, undecayed
expected  = baseline × 30 / (180 − 30)
activity  = saturate( max(0, recent − β × expected) + bonuses )
```

β is 1.0 once the signal store covers at least `min_history_days` (150) of NVD history, measured from the kv `nvd_history_from`. Until then β is forced to 0 (cold start), the detail panel shows "baseline warming up", and activity is the raw recent mass. The first NVD run sets `nvd_history_from` to its own start; to warm up immediately:

```bash
python -m scripts.backfill_nvd --days 180   # walks back in ≤119-day windows on publication date, idempotent
```

Mind the Claude budget: backfilled CVEs at or above `llm_tag_min_cvss` are queued for surface tagging like any other. Fresh items are processed first and the daily cap still applies.

The detail panel shows "N.N× its usual CVE rate" when recent/expected is at least 1.5. Every result also carries `activity_recent`, `activity_expected`, `activity_ratio` and `baseline_ready`.

### Two kinds of `embeds`

- **catalog `embeds`** (`components.yaml`): the product line bundles X. Drives *likelihood* through the inherited term. Each edge carries evidence and a `confirmed` flag; flip it only after reading the vendor's own advisory.
- **`appliances.yaml` `embeds`**: our deployed box contains X. Drives *exposure* by adding the appliance's hosts to X.

Claude never writes catalog edges. When extracted intel says a product is affected because it bundles another catalog component, the pair lands in the "Proposed dependency edges" panel; a human decides whether to add it to `components.yaml`.

`priority = likelihood × (0.35 + 0.65 × exposure)`. The floor keeps unknown or low-exposure components visible on the forecast. Every snapshot stores its term points and driver signals, which the detail panel shows.

## Trust boundary (Claude)

Intel is untrusted input:

- Documents are wrapped as data, with control characters stripped and `</document>` neutralized, so a document can't break out of its wrapper.
- The extractor has exactly one tool, forced via `tool_choice`, with no web access or code execution.
- Output is validated against the surface and exploitation enums, the catalog IDs, the batch item refs, a CVE regex, and CVSS bounds.
- The brief is escaped before marker spans are added.
- CSP is `script-src 'self'`.
- Run triggers require `HX-Request` (CSRF under Basic auth).
- A daily token budget caps spend.

Tests in `tests/test_core.py` cover the wrapper escape, schema stripping and XSS cases.

## Backtest

```bash
curl -sSo kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
python -m scripts.backtest kev.json --start 2025-01 --end 2026-10 --k 10
```

The backtest replays KEV month by month. It compares the model against three baselines: install base alone, prior alone, and recency (KEV count in the prior 90 days). Recency is the baseline to beat; if the model doesn't, say so.

**Known limits.** A KEV replay exercises prior, activity and exploit only. KEV has no attack-surface tags and no dependency labels, so spillover and inherited are not tested; that needs the extraction history this app accumulates. The replay also feeds signals with no history, so baseline subtraction runs in cold-start mode (β = 0). Don't enable it there, and don't tune weights to win the comparison.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Verify before trusting

These came from memory and were not verified against live endpoints in this build:

- feed URLs
- NVD date format, `pub`/`lastMod` date parameter names, 120-day window limit and rate limits
- CPE product names on the components added in 0.2 (`f5-bigip`, `cisco-expressway`, `symantec-sepm`, `cb-app-control`)
- EPSS batch limits
- Claude model IDs
- inventory routes and fields (placeholders in `config/inventory.yaml`)

## Roadmap

- Postgres/Timescale for snapshots and Redis Streams for jobs once this outgrows one box.
- Add a CWE-to-surface mapping so KEV and NVD signals carry surfaces without Claude.
- Add a spillover and inherited backtest once around 90 days of extractions exist.
- Add catalog growth from the "not in the catalog" and "Proposed dependency edges" lists.
- Add GitHub Security Advisories and OSV as structured sources.
