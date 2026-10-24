# UnKEV

Emerging-vulnerability forecast for your estate. UnKEV ingests KEV, NVD, EPSS and security news, and uses Claude to turn the news into structured signals. It then ranks catalog components by how likely they are to break soon, scaled by how much of each you actually run, according to your inventory.

The ranking is deterministic and reproducible. Claude extracts facts and writes the daily brief. It never sets a score or a weight.

```
 KEV ──────────┐ deterministic map (vendor/product regex)
 NVD 2.0 ──────┤ deterministic map (CPE, then description aliases)
 RSS/Atom ─────┤ local prefilter ─► Claude: record_findings (forced tool, enums)
 EPSS ─────────┘                         │ validated, off-vocab dropped
                                         ▼
                                     signals ──► scoring.py ◄── inventory ◄── inventory API / CMDB
                                                     │                    ◄── appliances.yaml
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

`likelihood` (0-100) is the sum of four weighted terms:

- **prior:** structural risk from `components.yaml`, made up of memory safety, pre-auth parsing, install base, embedding and legacy tail. These are analyst estimates; tune them with the backtest.
- **activity:** recent CVEs on the component, weighted by severity, emergency release, public PoC and broken embargo, with a 21-day half-life.
- **exploit:** the maximum of KEV, confirmed or attempted exploitation, and EPSS, with a 45-day half-life.
- **spillover:** the predictive term. When an attack surface (for example `ip-canonicalization`) breaks in one component, every other component sharing that surface gets a decayed bump. Half-life is 30 days.

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

**Limit:** a KEV replay can't test spillover, because KEV has no surface tags. That needs the extraction history this app accumulates.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Verify before trusting

These came from memory and were not verified against live endpoints in this build:

- feed URLs
- NVD date format, window limit and rate limits
- EPSS batch limits
- Claude model IDs
- inventory routes and fields (placeholders in `config/inventory.yaml`)

## Roadmap

- Postgres/Timescale for snapshots and Redis Streams for jobs once this outgrows one box.
- Add a CWE-to-surface mapping so KEV and NVD signals carry surfaces without Claude.
- Add a spillover backtest once around 90 days of extractions exist.
- Add catalog growth from the "not in the catalog" list.
- Add GitHub Security Advisories and OSV as structured sources.
