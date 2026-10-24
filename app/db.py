"""SQLite persistence. Stdlib only; WAL mode so the web app can read while
the worker writes. Swap for Postgres/Timescale if this outgrows one box."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS intel_items (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, url TEXT, title TEXT,
  published_at TEXT, fetched_at TEXT NOT NULL, raw_text TEXT,
  status TEXT NOT NULL DEFAULT 'new',   -- new|extracted|skipped|failed
  error TEXT
);
CREATE INDEX IF NOT EXISTS ix_intel_status ON intel_items(status);

CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  intel_id TEXT NOT NULL, component_id TEXT NOT NULL, cve TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL,                 -- kev|nvd|llm|seed
  surfaces TEXT NOT NULL DEFAULT '[]',
  exploitation TEXT NOT NULL DEFAULT 'unknown',
  kev INTEGER NOT NULL DEFAULT 0, emergency INTEGER NOT NULL DEFAULT 0,
  poc_public INTEGER NOT NULL DEFAULT 0, embargo_broken INTEGER NOT NULL DEFAULT 0,
  cvss REAL, epss REAL, epss_date TEXT,
  confidence REAL NOT NULL DEFAULT 0.7,
  observed_at TEXT NOT NULL, title TEXT, url TEXT, evidence TEXT,
  UNIQUE(intel_id, component_id, cve, origin)
);
CREATE INDEX IF NOT EXISTS ix_signals_comp ON signals(component_id, observed_at);

CREATE TABLE IF NOT EXISTS unmapped (
  name TEXT PRIMARY KEY, source TEXT, first_seen TEXT, last_seen TEXT,
  mentions INTEGER NOT NULL DEFAULT 1, example_url TEXT
);

CREATE TABLE IF NOT EXISTS inventory (
  component_id TEXT PRIMARY KEY, status TEXT NOT NULL,  -- known|none|unknown|declared
  hosts INTEGER NOT NULL DEFAULT 0, internet_facing INTEGER NOT NULL DEFAULT 0,
  critical INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '{}', synced_at TEXT
);

CREATE TABLE IF NOT EXISTS score_snapshots (
  ts TEXT NOT NULL, component_id TEXT NOT NULL, likelihood REAL, exposure REAL,
  exposure_status TEXT, priority REAL, breakdown TEXT,
  PRIMARY KEY (ts, component_id)
);

CREATE TABLE IF NOT EXISTS briefs (
  ts TEXT PRIMARY KEY, model TEXT, body TEXT, input_tokens INTEGER, output_tokens INTEGER
);

CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT, started TEXT, finished TEXT,
  ok INTEGER, detail TEXT
);

CREATE TABLE IF NOT EXISTS llm_usage (
  day TEXT PRIMARY KEY, input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def item_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


class DB:
    def __init__(self, path: str):
        self.path = path
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # --- kv -------------------------------------------------------------
    def get_kv(self, k: str, default: str | None = None) -> str | None:
        with self.conn() as c:
            r = c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
            return r["v"] if r else default

    def set_kv(self, k: str, v: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    # --- intel ----------------------------------------------------------
    def upsert_intel(self, *, id: str, source: str, url: str | None, title: str | None,
                     published_at: str | None, raw_text: str | None, status: str) -> bool:
        """Returns True if the item is new."""
        with self.conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO intel_items(id,source,url,title,published_at,fetched_at,raw_text,status)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (id, source, url, title, published_at, iso(utcnow()), raw_text, status),
            )
            return cur.rowcount == 1

    def pending_intel(self, limit: int) -> list[sqlite3.Row]:
        with self.conn() as c:
            return c.execute(
                "SELECT * FROM intel_items WHERE status='new' ORDER BY published_at DESC LIMIT ?", (limit,)
            ).fetchall()

    def mark_intel(self, id: str, status: str, error: str | None = None) -> None:
        with self.conn() as c:
            c.execute("UPDATE intel_items SET status=?, error=? WHERE id=?", (status, error, id))

    # --- signals --------------------------------------------------------
    def add_signal(self, *, intel_id: str, component_id: str, origin: str, observed_at: str,
                   cve: str = "", surfaces: list[str] | None = None, exploitation: str = "unknown",
                   kev: bool = False, emergency: bool = False, poc_public: bool = False,
                   embargo_broken: bool = False, cvss: float | None = None, confidence: float = 0.7,
                   title: str | None = None, url: str | None = None, evidence: str | None = None) -> None:
        with self.conn() as c:
            c.execute(
                """INSERT INTO signals(intel_id,component_id,cve,origin,surfaces,exploitation,kev,emergency,
                   poc_public,embargo_broken,cvss,confidence,observed_at,title,url,evidence)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(intel_id,component_id,cve,origin) DO UPDATE SET
                     surfaces=excluded.surfaces, exploitation=excluded.exploitation, kev=excluded.kev,
                     emergency=excluded.emergency, poc_public=excluded.poc_public,
                     embargo_broken=excluded.embargo_broken, cvss=COALESCE(excluded.cvss, signals.cvss),
                     confidence=excluded.confidence, evidence=COALESCE(excluded.evidence, signals.evidence)""",
                (intel_id, component_id, cve or "", origin, json.dumps(surfaces or []), exploitation,
                 int(kev), int(emergency), int(poc_public), int(embargo_broken), cvss, confidence,
                 observed_at, title, url, evidence),
            )

    def tag_signals_for_intel(self, intel_id: str, surfaces: list[str], confidence: float) -> int:
        with self.conn() as c:
            cur = c.execute("UPDATE signals SET surfaces=?, confidence=MAX(confidence, ?) WHERE intel_id=?",
                            (json.dumps(surfaces), confidence, intel_id))
            return cur.rowcount

    def signals_since(self, since_iso: str) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM signals WHERE observed_at >= ? ORDER BY observed_at DESC",
                             (since_iso,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["surfaces"] = json.loads(d["surfaces"] or "[]")
            for b in ("kev", "emergency", "poc_public", "embargo_broken"):
                d[b] = bool(d[b])
            out.append(d)
        return out

    def cves_needing_epss(self, since_iso: str, stale_before: str) -> list[str]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT DISTINCT cve FROM signals WHERE cve LIKE 'CVE-%' AND observed_at >= ? "
                "AND (epss_date IS NULL OR epss_date < ?)", (since_iso, stale_before)).fetchall()
        return [r["cve"] for r in rows]

    def set_epss(self, cve: str, epss: float, date: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE signals SET epss=?, epss_date=? WHERE cve=?", (epss, date, cve))

    # --- unmapped -------------------------------------------------------
    def note_unmapped(self, name: str, source: str, url: str | None = None) -> None:
        name = name.strip()[:120]
        if not name:
            return
        now = iso(utcnow())
        with self.conn() as c:
            c.execute(
                """INSERT INTO unmapped(name,source,first_seen,last_seen,mentions,example_url)
                   VALUES(?,?,?,?,1,?) ON CONFLICT(name) DO UPDATE SET
                   last_seen=excluded.last_seen, mentions=unmapped.mentions+1""",
                (name, source, now, now, url))

    def top_unmapped(self, limit: int = 15) -> list[sqlite3.Row]:
        with self.conn() as c:
            return c.execute("SELECT * FROM unmapped ORDER BY mentions DESC, last_seen DESC LIMIT ?",
                             (limit,)).fetchall()

    # --- inventory ------------------------------------------------------
    def replace_inventory(self, inv: dict[str, dict]) -> None:
        now = iso(utcnow())
        with self.conn() as c:
            c.execute("DELETE FROM inventory")
            for cid, v in inv.items():
                c.execute("INSERT INTO inventory VALUES(?,?,?,?,?,?,?)",
                          (cid, v["status"], v.get("hosts", 0), v.get("internet_facing", 0),
                           v.get("critical", 0), json.dumps(v.get("detail", {})), now))

    def inventory(self) -> dict[str, dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM inventory").fetchall()
        return {r["component_id"]: {**dict(r), "detail": json.loads(r["detail"])} for r in rows}

    # --- scores ---------------------------------------------------------
    def write_snapshot(self, ts: str, results: list[dict]) -> None:
        with self.conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO score_snapshots VALUES(?,?,?,?,?,?,?)",
                [(ts, r["component_id"], r["likelihood"], r["exposure"], r["exposure_status"],
                  r["priority"], json.dumps(r)) for r in results])

    def latest_snapshot(self) -> tuple[str | None, list[dict]]:
        with self.conn() as c:
            r = c.execute("SELECT MAX(ts) AS ts FROM score_snapshots").fetchone()
            if not r or not r["ts"]:
                return None, []
            rows = c.execute("SELECT breakdown FROM score_snapshots WHERE ts=? ORDER BY priority DESC",
                             (r["ts"],)).fetchall()
        out = [json.loads(x["breakdown"]) for x in rows]
        return r["ts"], sorted(out, key=lambda d: d.get("rank", 0))

    def snapshot_before(self, ts_iso: str) -> dict[str, float]:
        """priority per component from the newest snapshot at or before ts_iso."""
        with self.conn() as c:
            r = c.execute("SELECT MAX(ts) AS ts FROM score_snapshots WHERE ts <= ?", (ts_iso,)).fetchone()
            if not r or not r["ts"]:
                return {}
            rows = c.execute("SELECT component_id, priority FROM score_snapshots WHERE ts=?",
                             (r["ts"],)).fetchall()
        return {x["component_id"]: x["priority"] for x in rows}

    # --- briefs / runs / usage -----------------------------------------
    def save_brief(self, model: str, body: str, tin: int, tout: int) -> None:
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO briefs VALUES(?,?,?,?,?)", (iso(utcnow()), model, body, tin, tout))

    def latest_brief(self) -> sqlite3.Row | None:
        with self.conn() as c:
            return c.execute("SELECT * FROM briefs ORDER BY ts DESC LIMIT 1").fetchone()

    def start_run(self, job: str) -> int:
        with self.conn() as c:
            return c.execute("INSERT INTO runs(job,started) VALUES(?,?)", (job, iso(utcnow()))).lastrowid

    def finish_run(self, run_id: int, ok: bool, detail: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE runs SET finished=?, ok=?, detail=? WHERE id=?",
                      (iso(utcnow()), int(ok), detail[:2000], run_id))

    def last_runs(self) -> list[sqlite3.Row]:
        with self.conn() as c:
            return c.execute(
                "SELECT r.* FROM runs r JOIN (SELECT job, MAX(id) AS id FROM runs GROUP BY job) m ON r.id=m.id "
                "ORDER BY r.job").fetchall()

    def add_usage(self, tin: int, tout: int) -> None:
        day = utcnow().date().isoformat()
        with self.conn() as c:
            c.execute("""INSERT INTO llm_usage(day,input_tokens,output_tokens,calls) VALUES(?,?,?,1)
                         ON CONFLICT(day) DO UPDATE SET input_tokens=input_tokens+excluded.input_tokens,
                         output_tokens=output_tokens+excluded.output_tokens, calls=calls+1""",
                      (day, tin, tout))

    def usage_today(self) -> int:
        with self.conn() as c:
            r = c.execute("SELECT input_tokens+output_tokens AS t FROM llm_usage WHERE day=?",
                          (utcnow().date().isoformat(),)).fetchone()
            return int(r["t"]) if r else 0
