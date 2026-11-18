import datetime
import json
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  processed_at TEXT,
  verdict TEXT,
  details TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  new_cves INTEGER DEFAULT 0,
  updated TEXT DEFAULT '[]',
  alerts INTEGER DEFAULT 0,
  status TEXT,
  message TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sent_at TEXT NOT NULL,
  cve_id TEXT,
  package TEXT,
  subject TEXT,
  ok INTEGER,
  error TEXT
);
"""


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class StateStore:
    def __init__(self, path):
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def processed_cves(self):
        rows = self.conn.execute("SELECT cve_id FROM cves").fetchall()
        return {row["cve_id"] for row in rows}

    def mark_processed(self, cve_id, verdict, details=None, first_seen=None):
        self.conn.execute(
            "INSERT INTO cves (cve_id, first_seen, processed_at, verdict, details) VALUES (?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET processed_at=excluded.processed_at, "
            "verdict=excluded.verdict, details=excluded.details",
            (
                cve_id,
                first_seen or utcnow(),
                utcnow(),
                verdict,
                json.dumps(details, ensure_ascii=False) if details is not None else None,
            ),
        )
        self.conn.commit()

    def record_run(self, started_at, status, message="", new_cves=0, updated=None, alerts=0):
        cursor = self.conn.execute(
            "INSERT INTO runs (started_at, finished_at, new_cves, updated, alerts, status, message) "
            "VALUES (?,?,?,?,?,?,?)",
            (started_at, utcnow(), new_cves, json.dumps(updated or [], ensure_ascii=False), alerts, status, message),
        )
        self.conn.commit()
        return cursor.lastrowid

    def record_alert(self, subject, cve_id=None, package=None, ok=True, error=None):
        self.conn.execute(
            "INSERT INTO alerts (sent_at, cve_id, package, subject, ok, error) VALUES (?,?,?,?,?,?)",
            (utcnow(), cve_id, package, subject, 1 if ok else 0, error),
        )
        self.conn.commit()

    def recent_runs(self, limit=10):
        return self.conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def recent_alerts(self, limit=10):
        return self.conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def stats(self):
        total = self.conn.execute("SELECT COUNT(*) AS c FROM cves").fetchone()["c"]
        rows = self.conn.execute("SELECT verdict, COUNT(*) AS c FROM cves GROUP BY verdict").fetchall()
        return {"cves_total": total, "by_verdict": {row["verdict"]: row["c"] for row in rows}}

    def close(self):
        self.conn.close()
