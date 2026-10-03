"""SQLite persistence layer - thread-safe, zero external dependencies."""
import json
import sqlite3
import threading
import time
import uuid

from config import DB_PATH

_lock = threading.RLock()
_conn = None


def _connect():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
    return _conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    label       TEXT,
    status      TEXT NOT NULL DEFAULT 'queued',   -- queued|running|completed|failed
    progress    INTEGER NOT NULL DEFAULT 0,        -- 0-100
    stage       TEXT,
    config      TEXT,                              -- JSON scan configuration
    summary     TEXT,                              -- JSON: scores, counts, ai_summary
    error       TEXT,
    started_at  REAL,
    finished_at REAL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tests (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,                     -- functional|edge|negative|performance
    endpoint    TEXT,
    method      TEXT,
    status      TEXT NOT NULL,                     -- pass|fail|warn
    expected    TEXT,
    actual      TEXT,
    latency_ms  REAL,
    response_snippet TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL REFERENCES scans(id),
    fingerprint   TEXT NOT NULL,                   -- stable id for monitoring diffing
    category      TEXT NOT NULL,                    -- sqli|xss|auth|headers|open_endpoint|...
    severity      TEXT NOT NULL,                    -- critical|high|medium|low|info
    title         TEXT NOT NULL,
    endpoint      TEXT,
    method        TEXT,
    evidence      TEXT,
    impact        TEXT,
    request       TEXT,                            -- JSON
    response      TEXT,                            -- JSON
    attack_path   TEXT,                            -- JSON list of steps
    exploit_success INTEGER NOT NULL DEFAULT 0,
    ai_explanation TEXT,
    ai_fix        TEXT,
    ai_fix_code   TEXT,
    ai_learning   TEXT,                            -- JSON {mistake, best_practice, why}
    confidence    REAL DEFAULT 0.8,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    finding_id  TEXT,
    message     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    read        INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS monitors (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    interval_s  INTEGER NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    last_run    REAL,
    created_at  REAL NOT NULL
);
"""


def init_db():
    with _lock:
        conn = _connect()
        conn.executescript(SCHEMA)
        conn.commit()


def _new_id():
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------- scans ----
def create_scan(target, label, config):
    sid = _new_id()
    with _lock:
        _connect().execute(
            "INSERT INTO scans (id,target,label,status,config,created_at) VALUES (?,?,?,?,?,?)",
            (sid, target, label, "queued", json.dumps(config), time.time()),
        )
        _connect().commit()
    return sid


def update_scan(sid, **fields):
    if not fields:
        return
    cols, vals = [], []
    for k, v in fields.items():
        cols.append(f"{k}=?")
        vals.append(v if not isinstance(v, (dict, list)) else json.dumps(v))
    with _lock:
        _connect().execute(f"UPDATE scans SET {', '.join(cols)} WHERE id=?", (*vals, sid))
        _connect().commit()


def get_scan(sid):
    with _lock:
        row = _connect().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return _row(row)


def list_scans(limit=50):
    with _lock:
        rows = _connect().execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row(r) for r in rows]


# ---------------------------------------------------------------- tests ----
def add_test(scan_id, t):
    with _lock:
        _connect().execute(
            """INSERT INTO tests
               (id,scan_id,name,kind,endpoint,method,status,expected,actual,latency_ms,response_snippet,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                _new_id(), scan_id, t.get("name"), t.get("kind"), t.get("endpoint"),
                t.get("method"), t.get("status", "pass"), t.get("expected"),
                t.get("actual"), t.get("latency_ms"), t.get("response_snippet"), time.time(),
            ),
        )
        _connect().commit()


def get_tests(scan_id):
    with _lock:
        rows = _connect().execute(
            "SELECT * FROM tests WHERE scan_id=? ORDER BY created_at", (scan_id,)
        ).fetchall()
    return [_row(r) for r in rows]


# ------------------------------------------------------------- findings ----
def add_finding(scan_id, f):
    fid = _new_id()
    with _lock:
        _connect().execute(
            """INSERT INTO findings
               (id,scan_id,fingerprint,category,severity,title,endpoint,method,evidence,
                impact,request,response,attack_path,exploit_success,confidence,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fid, scan_id, f["fingerprint"], f["category"], f["severity"], f["title"],
                f.get("endpoint"), f.get("method"), f.get("evidence"), f.get("impact"),
                _j(f.get("request")), _j(f.get("response")), _j(f.get("attack_path")),
                1 if f.get("exploit_success") else 0, f.get("confidence", 0.8), time.time(),
            ),
        )
        _connect().commit()
    return fid


def update_finding(fid, **fields):
    if not fields:
        return
    cols, vals = [], []
    for k, v in fields.items():
        cols.append(f"{k}=?")
        vals.append(_j(v) if isinstance(v, (dict, list)) else v)
    with _lock:
        _connect().execute(f"UPDATE findings SET {', '.join(cols)} WHERE id=?", (*vals, fid))
        _connect().commit()


def get_findings(scan_id):
    with _lock:
        rows = _connect().execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY created_at", (scan_id,)
        ).fetchall()
    return [_row(r) for r in rows]


def get_finding(fid):
    with _lock:
        row = _connect().execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    return _row(row)


def clear_scan_data(scan_id):
    """Delete findings/tests of a scan (used before monitoring re-runs)."""
    with _lock:
        _connect().execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        _connect().execute("DELETE FROM tests WHERE scan_id=?", (scan_id,))
        _connect().commit()


def finding_fingerprints(scan_id):
    with _lock:
        rows = _connect().execute(
            "SELECT fingerprint,severity FROM findings WHERE scan_id=?", (scan_id,)
        ).fetchall()
    return {r["fingerprint"]: r["severity"] for r in rows}


# --------------------------------------------------------------- alerts ----
def add_alert(scan_id, message, severity, finding_id=None):
    with _lock:
        _connect().execute(
            "INSERT INTO alerts (id,scan_id,finding_id,message,severity,created_at) VALUES (?,?,?,?,?,?)",
            (_new_id(), scan_id, finding_id, message, severity, time.time()),
        )
        _connect().commit()


def list_alerts(limit=30, unread_only=False):
    q = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?"
    if unread_only:
        q = "SELECT * FROM alerts WHERE read=0 ORDER BY created_at DESC LIMIT ?"
    with _lock:
        rows = _connect().execute(q, (limit,)).fetchall()
    return [_row(r) for r in rows]


def mark_alerts_read():
    with _lock:
        _connect().execute("UPDATE alerts SET read=1")
        _connect().commit()


# ------------------------------------------------------------- monitors ----
def upsert_monitor(scan_id, interval_s):
    with _lock:
        existing = _connect().execute(
            "SELECT id FROM monitors WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if existing:
            _connect().execute(
                "UPDATE monitors SET interval_s=?, active=1 WHERE id=?", (interval_s, existing["id"])
            )
        else:
            _connect().execute(
                "INSERT INTO monitors (id,scan_id,interval_s,active,created_at) VALUES (?,?,?,1,?)",
                (_new_id(), scan_id, interval_s, time.time()),
            )
        _connect().commit()


def deactivate_monitor(scan_id):
    with _lock:
        _connect().execute("UPDATE monitors SET active=0 WHERE scan_id=?", (scan_id,))
        _connect().commit()


def get_active_monitors():
    with _lock:
        rows = _connect().execute(
            "SELECT * FROM monitors WHERE active=1 ORDER BY created_at"
        ).fetchall()
    return [_row(r) for r in rows]


def touch_monitor(scan_id):
    with _lock:
        _connect().execute(
            "UPDATE monitors SET last_run=? WHERE scan_id=?", (time.time(), scan_id)
        )
        _connect().commit()


def get_monitor(scan_id):
    with _lock:
        row = _connect().execute(
            "SELECT * FROM monitors WHERE scan_id=? AND active=1", (scan_id,)
        ).fetchone()
    return _row(row)


# ------------------------------------------------------------- helpers ----
def _j(val):
    return json.dumps(val) if val is not None else None


def _row(row):
    if row is None:
        return None
    d = dict(row)
    for key in ("config", "summary", "request", "response", "attack_path", "ai_learning"):
        if d.get(key) and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (ValueError, TypeError):
                pass
    return d


init_db()
