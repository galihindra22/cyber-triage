"""
Database layer. We use plain sqlite3 (built into Python) so there is
nothing extra to learn. One file = one database: backend/data/triage.db
"""
import csv
import sqlite3
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "triage.db"
MITRE_CSV = DATA_DIR / "mitre_map.csv"

# The whole data model in one place.
# Flow: events (raw logs) -> alerts (suspicious things) -> incidents (the story)
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,      -- time, ISO format: 2026-10-19T21:00:00
    source    TEXT NOT NULL,      -- windows_auth | web | firewall | ot_modbus
    host      TEXT,               -- which machine produced the log
    user      TEXT,               -- which account (if any)
    src_ip    TEXT,
    dst_ip    TEXT,
    action    TEXT NOT NULL,      -- login | modbus_write | connection | ...
    outcome   TEXT,               -- success | failure | allowed | blocked
    details   TEXT,               -- extra info as JSON text
    raw       TEXT                -- the original log line, untouched
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,    -- low | medium | high | critical
    status      TEXT NOT NULL DEFAULT 'open',
    start_ts    TEXT,
    end_ts      TEXT,
    summary     TEXT,             -- Bahasa summary written by the AI
    report      TEXT,             -- full Bahasa incident report
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    rule_id     TEXT NOT NULL,    -- which detection rule fired
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    technique_id TEXT,            -- MITRE ID, e.g. T1110
    host        TEXT,
    user        TEXT,
    src_ip      TEXT,
    event_ids   TEXT,             -- JSON list of events that triggered it
    incident_id INTEGER,          -- filled in when grouped into an incident
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    tactic       TEXT,
    matrix       TEXT,            -- enterprise | ics
    penjelasan_id TEXT            -- one-line explanation in Bahasa
);
"""


def get_conn() -> sqlite3.Connection:
    """Open a connection. Rows behave like dicts (row['title'])."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def load_mitre(conn: sqlite3.Connection) -> None:
    """Load the MITRE table from the CSV your brother maintains."""
    if not MITRE_CSV.exists():
        return
    with open(MITRE_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            conn.execute(
                "INSERT OR REPLACE INTO mitre_techniques VALUES (?,?,?,?,?)",
                (row["technique_id"], row["name"], row["tactic"],
                 row["matrix"], row["penjelasan_id"]),
            )


def init_db() -> None:
    """Create tables (if missing) and refresh the MITRE table."""
    DATA_DIR.mkdir(exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        load_mitre(conn)


def reset_db() -> None:
    """Wipe events/alerts/incidents. Used before each demo replay."""
    with get_conn() as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM sqlite_sequence")   # restart numbering at 1
