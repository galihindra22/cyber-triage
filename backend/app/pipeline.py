"""
THE PIPELINE: fake logs -> events -> alerts -> incidents.

Run from the backend folder (venv active):
    python -m app.pipeline
"""
import json

from . import simulator
from .correlation import correlate
from .db import get_conn, init_db, reset_db
from .detection import detect
from .parser import ingest


def run_pipeline(regenerate=True):
    init_db()
    if regenerate:
        simulator.generate()
    reset_db()
    with get_conn() as conn:
        report = ingest(conn)
        n_alerts = detect(conn)
        n_incidents = correlate(conn)
        n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"files": report, "events": n_events, "alerts": n_alerts, "incidents": n_incidents}


def check_against_truth():
    """Did we find every technique in the answer key?"""
    truth_file = simulator.LOG_DIR / "ground_truth.json"
    if not truth_file.exists():
        return None
    expected = set()
    for step in json.loads(truth_file.read_text(encoding="utf-8")):
        expected |= {t.strip() for t in step["mitre"].split(",")}
    with get_conn() as conn:
        found = {r[0] for r in conn.execute("SELECT DISTINCT technique_id FROM alerts")}
    return expected, found


if __name__ == "__main__":
    result = run_pipeline()
    print("\n=== FILES ===")
    for name, r in result["files"].items():
        print(f"  {name:20s} parsed={r['parsed']:5d} skipped={r['skipped']}")
    print(f"\n{result['events']} events -> {result['alerts']} alerts -> {result['incidents']} incident(s)\n")

    with get_conn() as conn:
        for inc in conn.execute("SELECT * FROM incidents"):
            print(f"INCIDENT #{inc['id']} [{inc['severity'].upper()}] {inc['title']}")
            print(f"  {inc['start_ts']}  ->  {inc['end_ts']}")
            q = ("SELECT a.*, m.name AS tname, m.tactic FROM alerts a "
                 "LEFT JOIN mitre_techniques m ON m.technique_id = a.technique_id "
                 "WHERE incident_id=? ORDER BY ts, a.id")
            for a in conn.execute(q, (inc["id"],)):
                print(f"   {a['ts'][11:]} [{a['severity']:8s}] {a['rule_id']} "
                      f"{a['technique_id']} ({a['tname']}) - {a['title']}")
    chk = check_against_truth()
    if chk:
        expected, found = chk
        print(f"\nAnswer key check: found {len(expected & found)}/{len(expected)} expected techniques"
              + (f"  MISSING: {sorted(expected - found)}" if expected - found else "  (all found)"))
