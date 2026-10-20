"""
The API. Run with:  uvicorn app.main:app --reload
Then open http://localhost:8000/docs to see and try every endpoint.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse

from .db import get_conn, init_db, reset_db
from .pipeline import run_pipeline
from .ai import stream_summary
from .playbook import playbook_for
from .report import build_report_html


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # runs once when the server starts
    yield


app = FastAPI(title="Cyber Triage API", lifespan=lifespan)

# Lets the Next.js frontend (port 3000) talk to this backend (port 8000).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/pipeline/run")
def pipeline_run(regenerate: bool = True):
    """THE DEMO BUTTON: make fake logs -> parse -> detect -> build incidents."""
    return run_pipeline(regenerate=regenerate)


@app.get("/api/stats")
def stats():
    """The headline numbers for the dashboard, e.g. '5586 events -> 1 incident'."""
    with get_conn() as conn:
        count = lambda t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        return {
            "events": count("events"),
            "alerts": count("alerts"),
            "incidents": count("incidents"),
        }


@app.get("/api/incidents")
def list_incidents():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT i.*, (SELECT COUNT(*) FROM alerts a WHERE a.incident_id = i.id) AS alert_count "
            "FROM incidents i ORDER BY start_ts DESC").fetchall()
        return [dict(r) for r in rows]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int):
    """One incident + its alerts as a timeline, each with its MITRE label."""
    with get_conn() as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        alerts = conn.execute(
            "SELECT a.*, m.name AS technique_name, m.tactic, m.matrix, m.penjelasan_id "
            "FROM alerts a LEFT JOIN mitre_techniques m ON m.technique_id = a.technique_id "
            "WHERE a.incident_id=? ORDER BY a.ts, a.id", (incident_id,)).fetchall()
        alerts = [dict(a) for a in alerts]
        return {**dict(inc), "alerts": alerts, "playbook": playbook_for(alerts)}


@app.post("/api/incidents/{incident_id}/summary")
def incident_summary(incident_id: int):
    """Streams the Bahasa summary (local AI, or a template if the AI is off)."""
    return StreamingResponse(stream_summary(incident_id), media_type="text/plain; charset=utf-8")


@app.get("/api/incidents/{incident_id}/report", response_class=HTMLResponse)
def incident_report(incident_id: int):
    """Printable Bahasa report. Open in browser, then Ctrl+P -> Save as PDF."""
    html = build_report_html(incident_id)
    if html is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return HTMLResponse(html)


@app.get("/api/alerts")
def list_alerts():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY ts, id")]


@app.get("/api/mitre")
def list_mitre():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM mitre_techniques ORDER BY technique_id").fetchall()
        return [dict(r) for r in rows]


@app.post("/api/reset")
def reset():
    """Clear all data (used before replaying the demo)."""
    reset_db()
    return {"status": "cleared"}
