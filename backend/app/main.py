"""
The API. Run with:  uvicorn app.main:app --reload
Then open http://localhost:8000/docs to see and try every endpoint.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db import get_conn, init_db, reset_db


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


@app.get("/api/stats")
def stats():
    """The headline numbers for the dashboard, e.g. '5000 events -> 1 incident'."""
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
        rows = conn.execute("SELECT * FROM incidents ORDER BY start_ts DESC").fetchall()
        return [dict(r) for r in rows]


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
