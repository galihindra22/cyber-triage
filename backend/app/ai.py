"""
AI SUMMARY (chunk 6)
====================
The rules already found the attack. The AI's only job is to WRITE the
Bahasa summary of it. It never decides what is an attack and never writes
the recommended actions (those come from playbook.csv).

If Ollama is not running or fails, we fall back to a plain template,
so the demo never shows an empty box.
"""
import json
import os
import urllib.request

from .db import get_conn

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
SEV = {"critical": "kritis", "high": "tinggi", "medium": "sedang", "low": "rendah"}

PROMPT = """Tulis ringkasan insiden keamanan siber dalam Bahasa Indonesia formal.
Aturan:
- 4 sampai 5 kalimat, hanya berdasarkan data di bawah, jangan menambah fakta, jangan memberi rekomendasi.
- Ceritakan berurutan dari kejadian paling awal sampai paling akhir.
- Sebutkan jam mulai dan jam akhir, akun yang dipakai, dan dampak pada genset.

Insiden berlangsung pukul {start} sampai {end}.
Data (urut waktu):
{facts}
"""


def load_incident(conn, incident_id):
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    alerts = conn.execute(
        "SELECT a.*, m.name AS technique_name FROM alerts a "
        "LEFT JOIN mitre_techniques m ON m.technique_id = a.technique_id "
        "WHERE a.incident_id=? ORDER BY a.ts, a.id", (incident_id,)).fetchall()
    return inc, alerts


def _distinct(alerts):
    seen, out = set(), []
    for a in alerts:
        if a["title"] not in seen:
            seen.add(a["title"])
            out.append(a)
    return out


def build_prompt(inc, alerts):
    facts = "\n".join(f"- {a['ts'][11:16]} | {a['title']} ({a['technique_name']})"
                      for a in _distinct(alerts))
    return PROMPT.format(start=inc["start_ts"][11:16], end=inc["end_ts"][11:16], facts=facts)


def template_summary(inc, alerts):
    """Used when the AI is unavailable. Plain, correct, no AI."""
    steps = " ".join(f"Pukul {a['ts'][11:16]}: {a['title']}." for a in _distinct(alerts))
    return (f"Sistem mendeteksi serangan berantai dengan tingkat keparahan "
            f"{SEV.get(inc['severity'], inc['severity'])}, berlangsung pukul "
            f"{inc['start_ts'][11:16]} sampai {inc['end_ts'][11:16]}. {steps}")


def _ollama_stream(prompt):
    body = json.dumps({
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": True,
        "keep_alive": "30m",
        "options": {"temperature": 0.2, "num_predict": 200},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        for line in resp:
            if not line.strip():
                continue
            data = json.loads(line)
            if data.get("response"):
                yield data["response"]
            if data.get("done"):
                break


def stream_summary(incident_id):
    """Yields the summary piece by piece (so the screen types it live), then saves it."""
    with get_conn() as conn:
        inc, alerts = load_incident(conn, incident_id)
    if not inc:
        yield "Insiden tidak ditemukan."
        return
    text = ""
    try:
        for piece in _ollama_stream(build_prompt(inc, alerts)):
            text += piece
            yield piece
    except Exception:
        pass                      # Ollama off or too slow -> fall back below
    if not text.strip():
        text = template_summary(inc, alerts)
        yield text
    with get_conn() as conn:
        # Only save if this is still the SAME incident (a newer run may have replaced it).
        conn.execute("UPDATE incidents SET summary=? WHERE id=? AND created_at=?",
                     (text.strip(), incident_id, inc["created_at"]))
