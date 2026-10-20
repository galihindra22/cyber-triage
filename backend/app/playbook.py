"""
PLAYBOOK: what to do for each attack technique.
The advice lives in data/playbook.csv (your brother edits it in Google Sheets).
The AI is NOT used here on purpose: advice must be vetted, not generated.
"""
import csv
from pathlib import Path

PLAYBOOK_CSV = Path(__file__).resolve().parent.parent / "data" / "playbook.csv"


def load_playbook():
    if not PLAYBOOK_CSV.exists():
        return {}
    with open(PLAYBOOK_CSV, newline="", encoding="utf-8") as f:
        return {row["technique_id"]: row for row in csv.DictReader(f)}


def playbook_for(alerts):
    """Advice for the techniques in this incident, in the order they appeared."""
    book, seen, out = load_playbook(), set(), []
    for a in alerts:
        tid = a["technique_id"]
        if tid in book and tid not in seen:
            seen.add(tid)
            out.append({**book[tid], "technique_name": a.get("technique_name")})
    return out
