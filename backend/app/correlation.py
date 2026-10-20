"""
CORRELATION (chunk 5)
=====================
Turns many alerts into INCIDENTS (stories). Two alerts belong together when
they happened close in time AND are linked:
  - same source IP, or
  - the later alert's source is the machine the earlier alert happened ON
    (that's how we follow an attacker from one computer to the next).
We use "union-find": a tiny trick to merge linked alerts into groups.
"""
from datetime import datetime

from . import config as C


def _t(a):
    return datetime.fromisoformat(a["ts"])


def _linked(a, b):
    """a is earlier than or equal to b."""
    if (_t(b) - _t(a)).total_seconds() > C.CORRELATION_WINDOW_SECONDS:
        return False
    if a["src_ip"] and a["src_ip"] == b["src_ip"]:
        return True
    host_ip = C.HOST_IPS.get(a["host"])
    return bool(host_ip and host_ip == b["src_ip"])


def _title(group, techniques):
    ics = [a for a in group if techniques.get(a["technique_id"], {}).get("matrix") == "ics"]
    first_src = group[0]["src_ip"]
    if ics and len(group) > len(ics):
        return (f"Serangan berantai IT ke OT: dari {first_src} hingga perintah tidak sah "
                f"ke {ics[-1]['host']}")
    if len(group) == 1:
        return group[0]["title"]
    return f"Insiden dari {first_src}: {len(group)} peringatan terkait"


def correlate(conn):
    alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY ts, id")]
    techniques = {r["technique_id"]: dict(r) for r in conn.execute("SELECT * FROM mitre_techniques")}

    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for j in range(len(alerts)):
        for i in range(j):
            if _linked(alerts[i], alerts[j]):
                parent[find(i)] = find(j)

    groups = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)

    for group in groups.values():
        group.sort(key=lambda a: a["ts"])
        severity = max((a["severity"] for a in group), key=lambda s: C.SEVERITY_ORDER[s])
        cur = conn.execute(
            "INSERT INTO incidents (title, severity, start_ts, end_ts) VALUES (?,?,?,?)",
            (_title(group, techniques), severity, group[0]["ts"], group[-1]["ts"]))
        conn.executemany("UPDATE alerts SET incident_id=? WHERE id=?",
                         [(cur.lastrowid, a["id"]) for a in group])
    return len(groups)
