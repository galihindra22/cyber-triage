"""
DETECTION RULES (chunk 4)
=========================
Each rule looks through the events and raises an ALERT when something is suspicious.
These are simple, readable rules on purpose: a unit can understand and tune them.

R001 Brute force           many failed logins from one IP        -> T1110
R002 Login after guessing  network login from an IP that just guessed passwords -> T1078
R003 Remote login to OT-adjacent host  (RDP/network logon to SCADA/GEN hosts)   -> T1021
R004 Unknown outside link  connection from inside to an outside IP -> T1566 (simplified)
R005 Unauthorized OT write a Modbus WRITE from a machine that is not the operator HMI -> T0855
R006 Abnormal setpoint     generator setpoint far outside normal   -> T0836
R007 Generator stop        STOP command from an unauthorized machine -> T0831
"""
import json
from collections import Counter
from datetime import datetime, timedelta

from . import config as C


def _t(e):
    return datetime.fromisoformat(e["ts"])


def _details(e):
    return json.loads(e["details"]) if e["details"] else {}


def _top(values):
    return Counter(values).most_common(1)[0][0]


def _alert(ts, rule_id, title, severity, technique, host=None, user=None, src_ip=None, events=()):
    return {"ts": ts, "rule_id": rule_id, "title": title, "severity": severity,
            "technique_id": technique, "host": host, "user": user, "src_ip": src_ip,
            "event_ids": json.dumps([e["id"] for e in events])}


# ---- R001: brute force --------------------------------------------------
def find_bursts(events):
    """Groups failed logins from the same IP into bursts (gap > 5 min starts a new burst)."""
    by_ip = {}
    for e in events:
        if e["action"] == "login" and e["outcome"] == "failure" and e["src_ip"]:
            by_ip.setdefault(e["src_ip"], []).append(e)
    bursts = []
    for ip, evs in by_ip.items():
        cluster = [evs[0]]
        for e in evs[1:]:
            if (_t(e) - _t(cluster[-1])).total_seconds() <= C.BF_GAP_SECONDS:
                cluster.append(e)
            else:
                bursts.append((ip, cluster)); cluster = [e]
        bursts.append((ip, cluster))
    return [(ip, c) for ip, c in bursts if len(c) >= C.BF_MIN_FAILURES]


def rule_brute_force(bursts):
    out = []
    for ip, c in bursts:
        host, user = _top(e["host"] for e in c), _top(e["user"] for e in c)
        out.append(_alert(c[0]["ts"], "R001",
                          f"Percobaan login gagal beruntun ({len(c)}x) dari {ip} ke {host}",
                          "high", "T1110", host, user, ip, c))
    return out


# ---- R002: successful network login right after a brute-force burst ------
def rule_login_after_bruteforce(events, bursts):
    out = []
    for e in events:
        if e["action"] == "login" and e["outcome"] == "success" and _details(e).get("logon_type") == 3:
            for ip, c in bursts:
                gap = (_t(e) - _t(c[-1])).total_seconds()
                if e["src_ip"] == ip and 0 <= gap <= C.AFTER_BF_SECONDS:
                    out.append(_alert(e["ts"], "R002",
                               f"Login berhasil setelah tebak password: akun {e['user']} dari {ip} ke {e['host']}",
                               "critical", "T1078", e["host"], e["user"], ip, [e]))
                    break
    return out


# ---- R003: remote login into a sensitive (OT-adjacent) host --------------
def rule_remote_login_sensitive(events):
    out = []
    for e in events:
        if (e["action"] == "login" and e["outcome"] == "success"
                and _details(e).get("logon_type") in (3, 10)
                and e["host"].startswith(C.SENSITIVE_HOST_PREFIXES)):
            out.append(_alert(e["ts"], "R003",
                       f"Login jarak jauh ke host sensitif {e['host']} oleh {e['user']} dari {e['src_ip']}",
                       "high", "T1021", e["host"], e["user"], e["src_ip"], [e]))
    return out


# ---- R004: connection to an unknown outside address -----------------------
def rule_external_connection(events):
    groups = {}
    for e in events:
        if (e["source"] == "firewall" and e["outcome"] == "allowed"
                and e["dst_ip"] and not e["dst_ip"].startswith(C.INTERNAL_PREFIX)
                and e["dst_ip"] not in C.EXTERNAL_ALLOWLIST):
            groups.setdefault((e["src_ip"], e["dst_ip"]), []).append(e)
    out = []
    for (src, dst), evs in groups.items():
        cluster = [evs[0]]
        for e in evs[1:] + [None]:
            if e and (_t(e) - _t(cluster[-1])).total_seconds() <= C.EXTERNAL_GAP_SECONDS:
                cluster.append(e)
            else:
                out.append(_alert(cluster[0]["ts"], "R004",
                           f"Koneksi keluar ke server luar tidak dikenal: {src} -> {dst} ({len(cluster)}x)",
                           "medium", "T1566", None, None, src, cluster))
                cluster = [e] if e else []
    return out


# ---- R005 / R006 / R007: OT rules -----------------------------------------
def rule_ot(events):
    out = []
    for e in events:
        if e["source"] != "ot_modbus" or not e["action"].startswith("WRITE"):
            continue
        d = _details(e)
        if e["src_ip"] in C.ALLOWED_OT_WRITERS:
            # Operator screen: only flag a crazy setpoint
            if e["action"] == "WRITE_SINGLE_REGISTER" and d.get("reg") == C.SETPOINT_REGISTER:
                v = int(d["value"])
                if not (C.SETPOINT_NORMAL_RANGE[0] <= v <= C.SETPOINT_NORMAL_RANGE[1]):
                    out.append(_alert(e["ts"], "R006",
                               f"Setpoint genset diubah ke {v / 100:.2f} Hz (normal 45-55 Hz)",
                               "critical", "T0836", e["host"], None, e["src_ip"], [e]))
            continue
        # Not the operator screen -> unauthorized
        out.append(_alert(e["ts"], "R005",
                   f"Perintah tulis Modbus dari sumber tidak berwenang {e['src_ip']} ke {e['host']}",
                   "critical", "T0855", e["host"], None, e["src_ip"], [e]))
        if e["action"] == "WRITE_SINGLE_REGISTER" and d.get("reg") == C.SETPOINT_REGISTER:
            v = int(d["value"])
            if not (C.SETPOINT_NORMAL_RANGE[0] <= v <= C.SETPOINT_NORMAL_RANGE[1]):
                out.append(_alert(e["ts"], "R006",
                           f"Setpoint genset diubah ke {v / 100:.2f} Hz (normal 45-55 Hz)",
                           "critical", "T0836", e["host"], None, e["src_ip"], [e]))
        if e["action"] == "WRITE_SINGLE_COIL" and d.get("coil") == C.GENERATOR_STOP_COIL \
                and d.get("value") == "OFF":
            out.append(_alert(e["ts"], "R007",
                       f"Perintah MATI (stop) ke genset {e['host']} dari sumber tidak berwenang {e['src_ip']}",
                       "critical", "T0831", e["host"], None, e["src_ip"], [e]))
    return out


# ---- Run everything -------------------------------------------------------
def detect(conn):
    events = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    bursts = find_bursts(events)
    alerts = (rule_brute_force(bursts)
              + rule_login_after_bruteforce(events, bursts)
              + rule_remote_login_sensitive(events)
              + rule_external_connection(events)
              + rule_ot(events))
    alerts.sort(key=lambda a: a["ts"])
    conn.executemany(
        "INSERT INTO alerts (ts, rule_id, title, severity, technique_id, host, user, src_ip, event_ids) "
        "VALUES (:ts,:rule_id,:title,:severity,:technique_id,:host,:user,:src_ip,:event_ids)", alerts)
    return len(alerts)
