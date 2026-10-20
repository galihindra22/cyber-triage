"""
LOG PARSER (chunk 3)
====================
Each log file has its own format. Here we turn every line into ONE
standard "event" so the rest of the system doesn't care where it came from.

Standard event fields:
  ts, source, host, user, src_ip, dst_ip, action, outcome, details(JSON), raw

Lines we can't understand are counted as 'skipped', never crash the run.
"""
import json
import os
import re
from datetime import datetime
from pathlib import Path

from .config import HOST_IPS

LOG_DIR = Path(os.environ.get("STATE_DIR", Path(__file__).resolve().parent.parent / "data")) / "logs"

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _kv(line):
    """'2026-.. HOST key=val key2=val2' -> (time, host, {key: val})"""
    parts = line.split()
    kv = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
    return parts[0], parts[1], kv


def parse_windows(line):
    ts, host, kv = _kv(line)
    return {
        "ts": ts, "source": "windows_auth", "host": host,
        "user": kv["Account"], "src_ip": kv["SrcIP"], "dst_ip": HOST_IPS.get(host),
        "action": "login", "outcome": kv["Result"].lower(),
        "details": {"event_id": int(kv["EventID"]), "logon_type": int(kv["LogonType"])},
        "raw": line,
    }


def parse_firewall(line):
    ts, host, kv = _kv(line)
    return {
        "ts": ts, "source": "firewall", "host": host, "user": None,
        "src_ip": kv["src"], "dst_ip": kv["dst"],
        "action": "connection",
        "outcome": "allowed" if kv["action"] == "ALLOW" else "blocked",
        "details": {"proto": kv["proto"], "dport": int(kv["dport"])},
        "raw": line,
    }


def parse_modbus(line):
    ts, host, kv = _kv(line)
    details = {k: kv[k] for k in ("unit", "reg", "coil", "value", "count") if k in kv}
    return {
        "ts": ts, "source": "ot_modbus", "host": host, "user": None,
        "src_ip": kv["src"], "dst_ip": HOST_IPS.get(host),
        "action": kv["func"], "outcome": kv["result"].lower(),
        "details": details, "raw": line,
    }


# Apache style:  10.10.5.11 - - [19/Oct/2026:19:00:51 +0700] "GET /x HTTP/1.1" 200 47412
WEB_RE = re.compile(
    r'^(\S+) - - \[(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+) [+-]\d{4}\] '
    r'"(\w+) (\S+) HTTP/[\d.]+" (\d+) (\d+)$')


def parse_web(line):
    m = WEB_RE.match(line)
    if not m:
        return None
    ip, d, mon, y, hh, mm, ss, method, path, status, size = m.groups()
    ts = datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss)).isoformat()
    return {
        "ts": ts, "source": "web", "host": "WEB-INTRA-01", "user": None,
        "src_ip": ip, "dst_ip": "10.10.2.15",
        "action": "http_request", "outcome": status,
        "details": {"method": method, "path": path, "bytes": int(size)},
        "raw": line,
    }


# Which parser reads which file. NEW LOG TYPE? Add one line here + one function above.
PARSERS = {
    "windows_auth.log": parse_windows,
    "web_access.log": parse_web,
    "firewall.log": parse_firewall,
    "ot_modbus.log": parse_modbus,
}


def ingest(conn, log_dir=LOG_DIR):
    """Read all log files, save events to the database. Returns a report."""
    events, report = [], {}
    for name, parse in PARSERS.items():
        path = Path(log_dir) / name
        if not path.exists():
            report[name] = {"parsed": 0, "skipped": 0, "missing": True}
            continue
        parsed = skipped = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                ev = parse(line)
            except Exception:
                ev = None
            if ev:
                events.append(ev)
                parsed += 1
            else:
                skipped += 1
        report[name] = {"parsed": parsed, "skipped": skipped}

    events.sort(key=lambda e: e["ts"])   # oldest first, across ALL sources
    conn.executemany(
        "INSERT INTO events (ts, source, host, user, src_ip, dst_ip, action, outcome, details, raw) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(e["ts"], e["source"], e["host"], e["user"], e["src_ip"], e["dst_ip"],
          e["action"], e["outcome"], json.dumps(e["details"]), e["raw"]) for e in events])
    return report
