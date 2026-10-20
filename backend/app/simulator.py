"""
ATTACK SIMULATOR
================
We can't get real logs from a TNI AD unit, so this file FAKES them.

It writes 4 log files (each in a different, realistic format) into
backend/data/logs/ :

  windows_auth.log   Windows login events (4624 = success, 4625 = failure)
  web_access.log     Intranet web server (Apache style)
  firewall.log       Firewall allow/block records
  ot_modbus.log      Industrial (OT) traffic to the generator controller

Inside ~5,000 normal "boring" log lines we hide ONE attack story:

  20:42  Phishing: workstation WS-ENG-07 talks to a suspicious outside server
  21:00  WS-ENG-07 starts guessing passwords on WS-ADM-03 (200 failures)
  21:05  A guess works: account budi.s logs in
  21:18  budi.s logs into SCADA-ENG-01 (engineering PC that can reach the OT network)
  21:25  SCADA-ENG-01 sends Modbus commands: change the generator setpoint, then STOP it

Run it (from the backend folder, venv active):
    python -m app.simulator

The random seed is fixed, so you get the SAME logs every time.
That matters: a demo must be repeatable.
"""
import json
import os
import random
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path(os.environ.get("STATE_DIR", Path(__file__).resolve().parent.parent / "data")) / "logs"

# ---- The simulated day -------------------------------------------------
DAY = datetime(2026, 10, 19)
START = DAY.replace(hour=19)          # logs cover 19:00 - 23:00
END = DAY.replace(hour=23)
SPAN = int((END - START).total_seconds())

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# ---- The simulated network ---------------------------------------------
# user -> (their workstation, that workstation's IP)
USERS = {
    "siti.r":  ("WS-ADM-01", "10.10.5.10"),
    "agus.w":  ("WS-ADM-02", "10.10.5.11"),
    "budi.s":  ("WS-ADM-03", "10.10.5.12"),   # the victim account
    "dewi.p":  ("WS-ADM-04", "10.10.5.13"),
    "rudi.h":  ("WS-ADM-05", "10.10.5.14"),
    "joko.e":  ("WS-ENG-07", "10.10.5.23"),   # WS-ENG-07 = later compromised
}
WORKSTATION_IPS = [ip for _, ip in USERS.values()]

DC_IP = "10.10.1.10"          # domain controller
WEB_IP = "10.10.2.15"         # intranet web server
HMI_IP = "10.10.9.5"          # the REAL operator screen for the generator
SCADA_ENG_IP = "10.10.9.20"   # engineering PC (bridge to OT)
GEN_IP = "10.10.9.50"         # generator controller (PLC)
ATTACKER_PC = "10.10.5.23"    # WS-ENG-07, already infected via phishing
EVIL_SERVER = "203.0.113.45"  # outside "phishing" server (test IP range)

WEB_PATHS = ["/portal/", "/portal/login", "/portal/surat", "/docs/sop.pdf",
             "/docs/jadwal.pdf", "/static/app.js", "/static/style.css",
             "/portal/laporan", "/portal/profil"]


# ---- Small helpers ------------------------------------------------------
def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def apache(dt):
    return f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt.strftime('%H:%M:%S')} +0700"


def rand_time(rng):
    return START + timedelta(seconds=rng.randint(0, SPAN - 1))


def at(hh, mm, ss=0):
    return DAY.replace(hour=hh, minute=mm, second=ss)


# ---- Normal (boring) traffic -------------------------------------------
def windows_noise(rng):
    rows = []
    for _ in range(700):                      # normal logins
        user = rng.choice(list(USERS))
        host, ip = USERS[user]
        t = rand_time(rng)
        rows.append((t, f"{iso(t)} {host} EventID=4624 Account={user} "
                        f"SrcIP={ip} LogonType=2 Result=SUCCESS"))
    for _ in range(40):                       # normal typos (1-2 failures)
        user = rng.choice(list(USERS))
        host, ip = USERS[user]
        t = rand_time(rng)
        rows.append((t, f"{iso(t)} {host} EventID=4625 Account={user} "
                        f"SrcIP={ip} LogonType=2 Result=FAILURE"))
    return rows


def web_noise(rng):
    rows = []
    for _ in range(2200):
        ip = rng.choice(WORKSTATION_IPS)
        t = rand_time(rng)
        path = rng.choice(WEB_PATHS)
        status = rng.choices([200, 304, 404], weights=[85, 10, 5])[0]
        size = rng.randint(200, 90000)
        rows.append((t, f'{ip} - - [{apache(t)}] "GET {path} HTTP/1.1" {status} {size}'))
    return rows


def firewall_noise(rng):
    rows = []
    flows = [(DC_IP, 445), (DC_IP, 88), (DC_IP, 389), (WEB_IP, 80), (WEB_IP, 443)]
    for _ in range(1600):
        src = rng.choice(WORKSTATION_IPS)
        dst, port = rng.choice(flows)
        t = rand_time(rng)
        rows.append((t, f"{iso(t)} FW-01 action=ALLOW proto=TCP src={src} dst={dst} dport={port}"))
    for _ in range(60):                       # normal blocked junk
        src = f"10.10.50.{rng.randint(2, 40)}"   # guest VLAN
        t = rand_time(rng)
        rows.append((t, f"{iso(t)} FW-01 action=BLOCK proto=TCP src={src} "
                        f"dst={DC_IP} dport={rng.choice([22, 23, 3389])}"))
    return rows


def modbus_noise(rng):
    rows = []
    t = START
    while t < END:                            # HMI polls generator every 20s
        rows.append((t, f"{iso(t)} GEN-CTRL-01 src={HMI_IP} unit=1 "
                        f"func=READ_HOLDING_REGISTERS reg=40001 count=10 result=OK"))
        t += timedelta(seconds=20)
    for _ in range(6):                        # operator makes small, normal setpoint changes
        t = rand_time(rng)
        value = rng.randint(4900, 5100)       # 5000 = 50.00 Hz
        rows.append((t, f"{iso(t)} GEN-CTRL-01 src={HMI_IP} unit=1 "
                        f"func=WRITE_SINGLE_REGISTER reg=40001 value={value} result=OK"))
    return rows


# ---- THE ATTACK ---------------------------------------------------------
def attack_events(rng):
    """Returns (windows, web, firewall, modbus, ground_truth)."""
    win, fw, ot, truth = [], [], [], []

    # 1) 20:42 phishing: infected PC talks to an outside server
    for s in (0, 31, 58):
        t = at(20, 42, s)
        fw.append((t, f"{iso(t)} FW-01 action=ALLOW proto=TCP src={ATTACKER_PC} "
                      f"dst={EVIL_SERVER} dport=443"))
    truth.append({"time": "20:42", "step": "Phishing: WS-ENG-07 contacts a suspicious outside server",
                  "mitre": "T1566"})

    # 2) 21:00-21:04 brute force: 200 failed logins on WS-ADM-03
    t = at(21, 0, 0)
    for i in range(200):
        t += timedelta(seconds=rng.uniform(0.5, 1.9))
        account = "budi.s" if i < 170 else "administrator"
        win.append((t, f"{iso(t)} WS-ADM-03 EventID=4625 Account={account} "
                       f"SrcIP={ATTACKER_PC} LogonType=3 Result=FAILURE"))
        if i % 4 == 0:
            fw.append((t, f"{iso(t)} FW-01 action=ALLOW proto=TCP src={ATTACKER_PC} "
                          f"dst=10.10.5.12 dport=445"))
    truth.append({"time": "21:00-21:04", "step": "200 failed logins on WS-ADM-03 from WS-ENG-07",
                  "mitre": "T1110"})

    # 3) 21:05 a guess works
    t = at(21, 5, 12)
    win.append((t, f"{iso(t)} WS-ADM-03 EventID=4624 Account=budi.s "
                   f"SrcIP={ATTACKER_PC} LogonType=3 Result=SUCCESS"))
    truth.append({"time": "21:05", "step": "Successful login as budi.s from the same IP",
                  "mitre": "T1078"})

    # 4) 21:18 attacker reaches the engineering PC that touches OT (RDP)
    t = at(21, 18, 40)
    fw.append((t, f"{iso(t)} FW-01 action=ALLOW proto=TCP src={ATTACKER_PC} "
                  f"dst={SCADA_ENG_IP} dport=3389"))
    t = at(21, 18, 44)
    win.append((t, f"{iso(t)} SCADA-ENG-01 EventID=4624 Account=budi.s "
                   f"SrcIP={ATTACKER_PC} LogonType=10 Result=SUCCESS"))
    truth.append({"time": "21:18", "step": "budi.s logs into SCADA-ENG-01 by remote desktop",
                  "mitre": "T1021"})

    # 5) 21:24-21:25 OT attack: look around, change setpoint, stop generator
    t = at(21, 24, 50)
    ot.append((t, f"{iso(t)} GEN-CTRL-01 src={SCADA_ENG_IP} unit=1 "
                  f"func=READ_HOLDING_REGISTERS reg=40001 count=10 result=OK"))
    t = at(21, 25, 3)
    fw.append((t, f"{iso(t)} FW-01 action=ALLOW proto=TCP src={SCADA_ENG_IP} "
                  f"dst={GEN_IP} dport=502"))
    ot.append((t, f"{iso(t)} GEN-CTRL-01 src={SCADA_ENG_IP} unit=1 "
                  f"func=WRITE_SINGLE_REGISTER reg=40001 value=2500 result=OK"))
    t = at(21, 25, 7)
    ot.append((t, f"{iso(t)} GEN-CTRL-01 src={SCADA_ENG_IP} unit=1 "
                  f"func=WRITE_SINGLE_COIL coil=00001 value=OFF result=OK"))
    truth.append({"time": "21:25", "step": "Modbus: setpoint changed 50.00Hz -> 25.00Hz, then generator STOP",
                  "mitre": "T0855, T0836, T0831"})

    return win, [], fw, ot, truth


# ---- Main ---------------------------------------------------------------
def write_log(name, rows):
    rows.sort(key=lambda r: r[0])             # oldest first, like a real log
    path = LOG_DIR / name
    path.write_text("\n".join(line for _, line in rows) + "\n", encoding="utf-8")
    return len(rows)


def generate(seed=42):
    rng = random.Random(seed)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    a_win, a_web, a_fw, a_ot, truth = attack_events(rng)
    counts = {
        "windows_auth.log": write_log("windows_auth.log", windows_noise(rng) + a_win),
        "web_access.log":   write_log("web_access.log",   web_noise(rng) + a_web),
        "firewall.log":     write_log("firewall.log",     firewall_noise(rng) + a_fw),
        "ot_modbus.log":    write_log("ot_modbus.log",    modbus_noise(rng) + a_ot),
    }
    # The "answer key": used later to check our detection finds everything.
    (LOG_DIR / "ground_truth.json").write_text(
        json.dumps(truth, indent=2, ensure_ascii=False), encoding="utf-8")
    return counts


if __name__ == "__main__":
    counts = generate()
    for name, n in counts.items():
        print(f"{name:20s} {n:5d} lines")
    print(f"{'TOTAL':20s} {sum(counts.values()):5d} lines")
    print(f"Written to: {LOG_DIR}")
