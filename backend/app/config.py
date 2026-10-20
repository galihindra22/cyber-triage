"""
Settings for the detection engine, in one place.
When a real unit tells us its network, THIS is the file we edit.
"""

# Which computer has which IP (used to follow an attacker from machine to machine)
HOST_IPS = {
    "WS-ADM-01": "10.10.5.10", "WS-ADM-02": "10.10.5.11", "WS-ADM-03": "10.10.5.12",
    "WS-ADM-04": "10.10.5.13", "WS-ADM-05": "10.10.5.14", "WS-ENG-07": "10.10.5.23",
    "SCADA-ENG-01": "10.10.9.20",   # engineering PC that can reach the OT network
    "SCADA-HMI-01": "10.10.9.5",    # the real operator screen
    "GEN-CTRL-01": "10.10.9.50",    # generator controller (PLC)
}

# Hosts we treat as sensitive / next to the OT network
SENSITIVE_HOST_PREFIXES = ("SCADA", "GEN")

# The ONLY machines allowed to send write commands to OT devices
ALLOWED_OT_WRITERS = {"10.10.9.5"}

# Generator setpoint register. Value 5000 = 50.00 Hz. Normal range 45-55 Hz.
SETPOINT_REGISTER = "40001"
SETPOINT_NORMAL_RANGE = (4500, 5500)
GENERATOR_STOP_COIL = "00001"

INTERNAL_PREFIX = "10."          # anything else is "outside"
EXTERNAL_ALLOWLIST = set()       # outside IPs that are OK (e.g. update servers)

# Detection thresholds
BF_MIN_FAILURES = 10             # this many failed logins in a row = brute force
BF_GAP_SECONDS = 300             # a pause longer than 5 min ends a burst
AFTER_BF_SECONDS = 1800          # a login within 30 min after a burst is suspicious
EXTERNAL_GAP_SECONDS = 600       # group outside connections within 10 min

# Correlation: alerts closer than this and linked together = same incident
CORRELATION_WINDOW_SECONDS = 1800

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
