"""
INCIDENT REPORT (chunk 8)
=========================
Builds a printable report page in Bahasa Indonesia for one incident.
It is plain HTML: open it in the browser, press Ctrl+P, choose "Save as PDF".
No extra libraries needed, so it also works offline and inside Docker.
"""
import json
from datetime import datetime
from html import escape

from .ai import SEV, load_incident, template_summary
from .db import get_conn
from .playbook import playbook_for

SEV_LABEL = {"critical": "Kritis", "high": "Tinggi", "medium": "Sedang", "low": "Rendah"}

CSS = """
body{font-family:Georgia,'Times New Roman',serif;color:#1b2318;max-width:820px;margin:32px auto;padding:0 24px;line-height:1.55}
h1{font-size:1.7rem;margin:0 0 4px}
h2{font-size:1.15rem;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid #3f4f26}
.sub{color:#596453;margin:0 0 18px}
table{border-collapse:collapse;width:100%;font-size:.93rem}
th,td{border:1px solid #c4cbb9;padding:6px 9px;text-align:left;vertical-align:top}
th{background:#eef0e8}
td.k{width:30%;background:#f6f7f2;font-weight:bold}
.sev{font-weight:bold}.critical{color:#a4231b}.high{color:#bd5410}.medium{color:#9c7110}.low{color:#2d6685}
.pb{margin:0 0 12px;padding:8px 12px;border-left:4px solid #3f4f26;background:#f6f7f2}
.pb p{margin:3px 0}.small{color:#596453;font-size:.85rem}
h2{break-after:avoid;page-break-after:avoid}
@media print{body{margin:0;max-width:none}.pb,tr,.keep{break-inside:avoid;page-break-inside:avoid}}
"""


def _p(text):
    return "".join(f"<p>{escape(t)}</p>" for t in text.split("\n") if t.strip())


def _group(alerts):
    """Same idea as the dashboard: alerts from the same log line are one step."""
    groups, index = [], {}
    for a in alerts:
        if a["event_ids"] in index:
            groups[index[a["event_ids"]]].append(a)
        else:
            index[a["event_ids"]] = len(groups)
            groups.append([a])
    return groups


def build_report_html(incident_id):
    with get_conn() as conn:
        inc, rows = load_incident(conn, incident_id)
        if not inc:
            return None
        n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        n_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        techniques = {r["technique_id"]: dict(r) for r in conn.execute("SELECT * FROM mitre_techniques")}
    alerts = [dict(r) for r in rows]
    summary = inc["summary"] or template_summary(inc, rows)

    hosts = sorted({a["host"] for a in alerts if a["host"]})
    users = sorted({a["user"] for a in alerts if a["user"]})
    ips = sorted({a["src_ip"] for a in alerts if a["src_ip"]})
    sev = inc["severity"]

    steps = ""
    for g in _group(alerts):
        first = g[0]
        zone = "Jaringan industri (OT)" if any(
            techniques.get(a["technique_id"], {}).get("matrix") == "ics" for a in g) else "Jaringan kantor (IT)"
        descs = "".join(f"<div>{escape(a['title'])}</div>" for a in g)
        mitre = "".join(
            f"<div><b>{escape(a['technique_id'] or '-')}</b> {escape(a['technique_name'] or '')}</div>" for a in g)
        lines = len(json.loads(first["event_ids"]))
        steps += (f"<tr><td>{first['ts'][11:19]}</td><td>{zone}</td>"
                  f"<td class='sev {first['severity']}'>{SEV_LABEL[first['severity']]}</td>"
                  f"<td>{descs}</td><td>{mitre}</td><td>{lines}</td></tr>")

    blocks = []
    for p in playbook_for(alerts):
        source = f"<p class='small'>Sumber: {escape(p['sumber'])}</p>" if p.get("sumber") else ""
        blocks.append(f"<div class='pb'><p><b>{escape(p['technique_id'])} {escape(p.get('technique_name') or '')}</b></p>"
                    f"<p><b>Satu jam pertama:</b> {escape(p['jam_pertama'])}</p>"
                    f"<p><b>Lanjutan:</b> {escape(p['lanjutan'])}</p>"
                    f"<p><b>Kabari:</b> {escape(p['kabari'])}</p>{source}</div>")

    # Keep the heading together with the first action block so it can't be stranded.
    if blocks:
        actions_html = ("<div class='keep'><h2>Tindakan yang disarankan</h2>" + blocks[0] + "</div>"
                        + "".join(blocks[1:]))
    else:
        actions_html = "<h2>Tindakan yang disarankan</h2><p>Tidak ada saran tindakan.</p>"

    meta = [
        ("Nomor insiden", f"#{inc['id']}"),
        ("Tingkat keparahan", f"<span class='sev {sev}'>{SEV_LABEL[sev]}</span>"),
        ("Tanggal", datetime.fromisoformat(inc["start_ts"]).strftime("%d-%m-%Y")),
        ("Waktu kejadian", f"{inc['start_ts'][11:16]} sampai {inc['end_ts'][11:16]}"),
        ("Data yang dianalisis", f"{n_events:,} baris log menjadi {n_alerts} peringatan menjadi 1 insiden".replace(",", ".")),
        ("Laporan dibuat", datetime.now().strftime("%d-%m-%Y %H:%M")),
    ]
    meta_html = "".join(f"<tr><td class='k'>{k}</td><td>{v}</td></tr>" for k, v in meta)

    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<title>Laporan Insiden Siber #{inc['id']}</title><style>{CSS}</style></head><body>
<h1>Laporan Insiden Siber</h1>
<p class="sub">{escape(inc['title'])}</p>
<table>{meta_html}</table>

<h2>Ringkasan</h2>{_p(summary)}

<h2>Aset dan akun terkait</h2>
<table>
<tr><td class="k">Perangkat</td><td>{escape(', '.join(hosts)) or '-'}</td></tr>
<tr><td class="k">Akun</td><td>{escape(', '.join(users)) or '-'}</td></tr>
<tr><td class="k">Alamat IP sumber</td><td>{escape(', '.join(ips)) or '-'}</td></tr>
</table>

<h2>Alur serangan</h2>
<table><tr><th>Waktu</th><th>Zona</th><th>Tingkat</th><th>Temuan</th><th>Teknik MITRE</th><th>Baris log</th></tr>{steps}</table>
<p class="small">Kolom "Baris log" menunjukkan jumlah baris log asli yang menjadi bukti temuan tersebut.</p>

{actions_html}

<h2>Catatan</h2>
<p class="small">Deteksi dilakukan oleh aturan yang dapat diaudit. Ringkasan ditulis oleh model bahasa lokal tanpa mengirim data keluar jaringan. Saran tindakan berasal dari tabel playbook yang diperiksa manusia. Laporan ini dibuat dari log simulasi untuk keperluan demonstrasi prototipe.</p>
</body></html>"""
