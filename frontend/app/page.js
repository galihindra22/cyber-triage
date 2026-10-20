"use client";
/*
  THE DASHBOARD (one page).
  It only talks to the backend at http://localhost:8000 and shows what comes back.
  Flow: click "Jalankan simulasi" -> backend runs the whole pipeline -> we fetch
  the incident -> the timeline reveals one step at a time (the demo moment).
*/
import { useState, useEffect, useRef } from "react";

const API = "http://localhost:8000";
const SEV = { critical: "Kritis", high: "Tinggi", medium: "Sedang", low: "Rendah" };
const RANK = { low: 1, medium: 2, high: 3, critical: 4 };

// Several alerts can come from the SAME log line (e.g. R005 + R006).
// We show them together as one step.
function groupAlerts(alerts) {
  const groups = [];
  const seen = {};
  for (const a of alerts) {
    if (a.event_ids in seen) {
      groups[seen[a.event_ids]].alerts.push(a);
    } else {
      seen[a.event_ids] = groups.length;
      groups.push({ ts: a.ts, alerts: [a] });
    }
  }
  return groups.map((g) => ({
    ...g,
    zone: g.alerts.some((a) => a.matrix === "ics") ? "ot" : "it",
    severity: g.alerts.reduce((m, a) => (RANK[a.severity] > RANK[m] ? a.severity : m), "low"),
  }));
}

const fmt = (n) => Number(n).toLocaleString("id-ID");
const clock = (ts) => ts.slice(11, 19);

export default function Home() {
  const [stats, setStats] = useState(null);
  const [incident, setIncident] = useState(null);
  const [shown, setShown] = useState(0);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState("");
  const [writing, setWriting] = useState(false);
  const [error, setError] = useState("");
  const timer = useRef(null);

  const down = "Tidak bisa terhubung ke backend di port 8000. Jalankan: uvicorn app.main:app --reload (folder backend, venv aktif).";

  async function load() {
    const s = await (await fetch(`${API}/api/stats`)).json();
    setStats(s);
    const list = await (await fetch(`${API}/api/incidents`)).json();
    if (!list.length) { setIncident(null); return null; }
    const inc = await (await fetch(`${API}/api/incidents/${list[0].id}`)).json();
    setIncident(inc);
    return inc;
  }

  function play(total, onDone) {
    clearInterval(timer.current);
    setShown(0);
    let n = 0;
    timer.current = setInterval(() => {
      n += 1;
      setShown(n);
      if (n >= total) {
        clearInterval(timer.current);
        if (onDone) onDone();
      }
    }, 1100);
  }

  // Reads the summary as it is being written and shows it live.
  async function summarize(id) {
    setWriting(true);
    setSummary("");
    try {
      const res = await fetch(`${API}/api/incidents/${id}/summary`, { method: "POST" });
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let text = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
        setSummary(text);
      }
    } catch (e) {
      setError("Gagal membuat ringkasan. Pastikan backend berjalan.");
    }
    setWriting(false);
  }

  async function run() {
    setLoading(true);
    setError("");
    setSummary("");
    try {
      const res = await fetch(`${API}/api/pipeline/run`, { method: "POST" });
      if (!res.ok) throw new Error("server");
      const inc = await load();
      if (inc) play(groupAlerts(inc.alerts).length, () => summarize(inc.id));
    } catch (e) {
      setError(down);
    }
    setLoading(false);
  }

  useEffect(() => {
    load().then((inc) => inc && setShown(999)).catch(() => setError(down));
    return () => clearInterval(timer.current);
  }, []);

  const groups = incident ? groupAlerts(incident.alerts) : [];
  const minutes = incident
    ? Math.round((new Date(incident.end_ts) - new Date(incident.start_ts)) / 60000)
    : 0;
  const firstOt = groups.findIndex((g) => g.zone === "ot");

  return (
    <main className="wrap">
      <header className="top">
        <div>
          <h1>Pusat Triase Insiden Siber</h1>
          <p className="lead">Dari ribuan baris log menjadi satu cerita serangan.</p>
        </div>
        <div className="actions">
          <button className="btn primary" onClick={run} disabled={loading}>
            {loading ? "Memproses log..." : "Jalankan simulasi serangan"}
          </button>
          {incident && (
            <button className="btn" onClick={() => play(groups.length)} disabled={loading}>
              Putar ulang cerita
            </button>
          )}
        </div>
      </header>

      {error && <p className="error">{error}</p>}

      {stats && stats.events > 0 && (
        <p className="flow">
          <b>{fmt(stats.events)}</b> baris log menjadi <b>{fmt(stats.alerts)}</b> peringatan,
          lalu menjadi <b>{fmt(stats.incidents)}</b> insiden.
        </p>
      )}

      {!incident && !error && (
        <p className="empty">Belum ada data. Klik “Jalankan simulasi serangan” untuk memulai.</p>
      )}

      {incident && (
        <>
          <section className="incident">
            <span className={`sev ${incident.severity}`}>{SEV[incident.severity]}</span>
            <h2>{incident.title}</h2>
            <p className="when">
              Berlangsung {clock(incident.start_ts).slice(0, 5)} sampai {clock(incident.end_ts).slice(0, 5)}, selama {minutes} menit.
            </p>
            <p className="summary">
              {summary || incident.summary ||
                (writing ? "Menulis ringkasan..." : "Ringkasan otomatis belum dibuat.")}
            </p>
            {!writing && (
              <button className="btn small" onClick={() => summarize(incident.id)}>
                Tulis ringkasan
              </button>
            )}
          </section>

          <h3 className="tl-head">Alur serangan</h3>
          <ol className="timeline">
            {groups.slice(0, shown).map((g, i) => (
              <li key={i} className={`step ${g.severity} reveal`}>
                {i === firstOt && (
                  <div className="cross">Penyerang masuk ke jaringan industri (OT)</div>
                )}
                <div className="stamp">
                  <time>{clock(g.ts)}</time>
                  <span className={`sev small ${g.severity}`}>{SEV[g.severity]}</span>
                  <span className="zone">{g.zone === "ot" ? "Jaringan industri" : "Jaringan kantor"}</span>
                </div>
                {g.alerts.map((a) => (
                  <div className="alert" key={a.id}>
                    <p className="atitle">{a.title}</p>
                    <p className="amitre">
                      <span className="tid">{a.technique_id}</span> {a.technique_name}, taktik {a.tactic}.{" "}
                      {a.penjelasan_id}
                    </p>
                  </div>
                ))}
              </li>
            ))}
          </ol>

          {shown >= groups.length && incident.playbook && incident.playbook.length > 0 && (
            <>
              <h3 className="tl-head">Tindakan yang disarankan</h3>
              <div className="playbook">
                {incident.playbook.map((p) => (
                  <div className="pb" key={p.technique_id}>
                    <p className="pbtitle">
                      <span className="tid">{p.technique_id}</span> {p.technique_name}
                    </p>
                    <p><b>Satu jam pertama:</b> {p.jam_pertama}</p>
                    <p><b>Lanjutan:</b> {p.lanjutan}</p>
                    <p><b>Kabari:</b> {p.kabari}</p>
                    {p.sumber && <p className="src">Sumber: {p.sumber}</p>}
                  </div>
                ))}
              </div>
            </>
          )}
        </>
      )}
    </main>
  );
}
