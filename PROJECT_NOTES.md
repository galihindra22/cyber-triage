# PROJECT NOTES  (paste this at the start of every new Claude chat)

## What we're building
Offline, Bahasa-first incident triage tool for a TNI AD unit's small cyber team, covering IT + OT.
Pipeline: fake logs -> detection rules -> incidents (+ MITRE labels) -> local AI writes Bahasa report -> dashboard.
Competition: TNI AD hackathon, Category 03 (Dukungan Teknologi). Judging: Relevance 25, Innovation 25,
Working prototype 25, Feasibility 15, Documentation 10.

## Stack
- Backend: FastAPI + SQLite (plain sqlite3), Python 3.12, folder `backend/`
- Frontend: Next.js (folder `frontend/`, created in chunk 7)
- AI: Ollama on Windows, model: qwen2.5:3b (8GB RAM machine; fall back to 1.5b if too slow)
- Docker Compose only for final deployment (week 4)
- OS: Windows, working in PowerShell + VS Code

## Data flow
events (raw logs) -> alerts (detections) -> incidents (grouped story) ; mitre_techniques = lookup table

## Chunks
- [x] 1. Skeleton + data model + setup   <- done when you can open localhost:8000/docs
- [x] 2. Attack simulator (IT + OT logs)   <- `python -m app.simulator` writes backend/data/logs/*.log (~5,600 lines)
- [x] 3. Log ingestion   <- app/parser.py
- [x] 4. Detection rules   <- app/detection.py (R001-R007), settings in app/config.py
- [x] 5. Correlation + MITRE mapping   <- app/correlation.py. `python -m app.pipeline` = 5586 events -> 8 alerts -> 1 incident, 7/7 techniques found
- [x] 6. Ollama summary (streamed) + template fallback + playbook   <- app/ai.py, app/playbook.py, data/playbook.csv (DRAFT: brother must verify + fill 'sumber')
- [x] 7. Dashboard (Next.js, v1)   <- frontend/ . Run: cd frontend; npm install; npm run dev -> http://localhost:3000 (backend must run on :8000)
- [ ] 8. Report export + polish

## Log formats (chunk 3 parser must handle all 4)
- windows_auth.log: `ISO_TIME HOST EventID=4624|4625 Account=.. SrcIP=.. LogonType=.. Result=SUCCESS|FAILURE`
- web_access.log: Apache style `IP - - [19/Oct/2026:21:00:05 +0700] "GET /path HTTP/1.1" 200 512`
- firewall.log: `ISO_TIME FW-01 action=ALLOW|BLOCK proto=TCP src=.. dst=.. dport=..`
- ot_modbus.log: `ISO_TIME GEN-CTRL-01 src=.. unit=1 func=READ_HOLDING_REGISTERS|WRITE_SINGLE_REGISTER|WRITE_SINGLE_COIL reg=/coil= value=.. result=OK`
- Attack answer key: backend/data/logs/ground_truth.json
- AI test: qwen2.5:3b, short summary prompt, ~33s on 8GB CPU. Plan: stream text, warm up model before demo, recommendations from a playbook table (not AI).

## API (chunk 3-5)
- POST /api/pipeline/run  (demo button: regenerate logs + run everything)
- GET /api/stats, /api/incidents, /api/incidents/{id}, /api/alerts, /api/mitre

## Known simplifications (be honest in the pitch)
- R004 maps 'connection to unknown outside IP' to T1566 Phishing; real phishing is an email event. Brother: review this mapping.
- Generator setpoint scale (5000 = 50.00 Hz) is our assumption.
- OT logs assume a passive sensor/gateway records Modbus traffic.

## Notes / problems
(write anything weird here before asking Claude)
