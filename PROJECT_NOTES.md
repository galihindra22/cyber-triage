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
- [ ] 3. Log ingestion
- [ ] 4. Detection rules
- [ ] 5. Correlation + MITRE mapping
- [ ] 6. Ollama integration (+ template fallback)
- [ ] 7. Dashboard (Next.js)
- [ ] 8. Report export + polish

## Log formats (chunk 3 parser must handle all 4)
- windows_auth.log: `ISO_TIME HOST EventID=4624|4625 Account=.. SrcIP=.. LogonType=.. Result=SUCCESS|FAILURE`
- web_access.log: Apache style `IP - - [19/Oct/2026:21:00:05 +0700] "GET /path HTTP/1.1" 200 512`
- firewall.log: `ISO_TIME FW-01 action=ALLOW|BLOCK proto=TCP src=.. dst=.. dport=..`
- ot_modbus.log: `ISO_TIME GEN-CTRL-01 src=.. unit=1 func=READ_HOLDING_REGISTERS|WRITE_SINGLE_REGISTER|WRITE_SINGLE_COIL reg=/coil= value=.. result=OK`
- Attack answer key: backend/data/logs/ground_truth.json
- AI test: qwen2.5:3b, short summary prompt, ~33s on 8GB CPU. Plan: stream text, warm up model before demo, recommendations from a playbook table (not AI).

## Notes / problems
(write anything weird here before asking Claude)
