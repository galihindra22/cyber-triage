# Cyber Triage

See PROJECT_NOTES.md for the plan and status.

## Run the backend (Windows PowerShell)
```
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://localhost:8000/docs
