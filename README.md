# URL Audit Kit

DB-free URL threat auditing with:
- 41 deterministic URL security checks
- AI-generated threat brief (NVIDIA NIM)
- URL normalization + HTTPS/HTTP fallback + parser fallback
- No `SKIP` runtime results (checks resolve to `PASS/WARN/FAIL/INFO`)
- Next.js frontend in Neo-Brutalist style
- FastAPI backend with progress websocket

## Architecture
- Frontend: Next.js (`frontend/`) on port `3000`
- Backend: FastAPI (`webapp/`) on port `8765`
- Core checks: `url_audit/`
- No database required

## Full Documentation
- Detailed project work document: `PROJECT_DOCUMENTATION.md`

## Quick Start

### 1. Backend
```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
UVICORN_RELOAD=0 .venv/bin/python -m webapp
```

### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```

### 3. Open
- Frontend UI: http://127.0.0.1:3000
- Backend API: http://127.0.0.1:8765
- API docs: http://127.0.0.1:8765/docs

## Environment
Copy `.env.example` to `.env` and configure AI keys.

Key fields:
- `AUDIT_TIMEOUT_SECONDS=15`
- `NVIDIA_NIM_API_KEY=...`
- `NVIDIA_TEXT_MODEL=...`
- `NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1`

## API

### Run audit
`POST /api/audit` (multipart form):
- `url`: target URL
- `job_id` (optional): enables websocket progress updates

Response additions:
- `input_url`
- `normalized_url`
- `resolved_url`

### Progress websocket
`GET ws://127.0.0.1:8765/ws/progress/{job_id}`

### Health
`GET /healthz`

## Run Both (Manual)
Open two terminals:
1. Backend: `UVICORN_RELOAD=0 .venv/bin/python -m webapp`
2. Frontend: `cd frontend && npm run dev`

If backend exits immediately, free the port and retry:
```bash
kill $(lsof -tiTCP:8765 -sTCP:LISTEN)
UVICORN_RELOAD=0 .venv/bin/python -m webapp
```
