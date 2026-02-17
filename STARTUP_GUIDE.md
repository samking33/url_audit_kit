# Startup Guide

## Prerequisites
- Python 3.9+
- Node.js 18+
- No database needed

## Backend
```bash
cd /path/to/url_audit_kit
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install -r requirements.txt
UVICORN_RELOAD=0 .venv/bin/python -m webapp
```

Expected:
- `Uvicorn running on http://127.0.0.1:8765`

## Frontend
```bash
cd /path/to/url_audit_kit/frontend
npm install
npm run dev
```

Expected:
- `Local: http://localhost:3000`

## Run in Two Terminals
Terminal 1:
```bash
cd /path/to/url_audit_kit
UVICORN_RELOAD=0 .venv/bin/python -m webapp
```

Terminal 2:
```bash
cd /path/to/url_audit_kit/frontend
npm run dev
```

Keep both terminals open. Closing either terminal stops that service.

## If Backend Exits Immediately
This usually means port `8765` is already occupied.

```bash
lsof -nP -iTCP:8765 -sTCP:LISTEN
kill $(lsof -tiTCP:8765 -sTCP:LISTEN)
UVICORN_RELOAD=0 .venv/bin/python -m webapp
```

## Endpoints
- UI: http://127.0.0.1:3000
- API: http://127.0.0.1:8765
- API Docs: http://127.0.0.1:8765/docs
- Health: http://127.0.0.1:8765/healthz

## Smoke Test
```bash
curl -X POST http://127.0.0.1:8765/api/audit \
  -F "url=https://example.com"
```
