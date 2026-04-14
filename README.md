# URL Audit Kit

URL threat auditing as a single Next.js Node.js app.

- 43 deterministic security checks
- SQLite persistence with `node-sqlite3-wasm`
- Optional NVIDIA NIM AI analysis
- Built-in API routes for scans, reports, IOCs, and dashboard data

## Architecture

- App: Next.js (`frontend/`)
- Runtime: Node.js
- API: Next route handlers under `frontend/src/app/api`
- Health: `/healthz`

## Quick Start

```bash
cd frontend
npm install
npm run dev
```

Open:

- UI: `http://127.0.0.1:3000`
- API health: `http://127.0.0.1:3000/healthz`

## Environment

For local development, copy `frontend/.env.local.example` to `frontend/.env.local`.
For Render, add the same keys to the service environment settings.

Active environment variables used by the current Node app:

- `URL_AUDIT_DB_PATH=...`
- `GOOGLE_SAFE_BROWSING_API_KEY=...` for blacklist and Safe Browsing checks
- `AI_PROVIDER=nim`
- `NVIDIA_NIM_API_KEY=...`
- `NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1`
- `NVIDIA_NIM_MODEL=meta/llama-3.1-70b-instruct`
- `NVIDIA_NIM_TIMEOUT=90`

Legacy aliases still supported:

- `AI_PROVIDER=nvidia` maps to the NVIDIA NIM provider
- `NVIDIA_TEXT_MODEL` maps to `NVIDIA_NIM_MODEL`
- `NVIDIA_TIMEOUT` maps to `NVIDIA_NIM_TIMEOUT`

## API

- `POST /api/audit`
- `GET /api/dashboard/overview`
- `GET /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/scans/:scanId/report`
- `GET /api/iocs`
- `GET /api/threat-intelligence/map`
- `GET /api/threat-intelligence/domains`
- `GET /api/threat-intelligence/ip-reputation`

## Render

This repo includes a single-service Render blueprint in `render.yaml` that deploys the Next.js app from `frontend/`.
