# Startup Guide

## Prerequisites

- Node.js 18+

## Local Run

```bash
cd /path/to/url_audit_kit/frontend
npm install
npm run dev
```

Expected:

- `Local: http://localhost:3000`

## Endpoints

- UI: `http://127.0.0.1:3000`
- Health: `http://127.0.0.1:3000/healthz`
- Audit API: `http://127.0.0.1:3000/api/audit`

## Smoke Test

```bash
curl -X POST http://127.0.0.1:3000/api/audit \
  -F "url=https://example.com"
```
