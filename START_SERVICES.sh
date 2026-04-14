#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Cleaning up existing Next.js process on port 3000..."
pids_3000="$(lsof -ti:3000 || true)"
if [ -n "$pids_3000" ]; then
  kill -9 $pids_3000 2>/dev/null || true
fi
sleep 1

echo "Starting URL Audit Kit on port 3000..."
cd "$ROOT_DIR/frontend"
nohup npm run dev > ../frontend.log 2>&1 &
FRONTEND_PID=$!

echo "Frontend started (PID: $FRONTEND_PID)"
echo ""
echo "URL Audit Kit is running"
echo "Frontend: http://localhost:3000"
echo "Health:   http://localhost:3000/healthz"
echo "Logs:     tail -f frontend.log"
