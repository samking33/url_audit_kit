#!/bin/bash

echo "Stopping URL Audit Kit..."

pids_3000="$(lsof -ti:3000 || true)"
if [ -n "$pids_3000" ]; then
  kill -9 $pids_3000 2>/dev/null || true
  echo "Frontend stopped"
else
  echo "Frontend not running"
fi

pkill -f "next dev" 2>/dev/null || true

echo "All services stopped"
