#!/usr/bin/env bash
set -euo pipefail

BACKEND_HOST="${BACKEND_HOST:-0.0.0.0}"
BACKEND_PORT="${BACKEND_PORT:-5000}"
STREAMLIT_HOST="${STREAMLIT_SERVER_ADDRESS:-0.0.0.0}"
STREAMLIT_PORT="${PORT:-${STREAMLIT_SERVER_PORT:-7860}}"
BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:${BACKEND_PORT}/analyse_email}"

export BACKEND_URL

gunicorn server:app \
  --bind "${BACKEND_HOST}:${BACKEND_PORT}" \
  --workers "${GUNICORN_WORKERS:-1}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" &
backend_pid=$!

cleanup() {
  kill "${backend_pid}" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

sleep 2

exec streamlit run app.py \
  --server.port "${STREAMLIT_PORT}" \
  --server.address "${STREAMLIT_HOST}" \
  --server.headless true \
  --server.enableXsrfProtection false \
  --browser.gatherUsageStats false
