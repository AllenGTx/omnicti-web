#!/bin/bash
set -e

echo "[*] Starting OmniCTI Security Suite (Docker)..."

# Start Python phishing service on port 5001 (internal)
echo "[*] Starting Phishing Detection Service (Python) on port 5001..."
PHISHING_PORT=5001 python3 phishing_service.py &
PYTHON_PID=$!
echo "[*] Phishing service PID: $PYTHON_PID"

# Wait for Python to be ready
sleep 4

# Start Go web server - use PORT from env (Render sets this), default 8080
PORT="${PORT:-8080}"
echo "[*] Starting OmniCTI Web Server (Go) on port $PORT..."
./domain-intel -http ":$PORT"

# Cleanup on exit
kill $PYTHON_PID 2>/dev/null || true
