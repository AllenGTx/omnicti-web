#!/bin/bash
set -e

echo "[*] Starting OmniCTI Security Suite..."

cd /home/runner/workspace

# Start Python phishing service on port 5001 (internal)
echo "[*] Starting Phishing Detection Service (Python) on port 5001..."
PHISHING_PORT=5001 python3 phishing_service.py &
PYTHON_PID=$!
echo "[*] Phishing service PID: $PYTHON_PID"

# Wait for Python to be ready
sleep 3

# Start Go web server on port 5000 (public webview)
echo "[*] Starting OmniCTI Web Server (Go) on port 5000..."
./domain-intel -http :5000

# Cleanup on exit
kill $PYTHON_PID 2>/dev/null || true
