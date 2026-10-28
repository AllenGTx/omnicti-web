#!/bin/bash
# Menjalankan OmniCTI secara lokal (Linux/macOS). Baca .env otomatis.
set -e
[ -f .env ] && set -a && . ./.env && set +a
PHISHING_PORT=5001 python3 phishing_service.py &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT
sleep 4
go run ./cmd/domain-intel -http :8080
