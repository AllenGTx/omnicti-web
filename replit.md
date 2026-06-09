# OmniCTI Security Suite

## Overview
OmniCTI adalah platform Cyber Threat Intelligence (CTI) berbasis web yang terdiri dari dua fitur utama:
1. **Domain Security Checker** — Analisis keamanan domain menggunakan 9 sumber CTI (Shodan, VirusTotal, AbuseIPDB, Censys, dll) dengan AI Risk Assessment via Gemini.
2. **Phishing Detector** — Deteksi URL phishing menggunakan Machine Learning (TF-IDF + Random Forest) + analisis heuristik + AI via Groq.

## Architecture
- **Go Web Server** (port 5000) — Handles semua HTTP request, domain scanning, AI analysis, dan proxy ke phishing service.
- **Python Phishing Service** (port 5001, internal) — ML inference menggunakan 3 joblib models (RandomForest, TF-IDF, Scaler).

## Running the App
```bash
bash start.sh
```
Ini akan menjalankan:
1. Python phishing service di port 5001 (internal)
2. Go web server di port 5000 (public)

## API Keys Required (Replit Secrets)
- `GEMINI_API_KEY` — Google Gemini AI (untuk domain analysis)
- `VIRUSTOTAL_KEY` — VirusTotal CTI source
- `SHODAN_KEY` — Shodan CTI source
- `ABUSEIPDB_KEY` — AbuseIPDB CTI source
- `GROQ_API_KEY` — Groq AI (untuk phishing analysis)

## Key Files
- `start.sh` — Startup script (run both services)
- `domain-intel` — Compiled Go binary
- `internal/server/server.go` — HTTP handlers + phishing proxy
- `internal/ai/client.go` — AI client (Gemini via REST, Groq/OpenAI via SDK)
- `phishing_service.py` — Python ML service
- `*.joblib` — Pre-trained ML models (RandomForest, TF-IDF, Scaler)
- `internal/config/scoring.yaml` — Risk scoring configuration

## User Preferences
- Jangan ubah style UI apapun
