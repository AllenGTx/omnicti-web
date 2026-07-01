# ── Stage 1: Build Go binary ─────────────────────────────────────────────────
FROM golang:1.24-alpine AS go-builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o domain-intel ./cmd/domain-intel/

# ── Stage 2: Final image with Go binary + Python ──────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Go binary
COPY --from=go-builder /build/domain-intel ./domain-intel
RUN chmod +x ./domain-intel

# Copy app files
COPY phishing_service.py .
COPY RandomForest_Phishing.joblib .
COPY tfidf_phishing.joblib .
COPY scaler_phishing.joblib .
COPY internal/config/scoring.yaml ./internal/config/scoring.yaml

# Startup script: launch Python service (bg) then Go server
COPY docker-start.sh .
RUN chmod +x docker-start.sh

EXPOSE 8080

CMD ["./docker-start.sh"]
