@echo off
REM Menjalankan OmniCTI secara lokal (Windows). Baca .env otomatis.
for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
  if not "%%B"=="" set "%%A=%%B"
)
start "Phishing Service" cmd /c "set PHISHING_PORT=5001&& python phishing_service.py"
timeout /t 4 >nul
go run ./cmd/domain-intel -http :8080
