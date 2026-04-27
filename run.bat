@echo off
REM WebGuard — one-line start (Windows)

where docker >nul 2>&1
if errorlevel 1 (
  echo Docker not found. Install Docker Desktop from https://docs.docker.com/desktop/install/windows-install/
  exit /b 1
)

echo Starting WebGuard...
docker compose up --build
