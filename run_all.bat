@echo off
title AuthzGraph Platform Launcher
echo ========================================================
echo           Launching AuthzGraph Platform
echo ========================================================
echo.

if not defined PY set "PY=python"

echo 1. Starting Backend Engine (Port 8000)...
start "AuthzGraph - Backend (8000)" cmd /k "cd /d %~dp0backend && "%PY%" -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo 2. Starting Target App (Port 8080)...
start "AuthzGraph - Target App (8080)" cmd /k "cd /d %~dp0target_app && "%PY%" -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload"

timeout /t 2 /nobreak >nul

echo 3. Starting Frontend UI (Port 5173)...
start "AuthzGraph - Frontend (5173)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ========================================================
echo  All 3 services are starting!
echo.
echo  - Frontend UI:       http://localhost:5173
echo  - Backend API Docs:  http://localhost:8000/docs
echo  - Target App (RideX): http://localhost:8080/dashboard
echo ========================================================
