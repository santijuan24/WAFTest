@echo off
echo ============================================
echo    WAF Project - Starting All Services
echo ============================================
echo.
echo IMPORTANT: Run this from WAFProyecto folder
echo.

echo [1/2] Starting API ^& Dashboard (Port 8000)...
start "WAF API (8000)" cmd /k "cd /d %~dp0waf_project && python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload"

ping -n 3 127.0.0.1 >nul

echo [2/2] Starting WAF Proxy (Port 8080)...
start "WAF Proxy (8080)" cmd /k "cd /d %~dp0waf_project && python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload"

echo.
echo ============================================
echo    Services Running:
echo    API + Dashboard : http://localhost:8000
echo    WAF Proxy       : http://localhost:8080
echo ============================================
echo.
pause
