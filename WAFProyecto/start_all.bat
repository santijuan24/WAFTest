@echo off
REM Start WAF SIEM & Vulnerable Shop

echo Arrancando la Tienda Vulnerable (ShopVuln) en puerto 5000...
start "ShopVuln Backend (Port 5000)" cmd /c "cd /d %~dp0waf_project && python -m uvicorn test_backend.main:app --port 5000 --reload"

echo Arrancando el proxy WAF y Dashboard de Seguridad en puerto 9000...
start "WAF Proxy & Panel (Port 9000)" cmd /c "cd /d %~dp0waf_project && python -m uvicorn waf_proxy.main:app --port 9000 --reload"

echo.
echo Todos los servicios han sido lanzados.
echo ----------------------------------------------------
echo 🛒 ShopVuln (App Vulnerable): http://localhost:5000/
echo 🛡️ WAF SIEM Panel de Admin:  http://localhost:9000/dashboard/
echo ----------------------------------------------------
echo.
pause
