@echo off
title WAF Proxy :9000
echo Arrancando WAF Proxy (puerto 9000)...
cd /d %~dp0waf_project
python -m uvicorn waf_proxy.main:app --host 0.0.0.0 --port 9000 --reload
