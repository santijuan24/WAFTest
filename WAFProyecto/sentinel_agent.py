"""
Sentinel Lightweight Agent (SDK)
Se instala en el servidor privado del cliente.
Actúa como un micro-proxy local súper rápido que pregunta a la Nube (Sentinel API) si debe dejar pasar el tráfico.

USO REAL (El cliente configura esto en su archivo .env):
SENTINEL_API_URL="http://ip-de-tu-aws:8000/api/validate"
SENTINEL_CLIENT_ID="demo-client-id-001"
SENTINEL_API_KEY="sk_test_sentinel_123456789"
TARGET_URL="http://localhost:3000"  # El backend inseguro del cliente
"""

import os
import uvicorn
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

# Configuración del Cliente
SENTINEL_API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000/api/validate")
SENTINEL_CLIENT_ID = os.getenv("SENTINEL_CLIENT_ID", "demo-client-id-001")
SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "sk_test_sentinel_123456789")
TARGET_URL = os.getenv("TARGET_URL", "http://127.0.0.1:3000")  # Donde de verdad corre su app

app = FastAPI(title="Sentinel WAF Local Agent", docs_url=None, redoc_url=None)

# Cliente asíncrono optimizado para mantener conexiones vivas (baja latencia)
http_client = httpx.AsyncClient(base_url=TARGET_URL, timeout=15.0)
sentinel_client = httpx.AsyncClient(timeout=2.0)  # Peticiones al WAF deben ser ultrarápidas

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def agent_interceptor(request: Request, full_path: str):
    # 1. Extraer los datos de la petición HTTP del usuario
    client_ip = request.client.host if request.client else "127.0.0.1"
    method = request.method
    endpoint = f"/{full_path}"
    if request.url.query:
        endpoint += f"?{request.url.query}"
    
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # 2. Leer el cuerpo de la petición (si existe)
    body_bytes = await request.body()
    try:
        body_str = body_bytes.decode('utf-8')
    except:
        body_str = str(body_bytes)

    # 3. Empaquetarlo y mandarlo a la Nube de Sentinel (AWS) para validación
    payload_to_validate = {
        "client_id": SENTINEL_CLIENT_ID,
        "api_key": SENTINEL_API_KEY,
        "ip_address": client_ip,
        "method": method,
        "endpoint": endpoint,
        "user_agent": user_agent,
        "payload": endpoint + " " + body_str  # Se junta todo lo evaluable para el Regex
    }

    try:
        # Hacemos la llamada al cerebro (API /validate) central
        val_resp = await sentinel_client.post(SENTINEL_API_URL, json=payload_to_validate)
        if val_resp.status_code == 401:
            print("[Agent] Error crítico: Credenciales inválidas o plan expirado.")
            return JSONResponse(status_code=500, content={"error": "WAF Agent Configuration Error"})
            
        verdict = val_resp.json()
    except Exception as e:
        # En caso de que se caiga el servidor principal de Sentinel WAF, 
        # pasamos a modo Failsafe (Dejar pasar o bloquear todo según política)
        print(f"[Agent] Falla de conexión a la nube Sentinel: {e}")
        return JSONResponse(status_code=502, content={"error": "WAF API Unreachable"})

    # 4. Decisión del cerebro en la nube
    if verdict.get("action") == "block":
        print(f"[Agent] Tráfico bloqueado por Sentinel Cloud. IP: {client_ip} Razón: {verdict.get('reason')}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "Acceso Bloqueado por Sentinel WAF Cloud",
                "risk_score": verdict.get("risk_score"),
                "reason": verdict.get("reason", "Violación de política")
            }
        )

    # 5. Si está limpio (action == 'allow'), redirigir silenciosamente al Target original del cliente
    print(f"[Agent] Tráfico legítimo verificado. Reenviando al Target > {endpoint}")
    headers_dict = dict(request.headers)
    
    # Rebotar la solicitud limpiamente al servidor original (ej: puero 3000)
    target_req = http_client.build_request(
        method=request.method,
        url=endpoint,
        headers=headers_dict,
        content=body_bytes
    )
    
    try:
        real_response = await http_client.send(target_req)
        return Response(
            content=real_response.content,
            status_code=real_response.status_code,
            headers=dict(real_response.headers)
        )
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "Target Backend Offline"})


if __name__ == "__main__":
    # El Agente Corre en el puerto 80 del servidor del Cliente, recibiendo todo el tráfico de internet
    print("[Sentinel Agent] Iniciando Interceptor Local...")
    uvicorn.run("sentinel_agent:app", host="0.0.0.0", port=80, reload=True)
