"""
API & Dashboard Server – provides /api/* endpoints and serves static dashboard.
Runs on port 8000.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import uvicorn

from db.connection import init_db
from api.routes import logs, stats, blocked_ips, alerts, validate
from config import API_PORT, is_waf_enabled, set_waf_enabled
from pydantic import BaseModel
from fastapi import Request
from fastapi.responses import JSONResponse

class WafToggleState(BaseModel):
    enabled: bool

class LoginRequest(BaseModel):
    username: str
    password: str

app = FastAPI(title="WAF Dashboard API", docs_url="/api-docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/") and not path.startswith("/api/validate"):
        token = request.headers.get("Authorization")
        if not token or token != "Bearer sentinel-auth-token-12345":
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)

@app.on_event("startup")
def startup():
    init_db()
    print(f"[API] Dashboard & API running on port {API_PORT}")


# ── API Routes ──
app.include_router(logs.router,       prefix="/api")
app.include_router(stats.router,      prefix="/api")
app.include_router(blocked_ips.router, prefix="/api")
app.include_router(alerts.router,     prefix="/api")
app.include_router(validate.router,   prefix="/api")

@app.post("/api/auth/login")
def login(creds: LoginRequest):
    # Demostración del WAF: usuario fijo
    if creds.username == "admin" and creds.password == "admin123":
        return {"token": "sentinel-auth-token-12345"}
    from fastapi import HTTPException
    raise HTTPException(status_code=401, detail="Credenciales invalidas")

@app.get("/api/config/status")
def get_waf_status():
    return {"waf_enabled": is_waf_enabled()}

@app.post("/api/config/toggle")
def toggle_waf_endpoint(state: WafToggleState):
    set_waf_enabled(state.enabled)
    return {"status": "success", "waf_enabled": state.enabled}


# ── Static Dashboard ──
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
dashboard_dir = os.path.join(os.path.dirname(_THIS_DIR), "dashboard")
app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")


@app.get("/")
def root():
    return RedirectResponse(url="/dashboard/index.html")


if __name__ == "__main__":
    uvicorn.run("api.server:app", host="0.0.0.0", port=API_PORT, reload=True)
