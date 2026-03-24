"""
API & Dashboard Server – provides /api/* endpoints and serves static dashboard.
Runs on port 8000. No authentication required (demo purpose).
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import uvicorn

from db.connection import init_db
from api.routes import logs, stats, blocked_ips, config, alerts
from config import API_PORT

app = FastAPI(title="WAF Dashboard API", docs_url="/api-docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()
    print(f"[API] Dashboard & API running on port {API_PORT}")


# ── API Routes (no auth) ──
app.include_router(logs.router,       prefix="/api")
app.include_router(stats.router,      prefix="/api")
app.include_router(blocked_ips.router, prefix="/api")
app.include_router(config.router,     prefix="/api")
app.include_router(alerts.router,     prefix="/api")

# ── Static Dashboard ──
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
dashboard_dir = os.path.join(os.path.dirname(_THIS_DIR), "dashboard")
app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")


@app.get("/")
def root():
    return RedirectResponse(url="/dashboard/index.html")


if __name__ == "__main__":
    uvicorn.run("api.server:app", host="0.0.0.0", port=API_PORT, reload=True)
