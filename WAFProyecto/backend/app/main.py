"""
WAF Backend – Entry Point
Sistema de Monitoreo y Prevención de Ataques Web
Servidor: uvicorn app.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base

# Importar modelos para que SQLAlchemy los registre antes de create_all()
from app import models  # noqa: F401

from app.routes import waf, attacks, blocked_ips, monitoring, users

# ── Inicializar aplicación ────────────────────────────────────────────────────
app = FastAPI(
    title="AI WAF System",
    description=(
        "Sistema Centralizado de Monitoreo y Prevención de Ataques Web. "
        "Detecta SQL Injection, XSS, Path Traversal y Command Injection."
    ),
    version="1.0.0",
    docs_url="/docs",        # Swagger UI
    redoc_url="/redoc",      # ReDoc
)

# ── CORS (permite consumo desde web y app móvil) ──────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # En producción, restringir a dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Crear tablas en MySQL (si no existen) ─────────────────────────────────────
@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)


# ── Rutas principales ─────────────────────────────────────────────────────────
# POST /waf/analyze-request
# POST /waf/report-attack
app.include_router(waf.router)

# GET  /attacks/
app.include_router(attacks.router)

# GET  /blocked-ips/
# POST /blocked-ips/
# DELETE /blocked-ips/{ip}
app.include_router(blocked_ips.router)

# GET  /stats/
app.include_router(monitoring.router)

# GET  /users/   (placeholder)
app.include_router(users.router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    """Liveness probe – verifica que el servidor está corriendo."""
    return {"status": "running", "system": "AI WAF System"}


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", tags=["Root"])
def root():
    return {
        "message": "AI WAF System API",
        "docs": "/docs",
        "health": "/health",
    }
