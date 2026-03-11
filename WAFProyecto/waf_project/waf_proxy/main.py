"""
WAF Proxy – main entry point AND Admin Dashboard.
Port: 9000

Serves:
 - /api/*       : Admin endpoints (stats, logs, config, etc.)
 - /dashboard/  : Admin frontend for WAF configuration
 - /*           : Proxy endpoints forwarded to the vulnerable backend
"""

import json
import sys
import os

# Ensure project root is in path so sibling packages are importable
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(PROJECT_ROOT))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from db_core.connection import init_db, get_db, SessionLocal
from models.request_log  import RequestLog
from models.alert        import Alert
from models.blocked_ip   import BlockedIP
from models.system_config import SystemConfig

from waf_proxy.request_analyzer import RequestAnalyzer
from waf_proxy.scoring_engine   import evaluate
from waf_proxy.proxy_handler    import forward

from config import WAF_PROXY_PORT, SCORE_ALLOW, SCORE_WARN

# Import admin routes
from admin_api.routes import logs, stats, blocked_ips, config, alerts

app = FastAPI(
    title="WAF Security Panel & Proxy",
    description="WAF Proxy server which also hosts the SIEM Dashboard for administration.",
    version="2.0.0",
    docs_url="/waf-docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _seed_default_config():
    """Insert default config keys if they don't exist yet."""
    defaults = [
        ("waf_enabled",            "true",  "Habilitar / deshabilitar la interceptación del WAF"),
        ("score_block_threshold",  "70",    "Puntuación de riesgo ≥ este valor → BLOQUEAR"),
        ("score_warn_threshold",   "40",    "Puntuación de riesgo ≥ este valor → AVISO"),
        ("rules_sqli_enabled",     "true",  "Reglas de inyección SQL activas"),
        ("rules_xss_enabled",      "true",  "Reglas XSS activas"),
        ("rules_lfi_enabled",      "true",  "Reglas de LFI / recorrido de rutas activas"),
        ("auto_block_on_attack",   "true",  "Bloquear IP automáticamente tras ataque confirmado"),
    ]
    db = SessionLocal()
    try:
        for key, value, desc in defaults:
            if not db.query(SystemConfig).filter(SystemConfig.key == key).first():
                db.add(SystemConfig(key=key, value=value, description=desc))
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def startup():
    init_db()
    _seed_default_config()
    print(f"[WAF] Service running on port {WAF_PROXY_PORT}")
    print(f"[WAF] Thresholds: WARN≥{SCORE_ALLOW} | BLOCK≥{SCORE_WARN}")
    print(f"[WAF] Admin Dashboard available at /dashboard/")


# ── Include Admin Routes ──────────────────────────────────────────────────────
# Since these are included before the proxy catch-all, they won't be forwarded.
app.include_router(logs.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(blocked_ips.router, prefix="/api")
app.include_router(config.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")

# Serve SIEM dashboard static files
DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")
app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")


# ── Helper – check if IP is currently blocked ─────────────────────────────────
def _is_blocked(ip: str, db) -> bool:
    from datetime import datetime
    record = (
        db.query(BlockedIP)
        .filter(BlockedIP.ip_address == ip, BlockedIP.is_active == True)  # noqa
        .first()
    )
    if not record:
        return False
    if record.expires_at and record.expires_at < datetime.utcnow():
        record.is_active = False
        db.commit()
        return False
    return True


# ── Helper – persist log + optional alert ────────────────────────────────────
def _log_request(db, meta: dict, result, status_code: int):
    """Store the request log and create an alert when appropriate.

    Any database error is caught and printed so the proxy doesn’t silently
    swallow failures; this should make it easier to diagnose why the panel
    remains empty.
    """
    try:
        log = RequestLog(
            ip_address  = meta["ip_address"],
            method      = meta["method"],
            path        = meta["path"],
            user_agent  = meta["user_agent"],
            risk_score  = result.score,
            action      = result.action,
            attack_type = result.attack_type,
            rule_hits   = json.dumps(result.rule_hits) if result.rule_hits else None,
            status_code = status_code,
        )
        db.add(log)
        db.flush()   # get log.id before commit

        if result.level in ("warning", "blocked"):
            level   = "critical" if result.level == "blocked" else "warning"
            message = (
                f"{result.attack_type or 'Suspicious'} detected from {meta['ip_address']} "
                f"[score={result.score}] → {result.action.upper()}"
            )
            alert = Alert(
                level     = level,
                message   = message,
                source_ip = meta["ip_address"],
                log_id    = log.id,
            )
            db.add(alert)

        db.commit()
        return log
    except Exception as e:
        # log to stdout; in production you might send this to a logging system
        print(f"[WAF] database error while logging request: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return None


# ── Catch-all proxy route ─────────────────────────────────────────────────────
@app.api_route("/{full_path:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def proxy(full_path: str, request: Request):
    db = SessionLocal()
    try:
        # Check if WAF is globally disabled in config
        enabled_conf = db.query(SystemConfig).filter(SystemConfig.key == "waf_enabled").first()
        is_waf_enabled = enabled_conf and enabled_conf.value.lower() == "true"

        # 1. Extract metadata
        meta = await RequestAnalyzer.extract(request)

        # 2. Check if IP is already blocked (even if WAF disabled, blocklists might apply, but let's say WAF disables everything)
        if is_waf_enabled and _is_blocked(meta["ip_address"], db):
            _log_request(db, meta, type("R", (), {
                "score": 100, "action": "block", "level": "blocked",
                "attack_type": "Blocked IP", "rule_hits": ["ip-blocklist"],
            })(), 403)
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "IP is blocked"},
            )

        # 3. Score the request IF WAF is enabled
        if is_waf_enabled:
            result = evaluate(meta["payload"], db)
        else:
            result = type("R", (), {"score": 0.0, "action": "allow", "level": "clean", "attack_type": None, "rule_hits": []})()

        # 4. Block if threshold met
        if is_waf_enabled and result.action == "block":
            _log_request(db, meta, result, 403)
            return JSONResponse(
                status_code=403,
                content={
                    "error":       "Request blocked by WAF",
                    "attack_type": result.attack_type,
                    "risk_score":  result.score,
                },
            )

        # 5. Forward to backend
        body = await request.body()
        backend_response = await forward(request, body)

        # 6. Log the forwarded request
        _log_request(db, meta, result, backend_response.status_code)

        return backend_response

    finally:
        db.close()
