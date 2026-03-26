"""
WAF Proxy Server – intercepts HTTP traffic, scores requests, blocks threats.
Runs on port 8080. Forwards clean requests to the target application on port 3000.
"""

from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from db.connection import init_db, SessionLocal, call_sp_procesar_peticion
from db.models.blocked_ip import IPBloqueada

from core.detection.analyzer import RequestAnalyzer
from core.detection.scoring import evaluate

from core.proxy.handler import forward

from config import WAF_PROXY_PORT, WAF_ENABLED, ATTACK_TYPE_MAP

app = FastAPI(title="WAF Proxy Engine", docs_url=None)


@app.on_event("startup")
def startup():
    init_db()
    print(f"[WAF Proxy] Listening on port {WAF_PROXY_PORT}")
    print(f"[WAF Proxy] WAF enabled: {WAF_ENABLED}")
    print(f"[WAF Proxy] Forwarding clean requests to target application")


# ── Helpers ──
def _is_blocked(ip: str, db) -> bool:
    """Check if an IP is in the active blocklist."""
    record = (
        db.query(IPBloqueada)
        .filter(IPBloqueada.ip_address == ip, IPBloqueada.activa == True)  # noqa
        .first()
    )
    if not record:
        return False
    if record.fecha_expiracion and record.fecha_expiracion < datetime.utcnow():
        record.activa = False
        db.commit()
        return False
    return True


def _log_request(db, meta: dict, result, status_code: int):
    """
    Persist request via sp_procesar_peticion stored procedure.
    The SP handles: insert into peticiones_log, alert generation, and IP blocking.
    """
    try:
        # Map attack_type category name to id_ataque
        id_ataque = None
        if result.attack_type:
            id_ataque = ATTACK_TYPE_MAP.get(result.attack_type)

        call_sp_procesar_peticion(
            db,
            ip=meta["ip_address"],
            metodo=meta["method"],
            endpoint=meta["path"],
            user_agent=meta["user_agent"],
            score=int(result.score),
            id_ataque=id_ataque,
        )
    except Exception as e:
        print(f"[WAF] DB error: {e}")


# ── Catch-all proxy route ──
@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(full_path: str, request: Request):
    """Intercept every request, analyze, score, block or forward."""
    db = SessionLocal()
    try:
        # Extract request metadata
        meta = await RequestAnalyzer.extract(request)

        # Blocked IP check
        if WAF_ENABLED and _is_blocked(meta["ip_address"], db):
            _log_request(
                db, meta,
                type("R", (), {"score": 100, "action": "block", "level": "blocked",
                               "attack_type": "SQL Injection", "rule_hits": ["ip-blocklist"]})(),
                403,
            )
            return JSONResponse(status_code=403, content={"error": "Acceso denegado", "reason": "IP bloqueada"})

        # Score the request
        if WAF_ENABLED:
            result = evaluate(meta["payload"])
        else:
            result = type("R", (), {"score": 0.0, "action": "allow", "level": "clean",
                                    "attack_type": None, "rule_hits": []})()

        # Block if threshold exceeded
        if WAF_ENABLED and result.action == "block":
            _log_request(db, meta, result, 403)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Peticion bloqueada por WAF",
                    "attack_type": result.attack_type,
                    "risk_score": result.score,
                },
            )

        # Forward to target application
        body = await request.body()
        backend_resp = await forward(request, body)

        # Log and return
        _log_request(db, meta, result, backend_resp.status_code)
        return backend_resp

    except Exception as e:
        print(f"[WAF] Unhandled error: {e}")
        return JSONResponse(status_code=500, content={"error": "WAF internal error"})
    finally:
        db.close()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=WAF_PROXY_PORT, reload=True)
