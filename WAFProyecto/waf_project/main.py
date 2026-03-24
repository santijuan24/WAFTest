"""
WAF Proxy Server – intercepts HTTP traffic, scores requests, blocks threats.
Runs on port 8080. Forwards clean requests to the target application.
"""

import json
import os
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from db.connection import init_db, SessionLocal
from db.models.request_log import RequestLog
from db.models.alert import Alert
from db.models.blocked_ip import BlockedIP
from db.models.system_config import SystemConfig

from core.detection.analyzer import RequestAnalyzer
from core.detection.scoring import evaluate
from core.proxy.handler import forward

from config import WAF_PROXY_PORT

app = FastAPI(title="WAF Proxy Engine", docs_url=None)


# ── Startup: initialize DB and seed default config ──
def _seed_default_config():
    """Insert default WAF config keys if they don't exist."""
    defaults = [
        ("waf_enabled",           "true",  "Enable/disable WAF interception"),
        ("score_block_threshold", "70",    "Score >= this -> BLOCK"),
        ("score_warn_threshold",  "40",    "Score >= this -> WARN"),
        ("rules_sqli_enabled",    "true",  "SQL Injection rules active"),
        ("rules_xss_enabled",     "true",  "XSS rules active"),
        ("rules_lfi_enabled",     "true",  "LFI rules active"),
        ("auto_block_on_attack",  "true",  "Auto-block IP after confirmed attack"),
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
    print(f"[WAF Proxy] Listening on port {WAF_PROXY_PORT}")
    print(f"[WAF Proxy] Forwarding clean requests to target application")


# ── Helpers ──
def _is_blocked(ip: str, db) -> bool:
    """Check if an IP is in the active blocklist."""
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


def _log_request(db, meta: dict, result, status_code: int):
    """Persist request log and create alert if threat detected."""
    try:
        log = RequestLog(
            ip_address=meta["ip_address"],
            method=meta["method"],
            path=meta["path"],
            user_agent=meta["user_agent"],
            risk_score=result.score,
            action=result.action,
            attack_type=result.attack_type,
            rule_hits=json.dumps(result.rule_hits) if result.rule_hits else None,
            status_code=status_code,
        )
        db.add(log)
        db.flush()

        if result.level in ("warning", "blocked"):
            level = "critical" if result.level == "blocked" else "warning"
            message = (
                f"{result.attack_type or 'Suspicious'} from {meta['ip_address']} "
                f"[score={result.score}] -> {result.action.upper()}"
            )
            alert = Alert(
                level=level,
                message=message,
                source_ip=meta["ip_address"],
                log_id=log.id,
            )
            db.add(alert)

        db.commit()
    except Exception as e:
        print(f"[WAF] DB error: {e}")
        try:
            db.rollback()
        except Exception:
            pass


# ── Catch-all proxy route ──
@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(full_path: str, request: Request):
    """Intercept every request, analyze, score, block or forward."""
    db = SessionLocal()
    try:
        # Check if WAF is enabled
        conf = db.query(SystemConfig).filter(SystemConfig.key == "waf_enabled").first()
        waf_on = conf and conf.value.lower() == "true"

        # Extract request metadata
        meta = await RequestAnalyzer.extract(request)

        # Blocked IP check
        if waf_on and _is_blocked(meta["ip_address"], db):
            _log_request(
                db, meta,
                type("R", (), {"score": 100, "action": "block", "level": "blocked",
                               "attack_type": "Blocked IP", "rule_hits": ["ip-blocklist"]})(),
                403,
            )
            return JSONResponse(status_code=403, content={"error": "Access denied", "reason": "IP is blocked"})

        # Score the request
        if waf_on:
            result = evaluate(meta["payload"], db)
        else:
            result = type("R", (), {"score": 0.0, "action": "allow", "level": "clean",
                                    "attack_type": None, "rule_hits": []})()

        # Block if threshold exceeded
        if waf_on and result.action == "block":
            _log_request(db, meta, result, 403)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by WAF",
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
