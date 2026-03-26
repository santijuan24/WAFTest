from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

from db.connection import get_db, call_sp_procesar_peticion
from core.detection.scoring import evaluate, ScoringResult
from config import ATTACK_TYPE_MAP, is_waf_enabled
from db.models.cliente import Cliente

router = APIRouter(tags=["Agent SDK"])

class ValidateRequest(BaseModel):
    client_id: str
    api_key: str
    ip_address: str
    method: str
    endpoint: str
    user_agent: Optional[str] = "Sentinel Agent / 1.0"
    payload: str  # Combine headers, query params and body here for checking

@router.post("/validate")
def validate_agent_request(req: ValidateRequest, db=Depends(get_db)):
    # 1. Autenticación del Cliente (Validar client_id + api_key en tabla `clientes`)
    if not req.client_id or not req.api_key:
        raise HTTPException(status_code=401, detail="Missing Client Credentials")
        
    cliente = db.query(Cliente).filter(Cliente.client_id == req.client_id, Cliente.api_key == req.api_key, Cliente.activo == True).first()
    if not cliente:
        raise HTTPException(status_code=401, detail="Invalid or Inactive Client Credentials")

    # 2. Evaluar Risk Score (Si el WAF no está bypasseado globalmente)
    if is_waf_enabled():
        result = evaluate(req.payload)
    else:
        from core.detection.scoring import ScoringResult
        result = ScoringResult(score=0.0, action="allow", level="clean", attack_type=None, rule_hits=[])

    # 3. Log en la Base de Datos Central (sentinel_waf)
    id_ataque = None
    if result.attack_type:
        id_ataque = ATTACK_TYPE_MAP.get(result.attack_type)
        
    try:
        call_sp_procesar_peticion(
            db,
            ip=req.ip_address,
            metodo=req.method.upper(),
            endpoint=req.endpoint,
            user_agent=req.user_agent,
            score=int(result.score),
            id_ataque=id_ataque
        )
    except Exception as e:
        print(f"[Validate API] Log error: {e}")
        # Not throwing exception here to ensure we return the verdict even if DB lags

    # 4. Responder al Agente Ligero
    return {
        "action": result.action,
        "risk_score": result.score,
        "reason": result.attack_type
    }
