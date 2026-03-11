"""
Ruta: POST /analyze-request
       POST /report-attack

Motor WAF expuesto como endpoints REST.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud
from app.waf_engine import analyze

router = APIRouter(prefix="/waf", tags=["WAF Engine"])


@router.post("/analyze-request", response_model=schemas.AnalyzeResponse)
def analyze_request(request: schemas.AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Analiza una solicitud HTTP en busca de patrones maliciosos.
    Registra el resultado en la base de datos y retorna la evaluación.
    """
    result = analyze(
        path=request.path,
        method=request.method,
        user_agent=request.user_agent or "",
        body=request.body or "",
        headers=request.headers or {},
    )

    # Persistir en attack_logs
    log_data = schemas.AttackLogCreate(
        source_ip=request.source_ip,
        method=request.method,
        path=request.path,
        user_agent=request.user_agent,
        attack_type=result.attack_type,
        payload=None,
        risk_score=result.risk_score,
        action=result.action,
    )
    crud.create_attack_log(db, log_data)

    return schemas.AnalyzeResponse(
        is_malicious=result.is_malicious,
        attack_type=result.attack_type,
        risk_score=result.risk_score,
        action=result.action,
        message=result.message,
    )


@router.post("/report-attack", response_model=schemas.AttackLogOut)
def report_attack(payload: schemas.ReportAttackRequest, db: Session = Depends(get_db)):
    """
    Endpoint para que clientes externos reporten un ataque detectado.
    """
    log_data = schemas.AttackLogCreate(
        source_ip=payload.source_ip,
        method=payload.method,
        path=payload.path,
        user_agent=payload.user_agent,
        attack_type=payload.attack_type,
        payload=payload.payload,
        risk_score=8.0,
        action="block",
    )
    return crud.create_attack_log(db, log_data)
