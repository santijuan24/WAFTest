"""
API routes – stats.py
GET /stats – estadísticas globales del WAF
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from db.connection import get_db
from db.models.request_log import PeticionLog
from db.models.blocked_ip  import IPBloqueada
from db.models.alert       import Alerta
from db.models.tipo_ataque import TipoAtaque

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("/")
def get_stats(db: Session = Depends(get_db)):
    """Returns global WAF statistics."""
    total     = db.query(func.count(PeticionLog.id_log)).scalar() or 0
    blocked   = db.query(func.count(PeticionLog.id_log)).filter(PeticionLog.accion_tomada == "Bloqueada").scalar() or 0
    allowed   = total - blocked
    active_ips = db.query(func.count(IPBloqueada.ip_address)).filter(IPBloqueada.activa == True).scalar() or 0  # noqa
    unread_alerts = db.query(func.count(Alerta.id_alerta)).filter(Alerta.revisada == False).scalar() or 0  # noqa

    # Ataques por tipo (JOIN con tipos_ataque)
    by_type = (
        db.query(TipoAtaque.nombre, func.count(PeticionLog.id_log))
        .join(PeticionLog, PeticionLog.id_ataque == TipoAtaque.id_ataque)
        .group_by(TipoAtaque.nombre)
        .all()
    )
    avg_score = db.query(func.avg(PeticionLog.score_riesgo)).scalar() or 0.0

    return {
        "total_requests":       total,
        "allowed_requests":     allowed,
        "blocked_requests":     blocked,
        "active_blocked_ips":   active_ips,
        "unread_alerts":        unread_alerts,
        "average_risk_score":   round(float(avg_score), 2),
        "attacks_by_type":      {t: c for t, c in by_type},
    }
