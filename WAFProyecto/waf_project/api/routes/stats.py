"""
Admin API routes – stats.py
GET /stats – system-wide WAF statistics
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from db.connection import get_db
from db.models.request_log import RequestLog
from db.models.blocked_ip  import BlockedIP
from db.models.alert       import Alert

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("/")
def get_stats(db: Session = Depends(get_db)):
    """Returns global WAF statistics."""
    total     = db.query(func.count(RequestLog.id)).scalar() or 0
    blocked   = db.query(func.count(RequestLog.id)).filter(RequestLog.action == "block").scalar() or 0
    allowed   = total - blocked
    active_ips = db.query(func.count(BlockedIP.id)).filter(BlockedIP.is_active == True).scalar() or 0  # noqa
    unread_alerts = db.query(func.count(Alert.id)).filter(Alert.is_read == False).scalar() or 0  # noqa

    by_type = (
        db.query(RequestLog.attack_type, func.count(RequestLog.id))
        .filter(RequestLog.attack_type != None)  # noqa
        .group_by(RequestLog.attack_type)
        .all()
    )
    avg_score = db.query(func.avg(RequestLog.risk_score)).scalar() or 0.0

    return {
        "total_requests":       total,
        "allowed_requests":     allowed,
        "blocked_requests":     blocked,
        "active_blocked_ips":   active_ips,
        "unread_alerts":        unread_alerts,
        "average_risk_score":   round(float(avg_score), 2),
        "attacks_by_type":      {t: c for t, c in by_type},
    }
