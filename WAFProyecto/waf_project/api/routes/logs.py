"""
API routes – logs.py
GET /logs  – historial paginado de peticiones
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from db.connection import get_db
from db.models.request_log import PeticionLog

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.get("/")
def get_logs(
    skip:   int = Query(0, ge=0),
    limit:  int = Query(100, ge=1, le=500),
    accion: Optional[str] = Query(None, description="Filter: Permitida | Alerta | Bloqueada"),
    ip:     Optional[str] = Query(None, description="Filter by IP address"),
    db: Session = Depends(get_db),
):
    """Returns request log history, newest first."""
    q = db.query(PeticionLog)
    if accion:
        q = q.filter(PeticionLog.accion_tomada == accion)
    if ip:
        q = q.filter(PeticionLog.ip_address == ip)
    rows = q.order_by(PeticionLog.fecha_hora.desc()).offset(skip).limit(limit).all()
    return [r.to_dict() for r in rows]


@router.delete("/clear")
def clear_logs(db: Session = Depends(get_db)):
    """Deletes ALL request logs."""
    count = db.query(PeticionLog).delete()
    db.commit()
    return {"deleted": count}


@router.get("/{log_id}")
def get_log(log_id: int, db: Session = Depends(get_db)):
    """Returns a single log entry by ID."""
    row = db.query(PeticionLog).filter(PeticionLog.id_log == log_id).first()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Log not found")
    return row.to_dict()
