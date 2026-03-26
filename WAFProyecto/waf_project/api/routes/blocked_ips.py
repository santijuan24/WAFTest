"""
API routes – blocked_ips.py
GET    /blocked-ips
POST   /blocked-ips
DELETE /blocked-ips/{ip}
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.connection import get_db
from db.models.blocked_ip import IPBloqueada

router = APIRouter(prefix="/blocked-ips", tags=["Blocked IPs"])


class BlockIPRequest(BaseModel):
    ip_address: str
    motivo: Optional[str] = None
    horas_bloqueo: int = 24


@router.get("/")
def list_blocked(active_only: bool = True, db: Session = Depends(get_db)):
    q = db.query(IPBloqueada)
    if active_only:
        q = q.filter(IPBloqueada.activa == True)  # noqa
    return [r.to_dict() for r in q.order_by(IPBloqueada.fecha_bloqueo.desc()).all()]


@router.post("/", status_code=201)
def block_ip(payload: BlockIPRequest, db: Session = Depends(get_db)):
    existing = db.query(IPBloqueada).filter(IPBloqueada.ip_address == payload.ip_address).first()
    if existing:
        existing.activa           = True
        existing.motivo           = payload.motivo or existing.motivo
        existing.fecha_bloqueo    = datetime.utcnow()
        existing.fecha_expiracion = datetime.utcnow() + timedelta(hours=payload.horas_bloqueo)
        db.commit()
        db.refresh(existing)
        return existing.to_dict()
    record = IPBloqueada(
        ip_address       = payload.ip_address,
        motivo           = payload.motivo,
        fecha_bloqueo    = datetime.utcnow(),
        fecha_expiracion = datetime.utcnow() + timedelta(hours=payload.horas_bloqueo),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record.to_dict()


@router.delete("/{ip}")
def unblock_ip(ip: str, db: Session = Depends(get_db)):
    record = db.query(IPBloqueada).filter(IPBloqueada.ip_address == ip).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found")
    record.activa = False
    db.commit()
    return {"message": f"IP {ip} desbloqueada", "ip": ip}
