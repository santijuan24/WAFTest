"""
Admin API routes – blocked_ips.py
GET    /blocked-ips
POST   /blocked-ips
DELETE /blocked-ips/{ip}
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db_core.connection import get_db
from models.blocked_ip import BlockedIP

router = APIRouter(prefix="/blocked-ips", tags=["Blocked IPs"])


class BlockIPRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


@router.get("/")
def list_blocked(active_only: bool = True, db: Session = Depends(get_db)):
    q = db.query(BlockedIP)
    if active_only:
        q = q.filter(BlockedIP.is_active == True)  # noqa
    return [r.to_dict() for r in q.order_by(BlockedIP.blocked_at.desc()).all()]


@router.post("/", status_code=201)
def block_ip(payload: BlockIPRequest, db: Session = Depends(get_db)):
    existing = db.query(BlockedIP).filter(BlockedIP.ip_address == payload.ip_address).first()
    if existing:
        existing.is_active  = True
        existing.reason     = payload.reason or existing.reason
        existing.expires_at = payload.expires_at
        existing.blocked_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing.to_dict()
    record = BlockedIP(
        ip_address = payload.ip_address,
        reason     = payload.reason,
        expires_at = payload.expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record.to_dict()


@router.delete("/{ip}")
def unblock_ip(ip: str, db: Session = Depends(get_db)):
    record = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found")
    record.is_active = False
    db.commit()
    return {"message": f"IP {ip} unblocked", "ip": ip}
