"""
Rutas: GET  /blocked-ips
        POST /block-ip
        DELETE /blocked-ips/{ip}
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud

router = APIRouter(prefix="/blocked-ips", tags=["Blocked IPs"])


@router.get("/", response_model=List[schemas.BlockedIPOut])
def get_blocked_ips(
    active_only: bool = True,
    db: Session = Depends(get_db),
):
    """Lista todas las IPs bloqueadas (por defecto solo las activas)."""
    return crud.get_blocked_ips(db, active_only=active_only)


@router.post("/", response_model=schemas.BlockedIPOut, status_code=201)
def block_ip(payload: schemas.BlockedIPCreate, db: Session = Depends(get_db)):
    """Bloquea una dirección IP."""
    return crud.block_ip(db, payload)


@router.delete("/{ip}", response_model=schemas.BlockedIPOut)
def unblock_ip(ip: str, db: Session = Depends(get_db)):
    """Desbloquea (desactiva) una IP previamente bloqueada."""
    record = crud.unblock_ip(db, ip)
    if not record:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in blocked list")
    return record
