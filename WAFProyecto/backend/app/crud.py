"""
CRUD operations – acceso a base de datos separado de las rutas.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app import models, schemas


# ── AttackLog ─────────────────────────────────────────────────────────────────
def create_attack_log(db: Session, log: schemas.AttackLogCreate) -> models.AttackLog:
    db_log = models.AttackLog(**log.model_dump())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


def get_attack_logs(
    db: Session, skip: int = 0, limit: int = 100
) -> List[models.AttackLog]:
    return (
        db.query(models.AttackLog)
        .order_by(models.AttackLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_attack_logs_by_ip(db: Session, ip: str) -> List[models.AttackLog]:
    return (
        db.query(models.AttackLog)
        .filter(models.AttackLog.source_ip == ip)
        .order_by(models.AttackLog.timestamp.desc())
        .all()
    )


# ── BlockedIP ─────────────────────────────────────────────────────────────────
def block_ip(db: Session, payload: schemas.BlockedIPCreate) -> models.BlockedIP:
    # Si ya existe, reactivar
    existing = (
        db.query(models.BlockedIP)
        .filter(models.BlockedIP.ip_address == payload.ip_address)
        .first()
    )
    if existing:
        existing.is_active = True
        existing.reason = payload.reason or existing.reason
        existing.expires_at = payload.expires_at
        existing.blocked_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    db_block = models.BlockedIP(**payload.model_dump())
    db.add(db_block)
    db.commit()
    db.refresh(db_block)
    return db_block


def get_blocked_ips(db: Session, active_only: bool = True) -> List[models.BlockedIP]:
    q = db.query(models.BlockedIP)
    if active_only:
        q = q.filter(models.BlockedIP.is_active == True)  # noqa: E712
    return q.order_by(models.BlockedIP.blocked_at.desc()).all()


def is_ip_blocked(db: Session, ip: str) -> bool:
    record = (
        db.query(models.BlockedIP)
        .filter(
            models.BlockedIP.ip_address == ip,
            models.BlockedIP.is_active == True,  # noqa: E712
        )
        .first()
    )
    if not record:
        return False
    # Verificar expiración
    if record.expires_at and record.expires_at < datetime.utcnow():
        record.is_active = False
        db.commit()
        return False
    return True


def unblock_ip(db: Session, ip: str) -> Optional[models.BlockedIP]:
    record = (
        db.query(models.BlockedIP)
        .filter(models.BlockedIP.ip_address == ip)
        .first()
    )
    if record:
        record.is_active = False
        db.commit()
        db.refresh(record)
    return record


# ── Stats ─────────────────────────────────────────────────────────────────────
def get_stats(db: Session) -> dict:
    total = db.query(func.count(models.AttackLog.id)).scalar()
    attacks = (
        db.query(func.count(models.AttackLog.id))
        .filter(models.AttackLog.action == "block")
        .scalar()
    )
    blocked = (
        db.query(func.count(models.BlockedIP.id))
        .filter(models.BlockedIP.is_active == True)  # noqa: E712
        .scalar()
    )

    by_type = (
        db.query(models.AttackLog.attack_type, func.count(models.AttackLog.id))
        .filter(models.AttackLog.attack_type != None)  # noqa: E711
        .group_by(models.AttackLog.attack_type)
        .all()
    )

    return {
        "total_requests_analyzed": total or 0,
        "total_attacks_detected": attacks or 0,
        "total_blocked_ips": blocked or 0,
        "attacks_by_type": {t: c for t, c in by_type},
    }
