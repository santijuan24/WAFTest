"""
Pydantic schemas – validación de entradas y serialización de respuestas.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr


# ── Request analysis ──────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    source_ip: str
    method: str
    path: str
    user_agent: Optional[str] = None
    body: Optional[str] = None
    headers: Optional[dict] = None


class AnalyzeResponse(BaseModel):
    is_malicious: bool
    attack_type: Optional[str]
    risk_score: float
    action: str          # "allow" | "block"
    message: str


# ── Attack log ────────────────────────────────────────────────────────────────
class AttackLogBase(BaseModel):
    source_ip: str
    method: str
    path: str
    user_agent: Optional[str] = None
    attack_type: Optional[str] = None
    payload: Optional[str] = None
    risk_score: float = 0.0
    action: str = "allow"
    status_code: Optional[int] = None


class AttackLogCreate(AttackLogBase):
    pass


class AttackLogOut(AttackLogBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


# ── BlockedIP ─────────────────────────────────────────────────────────────────
class BlockedIPCreate(BaseModel):
    ip_address: str
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class BlockedIPOut(BaseModel):
    id: int
    ip_address: str
    reason: Optional[str]
    blocked_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True


# ── Stats ─────────────────────────────────────────────────────────────────────
class StatsOut(BaseModel):
    total_requests_analyzed: int
    total_attacks_detected: int
    total_blocked_ips: int
    attacks_by_type: dict


# ── Report attack (desde cliente externo) ─────────────────────────────────────
class ReportAttackRequest(BaseModel):
    source_ip: str
    method: str
    path: str
    attack_type: str
    payload: Optional[str] = None
    user_agent: Optional[str] = None
