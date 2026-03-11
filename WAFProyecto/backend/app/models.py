"""
SQLAlchemy ORM models – tablas creadas automáticamente al iniciar la app.
Tablas: users, attack_logs, blocked_ips, waf_rules, api_keys, alerts
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float,
    DateTime, ForeignKey
)
from sqlalchemy.orm import relationship
from app.database import Base


# ──────────────────────────────────────────────────────────────────────────────
# users
# ──────────────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(200), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    api_keys = relationship("ApiKey", back_populates="user")


# ──────────────────────────────────────────────────────────────────────────────
# attack_logs
# ──────────────────────────────────────────────────────────────────────────────
class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    method = Column(String(10), nullable=False)
    path = Column(String(2048), nullable=False)
    user_agent = Column(String(512), nullable=True)
    attack_type = Column(String(100), nullable=True)     # sqli, xss, path_traversal…
    payload = Column(Text, nullable=True)                # fragmento sospechoso
    risk_score = Column(Float, default=0.0, nullable=False)
    action = Column(String(20), default="allow", nullable=False)  # allow / block
    status_code = Column(Integer, nullable=True)
    rule_id = Column(Integer, ForeignKey("waf_rules.id", ondelete="SET NULL"), nullable=True)

    rule = relationship("WafRule", back_populates="logs")
    alerts = relationship("Alert", back_populates="log")


# ──────────────────────────────────────────────────────────────────────────────
# blocked_ips
# ──────────────────────────────────────────────────────────────────────────────
class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(String(512), nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)    # None = bloqueo permanente
    is_active = Column(Boolean, default=True, nullable=False)


# ──────────────────────────────────────────────────────────────────────────────
# waf_rules
# ──────────────────────────────────────────────────────────────────────────────
class WafRule(Base):
    __tablename__ = "waf_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    pattern = Column(Text, nullable=False)           # expresión regular
    attack_type = Column(String(100), nullable=False)
    risk_score = Column(Float, default=5.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    logs = relationship("AttackLog", back_populates="rule")


# ──────────────────────────────────────────────────────────────────────────────
# api_keys
# ──────────────────────────────────────────────────────────────────────────────
class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(256), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    description = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="api_keys")


# ──────────────────────────────────────────────────────────────────────────────
# alerts
# ──────────────────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    level = Column(String(20), nullable=False)        # info / warning / critical
    message = Column(Text, nullable=False)
    source_ip = Column(String(45), nullable=True)
    log_id = Column(Integer, ForeignKey("attack_logs.id", ondelete="SET NULL"), nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)

    log = relationship("AttackLog", back_populates="alerts")
