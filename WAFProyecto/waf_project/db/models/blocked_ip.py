from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from db.connection import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id         = Column(Integer,  primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    reason     = Column(String(512), nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)          # None = permanent
    is_active  = Column(Boolean,  default=True, nullable=False)

    def to_dict(self):
        return {
            "id":         self.id,
            "ip_address": self.ip_address,
            "reason":     self.reason,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active":  self.is_active,
        }
