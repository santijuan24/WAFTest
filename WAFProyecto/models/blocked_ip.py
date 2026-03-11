from database import db
from datetime import datetime


class BlockedIP(db.Model):
    """Tracks IP addresses that have been blocked by the WAF."""

    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(512), nullable=True)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)  # None = permanent block
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
        }

    def __repr__(self):
        return f"<BlockedIP {self.ip_address} active={self.is_active}>"
