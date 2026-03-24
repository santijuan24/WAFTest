from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from db.connection import Base


class RequestLog(Base):
    __tablename__ = "request_logs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address  = Column(String(45),  nullable=False, index=True)
    method      = Column(String(10),  nullable=False)
    path        = Column(String(2048),nullable=False)
    user_agent  = Column(String(512), nullable=True)
    risk_score  = Column(Float,       default=0.0, nullable=False)
    action      = Column(String(10),  default="allow", nullable=False)  # allow / block
    attack_type = Column(String(100), nullable=True)
    rule_hits   = Column(Text,        nullable=True)   # JSON-encoded list of rule ids
    status_code = Column(Integer,     nullable=True)

    def to_dict(self):
        return {
            "id":          self.id,
            "timestamp":   self.timestamp.isoformat() if self.timestamp else None,
            "ip_address":  self.ip_address,
            "method":      self.method,
            "path":        self.path,
            "user_agent":  self.user_agent,
            "risk_score":  self.risk_score,
            "action":      self.action,
            "attack_type": self.attack_type,
            "rule_hits":   self.rule_hits,
            "status_code": self.status_code,
        }
