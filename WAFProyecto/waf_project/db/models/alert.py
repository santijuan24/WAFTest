from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from db.connection import Base


class Alert(Base):
    __tablename__ = "alerts"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, nullable=False)
    level      = Column(String(20), nullable=False)   # info | warning | critical
    message    = Column(Text, nullable=False)
    source_ip  = Column(String(45), nullable=True)
    log_id     = Column(Integer, ForeignKey("request_logs.id", ondelete="SET NULL"), nullable=True)
    is_read    = Column(Boolean, default=False, nullable=False)

    log = relationship("RequestLog", backref="alerts", lazy=True)

    def to_dict(self):
        return {
            "id":        self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level":     self.level,
            "message":   self.message,
            "source_ip": self.source_ip,
            "log_id":    self.log_id,
            "is_read":   self.is_read,
        }
