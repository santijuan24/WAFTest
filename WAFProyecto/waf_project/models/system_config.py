from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from db_core.connection import Base


class SystemConfig(Base):
    __tablename__ = "system_config"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    key         = Column(String(100), unique=True, nullable=False)
    value       = Column(Text, nullable=True)
    description = Column(String(512), nullable=True)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id":          self.id,
            "key":         self.key,
            "value":       self.value,
            "description": self.description,
            "updated_at":  self.updated_at.isoformat() if self.updated_at else None,
        }
