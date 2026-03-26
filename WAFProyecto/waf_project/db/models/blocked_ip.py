from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime
from db.connection import Base


class IPBloqueada(Base):
    """Mapea la tabla ips_bloqueadas de sentinel_waf."""
    __tablename__ = "ips_bloqueadas"

    ip_address       = Column(String(45), primary_key=True)
    motivo           = Column(String(255), nullable=True)
    fecha_bloqueo    = Column(DateTime, nullable=False, default=datetime.utcnow)
    fecha_expiracion = Column(DateTime, nullable=True)
    activa           = Column(Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            "ip_address":       self.ip_address,
            "motivo":           self.motivo,
            "fecha_bloqueo":    self.fecha_bloqueo.isoformat() if self.fecha_bloqueo else None,
            "fecha_expiracion": self.fecha_expiracion.isoformat() if self.fecha_expiracion else None,
            "activa":           self.activa,
        }
