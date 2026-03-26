from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from db.connection import Base


class Alerta(Base):
    """Mapea la tabla alertas de sentinel_waf."""
    __tablename__ = "alertas"

    id_alerta        = Column(Integer, primary_key=True, autoincrement=True)
    id_log           = Column(Integer, ForeignKey("peticiones_log.id_log", ondelete="CASCADE", onupdate="CASCADE"), nullable=False)
    nivel_criticidad = Column(String(20), nullable=True)
    mensaje          = Column(String(255), nullable=True)
    revisada         = Column(Boolean, nullable=False, default=False)
    fecha_generacion = Column(DateTime, nullable=False, default=datetime.utcnow)

    log = relationship("PeticionLog", backref="alertas", lazy=True)

    def to_dict(self):
        return {
            "id_alerta":        self.id_alerta,
            "id_log":           self.id_log,
            "nivel_criticidad": self.nivel_criticidad,
            "mensaje":          self.mensaje,
            "revisada":         self.revisada,
            "fecha_generacion": self.fecha_generacion.isoformat() if self.fecha_generacion else None,
        }
