from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from db.connection import Base


class PeticionLog(Base):
    """Mapea la tabla peticiones_log de sentinel_waf."""
    __tablename__ = "peticiones_log"

    id_log        = Column(Integer, primary_key=True, autoincrement=True)
    fecha_hora    = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    ip_address    = Column(String(45), nullable=False, index=True)
    metodo        = Column(String(10), nullable=False)
    endpoint      = Column(String(255), nullable=False)
    user_agent    = Column(String(255), nullable=True)
    score_riesgo  = Column(Integer, nullable=False, default=0)
    accion_tomada = Column(String(20), nullable=True)
    id_ataque     = Column(Integer, ForeignKey("tipos_ataque.id_ataque", ondelete="CASCADE", onupdate="CASCADE"), nullable=True)

    tipo_ataque = relationship("TipoAtaque", backref="peticiones", lazy=True)

    def to_dict(self):
        return {
            "id_log":        self.id_log,
            "fecha_hora":    self.fecha_hora.isoformat() if self.fecha_hora else None,
            "ip_address":    self.ip_address,
            "metodo":        self.metodo,
            "endpoint":      self.endpoint,
            "user_agent":    self.user_agent,
            "score_riesgo":  self.score_riesgo,
            "accion_tomada": self.accion_tomada,
            "id_ataque":     self.id_ataque,
            "tipo_ataque":   self.tipo_ataque.nombre if self.tipo_ataque else None,
        }
