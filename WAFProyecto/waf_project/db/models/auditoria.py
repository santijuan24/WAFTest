from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from db.connection import Base


class AuditoriaSistema(Base):
    __tablename__ = "auditoria_sistema"

    id_auditoria   = Column(Integer, primary_key=True, autoincrement=True)
    tabla_afectada = Column(String(50), nullable=False)
    accion         = Column(String(50), nullable=False)
    detalle_cambio = Column(String(255), nullable=True)
    fecha_hora     = Column(DateTime, nullable=False, default=datetime.utcnow)
    usuario_db     = Column(String(50), nullable=True)

    def to_dict(self):
        return {
            "id_auditoria":   self.id_auditoria,
            "tabla_afectada": self.tabla_afectada,
            "accion":         self.accion,
            "detalle_cambio": self.detalle_cambio,
            "fecha_hora":     self.fecha_hora.isoformat() if self.fecha_hora else None,
            "usuario_db":     self.usuario_db,
        }
