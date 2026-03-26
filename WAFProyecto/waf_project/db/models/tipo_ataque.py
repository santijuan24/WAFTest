from sqlalchemy import Column, Integer, String
from db.connection import Base


class TipoAtaque(Base):
    __tablename__ = "tipos_ataque"

    id_ataque         = Column(Integer, primary_key=True, autoincrement=True)
    nombre            = Column(String(50), nullable=False)
    descripcion       = Column(String(255), nullable=True)
    nivel_riesgo_base = Column(Integer, nullable=False, default=0)

    def to_dict(self):
        return {
            "id_ataque":         self.id_ataque,
            "nombre":            self.nombre,
            "descripcion":       self.descripcion,
            "nivel_riesgo_base": self.nivel_riesgo_base,
        }
