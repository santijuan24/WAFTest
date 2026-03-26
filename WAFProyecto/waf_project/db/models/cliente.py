from sqlalchemy import Column, String, Boolean, DateTime, Text, text
from db.connection import Base
from sqlalchemy.sql import func
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class Cliente(Base):
    __tablename__ = "clientes"

    client_id = Column(String(50), primary_key=True, default=generate_uuid)
    api_key = Column(String(100), unique=True, nullable=False)
    nombre_empresa = Column(String(150), nullable=False)
    target_url = Column(String(255), nullable=True)  # URL of the client's actual backend (optional for agent)
    plan = Column(String(50), default="basico")
    activo = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
