"""
Ruta: GET /stats
Estadísticas generales del sistema WAF.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud

router = APIRouter(prefix="/stats", tags=["Monitoring"])


@router.get("/", response_model=schemas.StatsOut)
def get_stats(db: Session = Depends(get_db)):
    """
    Retorna estadísticas globales:
    - Total de solicitudes analizadas
    - Total de ataques detectados
    - Total de IPs bloqueadas activas
    - Desglose de ataques por tipo
    """
    return crud.get_stats(db)
