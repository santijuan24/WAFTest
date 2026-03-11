"""
Ruta: GET /attacks

Retorna el historial de eventos de ataque registrados.
"""

from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud

router = APIRouter(prefix="/attacks", tags=["Attack Logs"])


@router.get("/", response_model=List[schemas.AttackLogOut])
def get_attacks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Retorna los últimos registros de ataques (más recientes primero)."""
    return crud.get_attack_logs(db, skip=skip, limit=limit)
