"""
API routes – alerts.py
GET    /alerts/              – listar alertas
POST   /alerts/{id}/read     – marcar como revisada
DELETE /alerts/clear          – borrar todas las alertas
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db.connection import get_db
from db.models.alert import Alerta

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/")
def list_alerts(
    unread_only: bool = False,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Retorna alertas de seguridad, las más recientes primero."""
    q = db.query(Alerta)
    if unread_only:
        q = q.filter(Alerta.revisada == False)  # noqa
    rows = q.order_by(Alerta.fecha_generacion.desc()).limit(limit).all()
    return [r.to_dict() for r in rows]


@router.post("/{alert_id}/read")
def mark_read(alert_id: int, db: Session = Depends(get_db)):
    """Marca una alerta como revisada."""
    row = db.query(Alerta).filter(Alerta.id_alerta == alert_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    row.revisada = True
    db.commit()
    return {"ok": True, "id": alert_id}


@router.post("/read-all")
def mark_all_read(db: Session = Depends(get_db)):
    """Marca todas las alertas como revisadas."""
    db.query(Alerta).update({"revisada": True})
    db.commit()
    return {"ok": True}


@router.delete("/clear")
def clear_alerts(db: Session = Depends(get_db)):
    """Borra todas las alertas."""
    count = db.query(Alerta).delete()
    db.commit()
    return {"deleted": count}
