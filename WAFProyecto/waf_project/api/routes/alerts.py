"""
Admin API routes – alerts.py
GET    /alerts/            – listar alertas
POST   /alerts/{id}/read  – marcar como leída
DELETE /alerts/clear       – borrar todas las alertas
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db.connection import get_db
from db.models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/")
def list_alerts(
    unread_only: bool = False,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Retorna alertas de seguridad, las más recientes primero."""
    q = db.query(Alert)
    if unread_only:
        q = q.filter(Alert.is_read == False)  # noqa
    rows = q.order_by(Alert.timestamp.desc()).limit(limit).all()
    return [r.to_dict() for r in rows]


@router.post("/{alert_id}/read")
def mark_read(alert_id: int, db: Session = Depends(get_db)):
    """Marca una alerta como leída."""
    row = db.query(Alert).filter(Alert.id == alert_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    row.is_read = True
    db.commit()
    return {"ok": True, "id": alert_id}


@router.post("/read-all")
def mark_all_read(db: Session = Depends(get_db)):
    """Marca todas las alertas como leídas."""
    db.query(Alert).update({"is_read": True})
    db.commit()
    return {"ok": True}


@router.delete("/clear")
def clear_alerts(db: Session = Depends(get_db)):
    """Borra todas las alertas."""
    count = db.query(Alert).delete()
    db.commit()
    return {"deleted": count}
