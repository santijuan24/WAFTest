"""
Admin API routes – logs.py
GET /logs  – paginated request log history
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from db.connection import get_db
from db.models.request_log import RequestLog

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.get("/")
def get_logs(
    skip:   int = Query(0, ge=0),
    limit:  int = Query(100, ge=1, le=500),
    action: Optional[str] = Query(None, description="Filter: allow | block"),
    ip:     Optional[str] = Query(None, description="Filter by IP address"),
    db: Session = Depends(get_db),
):
    """Returns request log history, newest first."""
    q = db.query(RequestLog)
    if action:
        q = q.filter(RequestLog.action == action)
    if ip:
        q = q.filter(RequestLog.ip_address == ip)
    rows = q.order_by(RequestLog.timestamp.desc()).offset(skip).limit(limit).all()
    return [r.to_dict() for r in rows]


@router.delete("/clear")
def clear_logs(db: Session = Depends(get_db)):
    """Deletes ALL request logs."""
    count = db.query(RequestLog).delete()
    db.commit()
    return {"deleted": count}


@router.get("/{log_id}")
def get_log(log_id: int, db: Session = Depends(get_db)):
    """Returns a single log entry by ID."""
    row = db.query(RequestLog).filter(RequestLog.id == log_id).first()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Log not found")
    return row.to_dict()
