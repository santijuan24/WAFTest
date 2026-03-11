"""Users route – placeholder para Fase 3 (autenticación)."""

from fastapi import APIRouter

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/")
def list_users():
    """Placeholder – la gestión de usuarios se implementa en Fase 3."""
    return {"message": "Users endpoint – coming in Phase 3"}
