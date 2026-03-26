"""
Database connection – shared by all components.
Import `engine`, `SessionLocal`, `Base`, and `get_db` from here.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency – yields a DB session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Importa modelos para que SQLAlchemy los registre.
    Las tablas ya fueron creadas por el script create_database.sql.
    """
    from db.models import TipoAtaque, PeticionLog, IPBloqueada, Alerta, AuditoriaSistema, Cliente  # noqa: F401


def call_sp_procesar_peticion(db, ip, metodo, endpoint, user_agent, score, id_ataque):
    """
    Invoca el stored procedure sp_procesar_peticion de sentinel_waf.
    El SP se encarga de insertar el log, generar alertas y bloquear IPs.
    """
    try:
        db.execute(
            text("CALL sp_procesar_peticion(:ip, :metodo, :endpoint, :ua, :score, :id_ataque)"),
            {
                "ip": ip,
                "metodo": metodo,
                "endpoint": endpoint,
                "ua": user_agent,
                "score": int(score),
                "id_ataque": id_ataque,
            },
        )
        db.commit()
    except Exception as e:
        print(f"[DB] Error calling sp_procesar_peticion: {e}")
        try:
            db.rollback()
        except Exception:
            pass
