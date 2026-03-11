"""
Database connection – shared by all three components.
Import `engine`, `SessionLocal`, `Base`, and `get_db` from here.
"""

import sys
import os

# Allow importing config.py from the project root regardless of cwd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=False,   # set True to debug SQL statements
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
    Create all tables that have been registered with Base.
    Import models before calling this function.
    """
    # Lazy-import every model so they register with Base
    from models import request_log, blocked_ip, alert, system_config  # noqa: F401
    Base.metadata.create_all(bind=engine)
