from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from fida.config import settings
from fida.models import Base

_engine = None
SessionLocal = None


def init_db():
    global _engine, SessionLocal
    if _engine is not None:
        return
    _engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=30)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    Base.metadata.create_all(bind=_engine)

    # Lightweight sanity query
    with _engine.connect() as c:
        c.execute(text("SELECT 1"))


def get_db():
    if SessionLocal is None:
        init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def engine():
    if _engine is None:
        init_db()
    return _engine
