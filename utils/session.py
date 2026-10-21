from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base

from config.config import Configs

# Pure local SQLite engine
sqlite_path = getattr(Configs.db_config, "sqlite_path", None)
if not sqlite_path:
    sqlite_path = str(Configs.PENTEST_ROOT / "data" / "penagent.db")

p = Path(sqlite_path)
if not p.is_absolute():
    p = Configs.PENTEST_ROOT / p
p.parent.mkdir(parents=True, exist_ok=True)

db_url = f"sqlite:///{p.as_posix()}"
engine = create_engine(db_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base: DeclarativeMeta = declarative_base()


@contextmanager
def session_scope() -> Session:
    """上下文管理器用于自动获取 Session, 避免错误"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()


def with_session(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        with session_scope() as session:
            try:
                result = f(session, *args, **kwargs)
                session.commit()
                return result
            except:
                session.rollback()
                raise

    return wrapper


def create_tables():
    import db.models.session_model
    import db.models.plan_model
    import db.models.task_model
    import db.models.conversation_model
    import db.models.message_model
    Base.metadata.create_all(bind=engine)
