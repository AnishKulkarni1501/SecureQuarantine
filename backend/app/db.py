import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker


BASE_DIR = Path(__file__).resolve().parents[1]
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'securequarantine.db'}")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def migrate_legacy_sqlite_schema():
    """Add non-destructive columns for local prototypes created before this version."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    columns = {column["name"] for column in inspect(engine).get_columns("analyses")}
    file_columns = {column["name"] for column in inspect(engine).get_columns("files")}
    with engine.begin() as connection:
        if "stage_status" not in columns:
            connection.execute(text("ALTER TABLE analyses ADD COLUMN stage_status JSON NOT NULL DEFAULT '{}'"))
        if "correlations" not in columns:
            connection.execute(text("ALTER TABLE analyses ADD COLUMN correlations JSON NOT NULL DEFAULT '{}'"))
        if "static_metadata" not in file_columns:
            connection.execute(text("ALTER TABLE files ADD COLUMN static_metadata JSON NOT NULL DEFAULT '{}'"))
        connection.execute(text("UPDATE analyses SET stage_status=:stages WHERE stage_status='{}'"), {"stages": '{"static":"completed","decompile":"not_configured","llm4decompile":"not_configured","interpretation":"not_configured","sandbox":"not_configured","correlation":"completed"}'})


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
