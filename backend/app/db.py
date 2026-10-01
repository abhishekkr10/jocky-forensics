import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from .core import DATA, ROOT

LOCK = threading.RLock()
DB = DATA / "jocky.db"
def now(): return datetime.now(timezone.utc).isoformat()

def _ensure_schema(db):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone() is None:
        db.executescript((ROOT / "backend/migrations/001_initial.sql").read_text())
    version = db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] or 0
    if version < 2:
        db.executescript((ROOT / "backend/migrations/002_analysis_records.sql").read_text())
        db.execute("INSERT INTO schema_migrations VALUES(2)")

@contextmanager
def connection():
    with LOCK:
        db = sqlite3.connect(DB, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        _ensure_schema(db)
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

def initialize():
    with connection() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)")
        version = db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] or 0
        if version < 1:
            db.executescript((ROOT / "backend/migrations/001_initial.sql").read_text())
            version = 1
        if version < 2:
            db.executescript((ROOT / "backend/migrations/002_analysis_records.sql").read_text())
            db.execute("INSERT INTO schema_migrations VALUES(2)")
        db.execute("UPDATE jobs SET status='interrupted',error='Server restarted during execution',completed_at=? WHERE status IN ('queued','running')", (now(),))

def audit(user_id, action, subject=None):
    with connection() as db:
        db.execute("INSERT INTO audit_logs(user_id,action,subject,created_at) VALUES(?,?,?,?)", (user_id,action,subject,now()))
