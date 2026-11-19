"""
Central PostgreSQL Connection Management, Connection Pooling, and Schema Initialization for RiskLens.
Provides ACID transaction safety, connection pooling (psycopg-pool), and automatic schema migration.
"""

import os
import atexit
import logging
from contextlib import contextmanager
from typing import Optional, Generator
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session as SASession

logger = logging.getLogger("risklens.db")

# Global singleton connection pool & SQLAlchemy engine
_pool: Optional[ConnectionPool] = None
_current_db_url: Optional[str] = None
_sa_engine: Optional[Engine] = None
_sa_session_factory = None


def get_sa_engine(db_url: Optional[str] = None) -> Engine:
    """Returns singleton SQLAlchemy Engine backed by psycopg driver."""
    global _sa_engine
    target_url = db_url or get_database_url()
    if _sa_engine is None:
        if target_url.startswith("postgresql://"):
            sa_url = target_url.replace("postgresql://", "postgresql+psycopg://", 1)
        elif target_url.startswith("postgres://"):
            sa_url = target_url.replace("postgres://", "postgresql+psycopg://", 1)
        else:
            sa_url = target_url
        _sa_engine = create_engine(sa_url, pool_size=10, max_overflow=20)
    return _sa_engine


def get_sa_session(db_url: Optional[str] = None) -> SASession:
    """Creates a new SQLAlchemy ORM session."""
    global _sa_session_factory
    engine = get_sa_engine(db_url)
    if _sa_session_factory is None:
        _sa_session_factory = sessionmaker(bind=engine)
    return _sa_session_factory()



def get_database_url() -> str:
    """
    Resolves PostgreSQL connection string from environment variables:
    1. DATABASE_URL
    2. RISKLENS_DATABASE_URL
    3. POSTGRES_URL
    4. Individual components: POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB
    """
    url = (
        os.environ.get("DATABASE_URL")
        or os.environ.get("RISKLENS_DATABASE_URL")
        or os.environ.get("POSTGRES_URL")
    )
    if url:
        return url

    user = os.environ.get("POSTGRES_USER", "risklens")
    password = os.environ.get("POSTGRES_PASSWORD", "risklens_password")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    dbname = os.environ.get("POSTGRES_DB", "risklens")
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


DDL_STATEMENTS = """
-- Users table: credentials, enterprise roles, and cryptographic salts
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    organization TEXT NOT NULL,
    role TEXT NOT NULL,
    salt TEXT NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));

-- Sessions table: active enterprise bearer tokens
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);

-- Reset tokens table: password recovery OTPs with TTL
CREATE TABLE IF NOT EXISTS reset_tokens (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reset_email ON reset_tokens(email);

-- Imported datasets table: catalog of uploaded enterprise risk dossiers
CREATE TABLE IF NOT EXISTS imported_datasets (
    dataset_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    sector TEXT NOT NULL,
    content_fingerprint TEXT NOT NULL,
    raw_content_hash TEXT NOT NULL,
    format TEXT NOT NULL,
    asset_count INTEGER NOT NULL,
    total_cves INTEGER NOT NULL,
    recalculated_eal_inr DOUBLE PRECISION NOT NULL,
    recalculated_risk_score DOUBLE PRECISION NOT NULL,
    created_at TEXT NOT NULL,
    imported_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_imported_datasets_fingerprint ON imported_datasets(content_fingerprint);
CREATE INDEX IF NOT EXISTS idx_imported_datasets_norm_name ON imported_datasets(normalized_name);
CREATE INDEX IF NOT EXISTS idx_imported_datasets_name_lower ON imported_datasets(LOWER(name));

-- Imported assets table: granular telemetry records belonging to imported datasets
CREATE TABLE IF NOT EXISTS imported_assets (
    id SERIAL PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES imported_datasets(dataset_id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    business_unit TEXT NOT NULL,
    criticality TEXT NOT NULL,
    revenue_per_hour_inr DOUBLE PRECISION NOT NULL,
    pii_records_count BIGINT NOT NULL,
    data_classification TEXT,
    rto_hours DOUBLE PRECISION,
    rpo_hours DOUBLE PRECISION,
    ip_or_endpoint TEXT,
    cloud_provider TEXT,
    cve_ids TEXT,
    raw_asset_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_imported_assets_dataset ON imported_assets(dataset_id);

-- AI Chat Memory table: multi-turn conversational history for AI Copilot
CREATE TABLE IF NOT EXISTS ai_chat_memory (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_email TEXT,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_mem_session ON ai_chat_memory(session_id);
CREATE INDEX IF NOT EXISTS idx_ai_mem_user ON ai_chat_memory(user_email);

-- AI User Preferences table: learned personas, budget limits, compliance mandates
CREATE TABLE IF NOT EXISTS ai_user_preferences (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_email TEXT,
    pref_key TEXT NOT NULL,
    pref_value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CONSTRAINT uq_session_pref UNIQUE (session_id, pref_key)
);
CREATE INDEX IF NOT EXISTS idx_ai_pref_session ON ai_user_preferences(session_id);

-- Active telemetry state table: replaces custom_assets.json & custom_metadata.json files
CREATE TABLE IF NOT EXISTS active_telemetry_state (
    key TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

"""


def init_db(pool_or_conn=None) -> None:
    """Executes idempotent PostgreSQL DDL schema initialization."""
    target_pool = pool_or_conn or get_pool()
    if isinstance(target_pool, ConnectionPool):
        with target_pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(DDL_STATEMENTS)
    else:
        with target_pool.cursor() as cur:
            cur.execute(DDL_STATEMENTS)
    logger.info("PostgreSQL schema initialization completed successfully.")


def get_pool(db_url: Optional[str] = None) -> ConnectionPool:
    """Retrieves or initializes the global psycopg ConnectionPool."""
    global _pool, _current_db_url
    target_url = db_url or get_database_url()

    if _pool is None or _current_db_url != target_url or _pool.closed:
        if _pool is not None and not _pool.closed:
            try:
                _pool.close()
            except Exception:
                pass
        _current_db_url = target_url
        _pool = ConnectionPool(
            target_url,
            min_size=1,
            max_size=20,
            timeout=10.0,
            kwargs={"row_factory": dict_row}
        )
        _pool.open(wait=True)
        init_db(_pool)
    return _pool


class PostgresCursorWrapper:
    def __init__(self, raw_cur):
        self._raw_cur = raw_cur

    def execute(self, query: str, params=None):
        if "?" in query:
            query = query.replace("?", "%s")
        if params is not None:
            return self._raw_cur.execute(query, params)
        return self._raw_cur.execute(query)

    def __iter__(self):
        return iter(self._raw_cur)

    def __getattr__(self, name):
        return getattr(self._raw_cur, name)


class PostgresConnectionWrapper:
    def __init__(self, raw_conn):
        self._raw_conn = raw_conn

    def execute(self, query: str, params=None):
        if "?" in query:
            query = query.replace("?", "%s")
        if params is not None:
            return self._raw_conn.execute(query, params)
        return self._raw_conn.execute(query)

    def cursor(self, *args, **kwargs):
        cur = self._raw_conn.cursor(*args, **kwargs)
        return PostgresCursorWrapper(cur)

    def commit(self):
        return self._raw_conn.commit()

    def rollback(self):
        return self._raw_conn.rollback()

    def close(self):
        return self._raw_conn.close()

    def __getattr__(self, name):
        return getattr(self._raw_conn, name)


@contextmanager
def get_db_connection(db_url: Optional[str] = None) -> Generator[PostgresConnectionWrapper, None, None]:
    """
    Context manager yielding a connection from the pool.
    Commits automatically on normal exit, rolls back on exception.
    Transparently supports both PostgreSQL %s and legacy ? parameter placeholders.
    """
    pool = get_pool(db_url)
    with pool.connection() as conn:
        wrapper = PostgresConnectionWrapper(conn)
        try:
            yield wrapper
        except Exception:
            conn.rollback()
            raise


def check_db_health(db_url: Optional[str] = None) -> bool:
    """Performs ping probe against PostgreSQL."""
    try:
        with get_db_connection(db_url) as conn:
            row = conn.execute("SELECT 1 AS ping").fetchone()
            return bool(row and row.get("ping") == 1)
    except Exception as e:
        logger.warning(f"PostgreSQL healthcheck probe failed: {e}")
        return False


def close_db() -> None:
    """Closes all connections in the pool cleanly."""
    global _pool
    if _pool is not None and not _pool.closed:
        try:
            _pool.close()
            logger.info("PostgreSQL connection pool closed successfully.")
        except Exception as e:
            logger.warning(f"Error closing PostgreSQL connection pool: {e}")
        finally:
            _pool = None


atexit.register(close_db)
