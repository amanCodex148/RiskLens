"""
PostgreSQL Database Package for RiskLens Platform.
Provides connection pooling (psycopg-pool), SQLAlchemy ORM models, and schema migrations.
"""
from backend.db.connection import (
    get_database_url,
    get_pool,
    get_db_connection,
    get_sa_engine,
    get_sa_session,
    init_db,
    check_db_health,
    close_db,
)
from backend.db.models import (
    Base,
    User,
    Session,
    ResetToken,
    ImportedDataset,
    ImportedAsset,
    AiChatMemory,
    AiUserPreference,
    ActiveTelemetryState,
)

__all__ = [
    "get_database_url",
    "get_pool",
    "get_db_connection",
    "get_sa_engine",
    "get_sa_session",
    "init_db",
    "check_db_health",
    "close_db",
    "Base",
    "User",
    "Session",
    "ResetToken",
    "ImportedDataset",
    "ImportedAsset",
    "AiChatMemory",
    "AiUserPreference",
    "ActiveTelemetryState",
]
