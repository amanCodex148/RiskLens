"""
SQLAlchemy ORM Models for RiskLens Enterprise Platform.
Compatible with PostgreSQL and psycopg driver.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Integer, BigInteger, Float,
    ForeignKey, UniqueConstraint, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    email = Column(Text, primary_key=True)
    user_id = Column(Text, unique=True, nullable=False)
    full_name = Column(Text, nullable=False)
    organization = Column(Text, nullable=False)
    role = Column(Text, nullable=False)
    salt = Column(Text, nullable=False)
    hashed_password = Column(Text, nullable=False)
    created_at = Column(Text, nullable=False)
    last_login_at = Column(Text, nullable=True)

    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    reset_tokens = relationship("ResetToken", back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"

    token = Column(Text, primary_key=True)
    email = Column(Text, ForeignKey("users.email", ondelete="CASCADE"), nullable=False)
    created_at = Column(Text, nullable=False)

    user = relationship("User", back_populates="sessions")


class ResetToken(Base):
    __tablename__ = "reset_tokens"

    token = Column(Text, primary_key=True)
    email = Column(Text, ForeignKey("users.email", ondelete="CASCADE"), nullable=False)
    created_at = Column(Text, nullable=False)

    user = relationship("User", back_populates="reset_tokens")


class ImportedDataset(Base):
    __tablename__ = "imported_datasets"

    dataset_id = Column(Text, primary_key=True)
    name = Column(Text, nullable=False)
    normalized_name = Column(Text, nullable=False)
    sector = Column(Text, nullable=False)
    content_fingerprint = Column(Text, nullable=False)
    raw_content_hash = Column(Text, nullable=False)
    format = Column(Text, nullable=False)
    asset_count = Column(Integer, nullable=False)
    total_cves = Column(Integer, nullable=False)
    recalculated_eal_inr = Column(Float, nullable=False)
    recalculated_risk_score = Column(Float, nullable=False)
    created_at = Column(Text, nullable=False)
    imported_by = Column(Text, nullable=True)

    assets = relationship("ImportedAsset", back_populates="dataset", cascade="all, delete-orphan")


class ImportedAsset(Base):
    __tablename__ = "imported_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(Text, ForeignKey("imported_datasets.dataset_id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    business_unit = Column(Text, nullable=False)
    criticality = Column(Text, nullable=False)
    revenue_per_hour_inr = Column(Float, nullable=False)
    pii_records_count = Column(BigInteger, nullable=False)
    data_classification = Column(Text, nullable=True)
    rto_hours = Column(Float, nullable=True)
    rpo_hours = Column(Float, nullable=True)
    ip_or_endpoint = Column(Text, nullable=True)
    cloud_provider = Column(Text, nullable=True)
    cve_ids = Column(Text, nullable=True)
    raw_asset_json = Column(Text, nullable=False)
    created_at = Column(Text, nullable=False)

    dataset = relationship("ImportedDataset", back_populates="assets")


class AiChatMemory(Base):
    __tablename__ = "ai_chat_memory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Text, nullable=False, index=True)
    user_email = Column(Text, nullable=True, index=True)
    role = Column(Text, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=True)


class AiUserPreference(Base):
    __tablename__ = "ai_user_preferences"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Text, nullable=False, index=True)
    user_email = Column(Text, nullable=True)
    pref_key = Column(Text, nullable=False)
    pref_value = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint("session_id", "pref_key", name="uq_session_pref"),
    )


class ActiveTelemetryState(Base):
    """
    Persists currently loaded enterprise assets and metadata directly in PostgreSQL,
    replacing legacy custom_assets.json and custom_metadata.json files.
    """
    __tablename__ = "active_telemetry_state"

    key = Column(Text, primary_key=True)  # 'active_assets', 'active_metadata'
    payload_json = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)
