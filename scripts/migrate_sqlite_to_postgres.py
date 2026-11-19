#!/usr/bin/env python3
"""
RiskLens SQLite to PostgreSQL Complete Migration Script.
Transfers all existing users, active sessions, reset tokens, imported datasets,
imported assets, AI chat memory, and user preferences from SQLite to PostgreSQL.
"""

import os
import sys
import sqlite3
import logging
from typing import Optional

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.db.connection import get_db_connection, init_db, get_database_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger("risklens.migration")

DEFAULT_SQLITE_PATH = os.path.join(PROJECT_ROOT, "data", "risklens_users.db")


def migrate_sqlite_to_postgres(sqlite_path: str = DEFAULT_SQLITE_PATH, postgres_url: Optional[str] = None):
    if not os.path.exists(sqlite_path):
        logger.warning(f"SQLite database file not found at: {sqlite_path}. Nothing to migrate.")
        return

    logger.info("==========================================================")
    logger.info(f" Starting RiskLens Migration from SQLite to PostgreSQL")
    logger.info(f" Source SQLite DB : {sqlite_path}")
    target_url = postgres_url or get_database_url()
    logger.info(f" Target PostgreSQL: {target_url.split('@')[-1] if '@' in target_url else target_url}")
    logger.info("==========================================================")

    init_db()

    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    with get_db_connection(target_url) as pg_conn:
        # 1. Migrate Users
        try:
            users = sqlite_conn.execute("SELECT * FROM users").fetchall()
            logger.info(f"Migrating {len(users)} users...")
            for u in users:
                pg_conn.execute("""
                    INSERT INTO users (email, user_id, full_name, organization, role, salt, hashed_password, created_at, last_login_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (email) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        full_name = EXCLUDED.full_name,
                        organization = EXCLUDED.organization,
                        role = EXCLUDED.role,
                        salt = EXCLUDED.salt,
                        hashed_password = EXCLUDED.hashed_password,
                        created_at = EXCLUDED.created_at,
                        last_login_at = EXCLUDED.last_login_at;
                """, (
                    u["email"], u["user_id"], u["full_name"], u["organization"],
                    u["role"], u["salt"], u["hashed_password"], u["created_at"],
                    u["last_login_at"]
                ))
            logger.info(" Users migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'users' not present in SQLite DB, skipping.")

        # 2. Migrate Sessions
        try:
            sessions = sqlite_conn.execute("SELECT * FROM sessions").fetchall()
            logger.info(f"Migrating {len(sessions)} sessions...")
            for s in sessions:
                pg_conn.execute("""
                    INSERT INTO sessions (token, email, created_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (token) DO UPDATE SET
                        email = EXCLUDED.email,
                        created_at = EXCLUDED.created_at;
                """, (s["token"], s["email"], s["created_at"]))
            logger.info(" Sessions migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'sessions' not present in SQLite DB, skipping.")

        # 3. Migrate Reset Tokens
        try:
            tokens = sqlite_conn.execute("SELECT * FROM reset_tokens").fetchall()
            logger.info(f"Migrating {len(tokens)} reset tokens...")
            for t in tokens:
                pg_conn.execute("""
                    INSERT INTO reset_tokens (token, email, created_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (token) DO UPDATE SET
                        email = EXCLUDED.email,
                        created_at = EXCLUDED.created_at;
                """, (t["token"], t["email"], t["created_at"]))
            logger.info(" Reset tokens migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'reset_tokens' not present in SQLite DB, skipping.")

        # 4. Migrate Imported Datasets
        try:
            datasets = sqlite_conn.execute("SELECT * FROM imported_datasets").fetchall()
            logger.info(f"Migrating {len(datasets)} imported datasets...")
            for d in datasets:
                pg_conn.execute("""
                    INSERT INTO imported_datasets (
                        dataset_id, name, normalized_name, sector, content_fingerprint,
                        raw_content_hash, format, asset_count, total_cves,
                        recalculated_eal_inr, recalculated_risk_score, created_at, imported_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (dataset_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        normalized_name = EXCLUDED.normalized_name,
                        sector = EXCLUDED.sector,
                        content_fingerprint = EXCLUDED.content_fingerprint,
                        raw_content_hash = EXCLUDED.raw_content_hash,
                        format = EXCLUDED.format,
                        asset_count = EXCLUDED.asset_count,
                        total_cves = EXCLUDED.total_cves,
                        recalculated_eal_inr = EXCLUDED.recalculated_eal_inr,
                        recalculated_risk_score = EXCLUDED.recalculated_risk_score,
                        created_at = EXCLUDED.created_at,
                        imported_by = EXCLUDED.imported_by;
                """, (
                    d["dataset_id"], d["name"], d["normalized_name"], d["sector"],
                    d["content_fingerprint"], d["raw_content_hash"], d["format"],
                    d["asset_count"], d["total_cves"], d["recalculated_eal_inr"],
                    d["recalculated_risk_score"], d["created_at"], d["imported_by"]
                ))
            logger.info(" Imported datasets migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'imported_datasets' not present in SQLite DB, skipping.")

        # 5. Migrate Imported Assets
        try:
            assets = sqlite_conn.execute("SELECT * FROM imported_assets").fetchall()
            logger.info(f"Migrating {len(assets)} imported assets...")
            for a in assets:
                pg_conn.execute("""
                    INSERT INTO imported_assets (
                        id, dataset_id, asset_id, name, business_unit, criticality,
                        revenue_per_hour_inr, pii_records_count, data_classification,
                        rto_hours, rpo_hours, ip_or_endpoint, cloud_provider,
                        cve_ids, raw_asset_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        dataset_id = EXCLUDED.dataset_id,
                        asset_id = EXCLUDED.asset_id,
                        name = EXCLUDED.name,
                        business_unit = EXCLUDED.business_unit,
                        criticality = EXCLUDED.criticality,
                        revenue_per_hour_inr = EXCLUDED.revenue_per_hour_inr,
                        pii_records_count = EXCLUDED.pii_records_count,
                        data_classification = EXCLUDED.data_classification,
                        rto_hours = EXCLUDED.rto_hours,
                        rpo_hours = EXCLUDED.rpo_hours,
                        ip_or_endpoint = EXCLUDED.ip_or_endpoint,
                        cloud_provider = EXCLUDED.cloud_provider,
                        cve_ids = EXCLUDED.cve_ids,
                        raw_asset_json = EXCLUDED.raw_asset_json,
                        created_at = EXCLUDED.created_at;
                """, (
                    a["id"], a["dataset_id"], a["asset_id"], a["name"],
                    a["business_unit"], a["criticality"], a["revenue_per_hour_inr"],
                    a["pii_records_count"], a["data_classification"],
                    a["rto_hours"], a["rpo_hours"], a["ip_or_endpoint"],
                    a["cloud_provider"], a["cve_ids"], a["raw_asset_json"],
                    a["created_at"]
                ))
            pg_conn.execute("""
                SELECT setval(pg_get_serial_sequence('imported_assets', 'id'), COALESCE((SELECT MAX(id) FROM imported_assets), 1));
            """)
            logger.info(" Imported assets migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'imported_assets' not present in SQLite DB, skipping.")

        # 6. Migrate AI Chat Memory
        try:
            chats = sqlite_conn.execute("SELECT * FROM ai_chat_memory").fetchall()
            logger.info(f"Migrating {len(chats)} AI chat memory records...")
            for c in chats:
                pg_conn.execute("""
                    INSERT INTO ai_chat_memory (id, session_id, user_email, role, content, created_at, metadata_json)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        session_id = EXCLUDED.session_id,
                        user_email = EXCLUDED.user_email,
                        role = EXCLUDED.role,
                        content = EXCLUDED.content,
                        created_at = EXCLUDED.created_at,
                        metadata_json = EXCLUDED.metadata_json;
                """, (
                    c["id"], c["session_id"], c["user_email"], c["role"],
                    c["content"], c["created_at"], c["metadata_json"]
                ))
            pg_conn.execute("""
                SELECT setval(pg_get_serial_sequence('ai_chat_memory', 'id'), COALESCE((SELECT MAX(id) FROM ai_chat_memory), 1));
            """)
            logger.info(" AI chat memory records migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'ai_chat_memory' not present in SQLite DB, skipping.")

        # 7. Migrate AI User Preferences
        try:
            prefs = sqlite_conn.execute("SELECT * FROM ai_user_preferences").fetchall()
            logger.info(f"Migrating {len(prefs)} AI user preference records...")
            for p in prefs:
                pg_conn.execute("""
                    INSERT INTO ai_user_preferences (id, session_id, user_email, pref_key, pref_value, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (session_id, pref_key) DO UPDATE SET
                        user_email = COALESCE(EXCLUDED.user_email, ai_user_preferences.user_email),
                        pref_value = EXCLUDED.pref_value,
                        updated_at = EXCLUDED.updated_at;
                """, (
                    p["id"], p["session_id"], p["user_email"], p["pref_key"],
                    p["pref_value"], p["updated_at"]
                ))
            pg_conn.execute("""
                SELECT setval(pg_get_serial_sequence('ai_user_preferences', 'id'), COALESCE((SELECT MAX(id) FROM ai_user_preferences), 1));
            """)
            logger.info(" AI user preference records migrated successfully.")
        except sqlite3.OperationalError:
            logger.info("Table 'ai_user_preferences' not present in SQLite DB, skipping.")

    sqlite_conn.close()
    logger.info("==========================================================")
    logger.info(" Complete SQLite to PostgreSQL Migration Succeeded!")
    logger.info("==========================================================")


if __name__ == "__main__":
    sqlite_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SQLITE_PATH
    migrate_sqlite_to_postgres(sqlite_file)
