"""
Persistent SQLite Storage & Deduplication Engine for Imported Enterprise Datasets.
Prevents repeated/duplicate data ingestion and persists historical datasets across reloads.
"""

import os
import re
import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import List, Dict, Any, Optional, Tuple

from backend.models.schemas import Asset

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.environ.get(
    "RISKLENS_DB_PATH",
    os.path.join(PROJECT_ROOT, "data", "risklens_users.db")
)


def compute_asset_fingerprint(assets: List[Asset]) -> str:
    """
    Computes a canonical SHA-256 fingerprint representing the normalized asset telemetry.
    Invariant to row order, extra whitespace, or dataset name changes.
    """
    sorted_items = []
    for a in sorted(assets, key=lambda x: str(x.asset_id).strip().upper()):
        cve_list = sorted([str(v.cve_id).strip().upper() for v in (a.vulnerabilities or []) if v.cve_id])
        ctrl_list = sorted([
            f"{str(c.control_id).strip().upper()}:{round(float(c.telemetry_score), 2)}"
            for c in (a.controls or []) if c.control_id
        ])
        item = {
            "id": str(a.asset_id).strip().upper(),
            "name": str(a.name).strip().lower(),
            "bu": a.business_unit.value if hasattr(a.business_unit, "value") else str(a.business_unit).lower(),
            "crit": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality).lower(),
            "rev": round(float(a.revenue_per_hour_inr), 2),
            "pii": int(a.pii_records_count),
            "cves": cve_list,
            "ctrls": ctrl_list,
            "cloud": str(a.cloud_provider or "").strip().lower()
        }
        sorted_items.append(item)
    canonical = json.dumps(sorted_items, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def compute_raw_content_hash(raw_text: str) -> str:
    """Computes SHA-256 of normalized raw CSV/JSON payload."""
    normalized = re.sub(r'\s+', ' ', (raw_text or "").strip().lower())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


class ImportedDatasetStore:
    """
    ACID SQLite repository managing imported enterprise datasets.
    Provides strict duplicate prevention (both content-fingerprint and name collisions)
    and persists all historical asset telemetry.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS imported_datasets (
                    dataset_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL COLLATE NOCASE,
                    sector TEXT NOT NULL,
                    content_fingerprint TEXT NOT NULL,
                    raw_content_hash TEXT NOT NULL,
                    format TEXT NOT NULL,
                    asset_count INTEGER NOT NULL,
                    total_cves INTEGER NOT NULL,
                    recalculated_eal_inr REAL NOT NULL,
                    recalculated_risk_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    imported_by TEXT
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_imported_datasets_fingerprint 
                ON imported_datasets(content_fingerprint);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_imported_datasets_norm_name 
                ON imported_datasets(normalized_name);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS imported_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dataset_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    business_unit TEXT NOT NULL,
                    criticality TEXT NOT NULL,
                    revenue_per_hour_inr REAL NOT NULL,
                    pii_records_count INTEGER NOT NULL,
                    data_classification TEXT,
                    rto_hours REAL,
                    rpo_hours REAL,
                    ip_or_endpoint TEXT,
                    cloud_provider TEXT,
                    cve_ids TEXT,
                    raw_asset_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(dataset_id) REFERENCES imported_datasets(dataset_id) ON DELETE CASCADE
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_imported_assets_dataset 
                ON imported_assets(dataset_id);
            """)

    def check_duplicate(self, fingerprint: str, name: str) -> Optional[Dict[str, Any]]:
        """
        Validates whether identical telemetry data or an identical dataset name already exists.
        Returns duplicate details if a conflict is found, otherwise None.
        """
        norm_name = name.strip().lower()
        with self._get_conn() as conn:
            # 1. Check content fingerprint (same data regardless of name)
            row = conn.execute(
                """
                SELECT dataset_id, name, sector, created_at, asset_count, total_cves
                FROM imported_datasets
                WHERE content_fingerprint = ?
                LIMIT 1
                """,
                (fingerprint,)
            ).fetchone()
            if row:
                return {
                    "conflict_type": "content",
                    "dataset_id": row["dataset_id"],
                    "existing_name": row["name"],
                    "sector": row["sector"],
                    "created_at": row["created_at"],
                    "asset_count": row["asset_count"],
                    "total_cves": row["total_cves"]
                }

            # 2. Check name collision (same name with different data)
            row_name = conn.execute(
                """
                SELECT dataset_id, name, sector, created_at, asset_count, total_cves
                FROM imported_datasets
                WHERE normalized_name = ?
                LIMIT 1
                """,
                (norm_name,)
            ).fetchone()
            if row_name:
                return {
                    "conflict_type": "name",
                    "dataset_id": row_name["dataset_id"],
                    "existing_name": row_name["name"],
                    "sector": row_name["sector"],
                    "created_at": row_name["created_at"],
                    "asset_count": row_name["asset_count"],
                    "total_cves": row_name["total_cves"]
                }

        return None

    def save_imported_dataset(
        self,
        dataset_id: str,
        name: str,
        sector: str,
        format_type: str,
        assets: List[Asset],
        fingerprint: str,
        raw_content: str,
        recalculated_eal: float,
        risk_score: float,
        imported_by: str = "anonymous",
        overwrite: bool = False
    ) -> Dict[str, Any]:
        """
        Persists an imported dataset and its asset telemetry into the SQLite database.
        If overwrite is True, replaces existing entries with the same name or fingerprint.
        """
        norm_name = name.strip().lower()
        created_at = datetime.now(timezone.utc).isoformat()
        raw_hash = compute_raw_content_hash(raw_content)
        total_cves = sum(len(a.vulnerabilities or []) for a in assets)

        with self._get_conn() as conn:
            if overwrite:
                # Remove prior entries matching name or fingerprint
                conn.execute(
                    "DELETE FROM imported_datasets WHERE normalized_name = ? OR content_fingerprint = ?",
                    (norm_name, fingerprint)
                )

            # Insert dataset record
            conn.execute(
                """
                INSERT INTO imported_datasets (
                    dataset_id, name, normalized_name, sector, content_fingerprint,
                    raw_content_hash, format, asset_count, total_cves,
                    recalculated_eal_inr, recalculated_risk_score, created_at, imported_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dataset_id, name, norm_name, sector, fingerprint,
                    raw_hash, format_type, len(assets), total_cves,
                    recalculated_eal, risk_score, created_at, imported_by
                )
            )

            # Insert all assets
            for a in assets:
                cve_str = ";".join([v.cve_id for v in (a.vulnerabilities or []) if v.cve_id])
                asset_json = json.dumps(a.model_dump())
                conn.execute(
                    """
                    INSERT INTO imported_assets (
                        dataset_id, asset_id, name, business_unit, criticality,
                        revenue_per_hour_inr, pii_records_count, data_classification,
                        rto_hours, rpo_hours, ip_or_endpoint, cloud_provider,
                        cve_ids, raw_asset_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        dataset_id, a.asset_id, a.name,
                        a.business_unit.value if hasattr(a.business_unit, "value") else str(a.business_unit),
                        a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
                        a.revenue_per_hour_inr, a.pii_records_count, a.data_classification or "",
                        a.rto_hours or 4.0, a.rpo_hours or 1.0,
                        a.ip_or_endpoint or "", a.cloud_provider or "AWS",
                        cve_str, asset_json, created_at
                    )
                )

        return {
            "dataset_id": dataset_id,
            "name": name,
            "sector": sector,
            "asset_count": len(assets),
            "total_cves": total_cves,
            "fingerprint": fingerprint,
            "created_at": created_at
        }

    def list_imported_datasets(self) -> List[Dict[str, Any]]:
        """Returns all custom datasets saved in the database, newest first."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT dataset_id, name, sector, format, asset_count, total_cves,
                       recalculated_eal_inr, recalculated_risk_score, created_at, imported_by
                FROM imported_datasets
                ORDER BY created_at DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def get_dataset(self, dataset_id: str) -> Optional[Tuple[Dict[str, Any], List[Asset]]]:
        """Loads a saved dataset and parses its assets from SQLite."""
        with self._get_conn() as conn:
            ds_row = conn.execute(
                "SELECT * FROM imported_datasets WHERE dataset_id = ? OR LOWER(name) = ? LIMIT 1",
                (dataset_id, dataset_id.lower())
            ).fetchone()
            if not ds_row:
                return None

            asset_rows = conn.execute(
                "SELECT raw_asset_json FROM imported_assets WHERE dataset_id = ? ORDER BY id ASC",
                (ds_row["dataset_id"],)
            ).fetchall()

            assets = [Asset.model_validate_json(r["raw_asset_json"]) for r in asset_rows]
            return dict(ds_row), assets

    def delete_dataset(self, dataset_id: str) -> bool:
        """Deletes a dataset and its assets from the database."""
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM imported_datasets WHERE dataset_id = ?", (dataset_id,))
            return cursor.rowcount > 0

    def clear(self) -> int:
        """Clears all stored datasets and cascade-deletes assets (used for tests/full resets)."""
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM imported_datasets")
            return cursor.rowcount


# Global singleton instance
_dataset_store: Optional[ImportedDatasetStore] = None


def get_dataset_store(db_path: str = DEFAULT_DB_PATH) -> ImportedDatasetStore:
    global _dataset_store
    if _dataset_store is None or _dataset_store.db_path != db_path:
        _dataset_store = ImportedDatasetStore(db_path=db_path)
    return _dataset_store
