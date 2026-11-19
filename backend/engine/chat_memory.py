"""
Persistent Conversation Memory Store for RiskLens AI Copilot.
Stores multi-turn conversational history in SQLite so the AI remembers:
1. Past questions and answers across sessions.
2. Contextual entities (e.g., previously discussed assets, CVEs, budgets, scenarios).
3. Provides multi-turn context resolution and history management endpoints.
"""

import os
import re
import sqlite3
import json
import secrets
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = os.environ.get(
    "RISKLENS_DB_PATH",
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "data", "risklens_users.db")
    )
)


class ChatMemoryStore:
    """
    ACID-compliant persistent memory vault for the RiskLens AI Copilot.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._mem_conn = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        else:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self):
        if self._mem_conn is not None:
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
        else:
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
                CREATE TABLE IF NOT EXISTS ai_chat_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    user_email TEXT COLLATE NOCASE,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_user_preferences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    user_email TEXT COLLATE NOCASE,
                    pref_key TEXT NOT NULL,
                    pref_value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(session_id, pref_key)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_mem_session ON ai_chat_memory(session_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_mem_user ON ai_chat_memory(user_email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_pref_session ON ai_user_preferences(session_id);")
            conn.commit()

    def set_preference(
        self,
        session_id: str,
        pref_key: str,
        pref_value: str,
        user_email: Optional[str] = None
    ):
        """Sets a persistent conversational preference (e.g., role, budget_limit, compliance_focus)."""
        now_iso = datetime.now(timezone.utc).isoformat()
        email_clean = user_email.strip().lower() if user_email else None
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO ai_user_preferences (session_id, user_email, pref_key, pref_value, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id, pref_key) DO UPDATE SET
                    pref_value = excluded.pref_value,
                    user_email = COALESCE(excluded.user_email, ai_user_preferences.user_email),
                    updated_at = excluded.updated_at;
            """, (session_id, email_clean, pref_key, pref_value, now_iso))

    def get_preferences(
        self,
        session_id: Optional[str] = None,
        user_email: Optional[str] = None
    ) -> Dict[str, str]:
        """Retrieves learned user preferences and contextual parameters."""
        email_clean = user_email.strip().lower() if user_email else None
        prefs: Dict[str, str] = {}
        with self._get_conn() as conn:
            if email_clean and session_id:
                rows = conn.execute("""
                    SELECT pref_key, pref_value FROM ai_user_preferences
                    WHERE user_email = ? OR session_id = ?
                    ORDER BY id ASC
                """, (email_clean, session_id)).fetchall()
            elif email_clean:
                rows = conn.execute("SELECT pref_key, pref_value FROM ai_user_preferences WHERE user_email = ?", (email_clean,)).fetchall()
            elif session_id:
                rows = conn.execute("SELECT pref_key, pref_value FROM ai_user_preferences WHERE session_id = ?", (session_id,)).fetchall()
            else:
                return {}

        for r in rows:
            prefs[r["pref_key"]] = r["pref_value"]
        return prefs

    def extract_and_store_preferences(
        self,
        text: str,
        session_id: str,
        user_email: Optional[str] = None
    ) -> Dict[str, str]:
        """Scans user inquiry for self-declared constraints, roles, or preferences and remembers them."""
        lower = text.lower()
        extracted: Dict[str, str] = {}

        # Role / persona extraction
        if any(r in lower for r in ["i am the ciso", "i'm the ciso", "as ciso", "chief information security officer"]):
            extracted["user_role"] = "CISO"
        elif any(r in lower for r in ["risk officer", "chief risk officer", "cro"]):
            extracted["user_role"] = "Chief Risk Officer"
        elif any(r in lower for r in ["board member", "board director", "on the board"]):
            extracted["user_role"] = "Board Director"

        # Compliance mandate focus
        if "dpdp" in lower:
            extracted["compliance_focus"] = "DPDP Act 2023"
        elif "rbi" in lower:
            extracted["compliance_focus"] = "RBI Cyber Security Framework"
        elif "sebi" in lower:
            extracted["compliance_focus"] = "SEBI CSCRF"
        elif "iso 27001" in lower or "iso27001" in lower:
            extracted["compliance_focus"] = "ISO/IEC 27001:2022"

        # Budget ceiling preference
        budget_match = re.search(r'(?:budget|spend|cap)(?:\s+(?:limit|ceiling|target|cap))?\s*(?:of|is|at|to|=|:)?\s*(?:(?:₹|rs\.?|inr|\$|usd)\s*)?([0-9]+(?:\.[0-9]+)?)\s*(crore|cr|lakh|lakhs|m|million|k)?', lower)
        if budget_match:
            val_str, unit = budget_match.groups()
            extracted["budget_preference"] = f"{val_str} {unit if unit else ''}".strip()

        for k, v in extracted.items():
            self.set_preference(session_id, k, v, user_email)

        return extracted

    def save_message(
        self,
        session_id: str,
        role: str,
        content: str,
        user_email: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """Saves a conversation turn (user or assistant) to persistent SQLite memory, preventing duplicate echos."""
        now_iso = datetime.now(timezone.utc).isoformat()
        meta_str = json.dumps(metadata) if metadata else None
        email_clean = user_email.strip().lower() if user_email else None

        with self._get_conn() as conn:
            # Deduplicate consecutive turns with same role (e.g. sub-agent delegation echo)
            last = conn.execute("""
                SELECT id, role, content FROM ai_chat_memory
                WHERE session_id = ? ORDER BY id DESC LIMIT 1
            """, (session_id,)).fetchone()

            if last and last["role"] == role:
                # Skip duplicate consecutive user messages in same turn (e.g. sub-agent delegation echo)
                if role == "user":
                    return last["id"]
                if last["content"] == content or content.startswith(last["content"]) or last["content"].startswith(content):
                    return last["id"]

            cursor = conn.execute("""
                INSERT INTO ai_chat_memory (session_id, user_email, role, content, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, email_clean, role, content, now_iso, meta_str))
            return cursor.lastrowid

    def close(self):
        """Closes any persistent or in-memory SQLite connection."""
        if self._mem_conn is not None:
            try:
                self._mem_conn.close()
            except Exception:
                pass
            self._mem_conn = None

    def get_history(
        self,
        session_id: Optional[str] = None,
        user_email: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Retrieves chronological conversation history for a given session or authenticated user.
        Uses ORDER BY id DESC with limit to fetch the latest messages, then reverses to chronological order.
        """
        email_clean = user_email.strip().lower() if user_email else None
        with self._get_conn() as conn:
            if email_clean and session_id:
                rows = conn.execute("""
                    SELECT id, session_id, user_email, role, content, created_at, metadata_json
                    FROM ai_chat_memory
                    WHERE user_email = ? OR session_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                """, (email_clean, session_id, limit)).fetchall()
            elif email_clean:
                rows = conn.execute("""
                    SELECT id, session_id, user_email, role, content, created_at, metadata_json
                    FROM ai_chat_memory
                    WHERE user_email = ?
                    ORDER BY id DESC
                    LIMIT ?
                """, (email_clean, limit)).fetchall()
            elif session_id:
                rows = conn.execute("""
                    SELECT id, session_id, user_email, role, content, created_at, metadata_json
                    FROM ai_chat_memory
                    WHERE session_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                """, (session_id, limit)).fetchall()
            else:
                return []

        rows = list(reversed(rows))
        history = []
        for r in rows:
            meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            history.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "user_email": r["user_email"],
                "role": r["role"],
                "content": r["content"],
                "created_at": r["created_at"],
                "metadata": meta,
                "suggested_next_questions": meta.get("suggested_next_questions", [])
            })
        return history

    def get_recent_turns(
        self,
        session_id: Optional[str] = None,
        user_email: Optional[str] = None,
        max_turns: int = 6
    ) -> List[Dict[str, Any]]:
        """
        Fetches the most recent N turns for active context memory injection.
        """
        full_history = self.get_history(session_id=session_id, user_email=user_email, limit=max_turns * 2)
        return full_history[-max_turns:] if len(full_history) > max_turns else full_history

    def clear_history(
        self,
        session_id: Optional[str] = None,
        user_email: Optional[str] = None
    ) -> int:
        """Clears stored conversation history and learned preferences for a given session or user."""
        email_clean = user_email.strip().lower() if user_email else None
        with self._get_conn() as conn:
            if email_clean and session_id:
                cursor = conn.execute(
                    "DELETE FROM ai_chat_memory WHERE user_email = ? OR session_id = ?",
                    (email_clean, session_id)
                )
                conn.execute("DELETE FROM ai_user_preferences WHERE user_email = ? OR session_id = ?", (email_clean, session_id))
            elif email_clean:
                cursor = conn.execute("DELETE FROM ai_chat_memory WHERE user_email = ?", (email_clean,))
                conn.execute("DELETE FROM ai_user_preferences WHERE user_email = ?", (email_clean,))
            elif session_id:
                cursor = conn.execute("DELETE FROM ai_chat_memory WHERE session_id = ?", (session_id,))
                conn.execute("DELETE FROM ai_user_preferences WHERE session_id = ?", (session_id,))
            else:
                return 0
            return cursor.rowcount

    def generate_history_summary(
        self,
        session_id: Optional[str] = None,
        user_email: Optional[str] = None
    ) -> str:
        """Synthesizes a clean summary of previous questions and answers in this conversation."""
        turns = self.get_history(session_id=session_id, user_email=user_email, limit=20)
        prefs = self.get_preferences(session_id=session_id, user_email=user_email)

        if not turns and not prefs:
            return "No previous conversation history found in this session."

        user_queries = [t["content"] for t in turns if t["role"] == "user"]
        summary_lines = [f"**Previous Chat Conversation Summary ({len(user_queries)} turns recorded):**\n"]
        for idx, q in enumerate(user_queries[-5:], 1):
            summary_lines.append(f"{idx}. *\"{q}\"*")

        if prefs:
            summary_lines.append("\n**Learned User Context & Preferences:**")
            for k, v in prefs.items():
                summary_lines.append(f"• **{k.replace('_', ' ').title()}**: `{v}`")

        return "\n".join(summary_lines)

    def close(self):
        """Closes any persistent in-memory database connections to release resources cleanly."""
        if self._mem_conn is not None:
            try:
                self._mem_conn.close()
            except Exception:
                pass
            self._mem_conn = None

    def __del__(self):
        self.close()


# Singleton memory store instance
_memory_store: Optional[ChatMemoryStore] = None


def get_memory_store(db_path: str = DEFAULT_DB_PATH) -> ChatMemoryStore:
    global _memory_store
    if _memory_store is None or _memory_store.db_path != db_path:
        _memory_store = ChatMemoryStore(db_path=db_path)
    return _memory_store
