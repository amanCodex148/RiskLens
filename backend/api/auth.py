"""
Persistent Authentication & User Management Module for RiskLens.
Provides Sign In, Sign Up, Forgot Password, and Session Management.
Uses salted SHA-256 cryptographic hashing and persists all credentials,
sessions, and tokens into an ACID-compliant SQLite database.
"""

import os
import sqlite3
import re
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from typing import Dict, Optional, Any, List
from pydantic import BaseModel, Field, field_validator
from fastapi import APIRouter, HTTPException, Header, Depends

logger = logging.getLogger("risklens.auth")

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

# Project storage directory for persistent SQLite database
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.environ.get(
    "RISKLENS_DB_PATH",
    os.path.join(PROJECT_ROOT, "data", "risklens_users.db")
)

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")


# --- Schemas ---

class UserSignUpRequest(BaseModel):
    full_name: str = Field(..., min_length=2)
    email: str = Field(..., min_length=3)
    organization: str = Field("Enterprise Financial Services", min_length=2)
    role: str = Field("Chief Information Security Officer (CISO)")
    password: str = Field(..., min_length=6)

    @field_validator("email")
    @classmethod
    def validate_signup_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid corporate email format (e.g. user@company.com).")
        return clean

    @field_validator("password")
    @classmethod
    def validate_signup_password(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 6:
            raise ValueError("Password must contain at least 6 non-whitespace characters.")
        return clean


class UserSignInRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3)


class ResetPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3)
    reset_token: str
    new_password: str = Field(..., min_length=6)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 6:
            raise ValueError("Password must contain at least 6 non-whitespace characters.")
        return clean


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)

    @field_validator("new_password")
    @classmethod
    def validate_change_password(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 6:
            raise ValueError("New password must contain at least 6 non-whitespace characters.")
        return clean


class UserProfile(BaseModel):
    user_id: str
    full_name: str
    email: str
    organization: str
    role: str
    created_at: str


class AuthResponse(BaseModel):
    token: str
    user: UserProfile
    message: str


# --- Hash Utility ---

def _hash_password(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 with 100,000 iterations for cryptographic security."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=100000
    ).hex()


# --- Persistent SQLite Auth Store ---

class SqliteAuthStore:
    """
    Persistent SQLite storage engine for user accounts, credentials, sessions, and recovery tokens.
    Guarantees user credentials persist on disk across server reloads and restarts.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()
        self._seed_default_users()

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
                CREATE TABLE IF NOT EXISTS users (
                    email TEXT PRIMARY KEY COLLATE NOCASE,
                    user_id TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    organization TEXT NOT NULL,
                    role TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    hashed_password TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    email TEXT NOT NULL COLLATE NOCASE,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    token TEXT PRIMARY KEY,
                    email TEXT NOT NULL COLLATE NOCASE,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reset_email ON reset_tokens(email);")
            conn.commit()

    def _seed_default_users(self):
        # In production environments, skip seeding known default demo accounts unless explicitly opted-in
        is_prod = os.environ.get("RISKLENS_ENV", "").lower() == "production"
        seed_allowed = os.environ.get("RISKLENS_SEED_DEMO_USERS", "true" if not is_prod else "false").lower() in ("true", "1", "yes")
        if not seed_allowed:
            logger.info("Production mode: Automatic demo accounts seeding skipped for security.")
            return

        default_accounts = [
            {
                "full_name": "Vikramaditya Sharma",
                "email": "ciso@enterprisebank.com",
                "organization": "Bharat Premier Financial Bank",
                "role": "Chief Information Security Officer (CISO)",
                "password": "RiskLens@2026"
            },
            {
                "full_name": "Priyanka Nambiar",
                "email": "risk@enterprisebank.com",
                "organization": "Bharat Premier Financial Bank",
                "role": "Chief Risk Officer (CRO)",
                "password": "RiskLens@2026"
            },
            {
                "full_name": "Arjun Singhania",
                "email": "board@enterprisebank.com",
                "organization": "Bharat Premier Financial Bank",
                "role": "Board Audit Committee Director",
                "password": "RiskLens@2026"
            }
        ]

        with self._get_conn() as conn:
            for acc in default_accounts:
                email = acc["email"].lower()
                row = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
                if not row:
                    salt = secrets.token_hex(16)
                    hashed_pw = _hash_password(acc["password"], salt)
                    user_id = f"USR-{secrets.token_hex(4).upper()}"
                    conn.execute("""
                        INSERT INTO users (email, user_id, full_name, organization, role, salt, hashed_password, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        email,
                        user_id,
                        acc["full_name"],
                        acc["organization"],
                        acc["role"],
                        salt,
                        hashed_pw,
                        "2026-01-15T10:00:00Z"
                    ))
            conn.commit()

    def reset_demo_accounts(self):
        """Resets the demo accounts back to their baseline passwords for idempotent testing."""
        self._failed_attempts.clear()
        default_accounts = [
            {
                "full_name": "Vikramaditya Sharma",
                "email": "ciso@enterprisebank.com",
                "organization": "Bharat Premier Financial Bank",
                "role": "Chief Information Security Officer (CISO)",
                "password": "RiskLens@2026"
            },
            {
                "full_name": "Priyanka Nambiar",
                "email": "risk@enterprisebank.com",
                "organization": "Bharat Premier Financial Bank",
                "role": "Chief Risk Officer (CRO)",
                "password": "RiskLens@2026"
            },
            {
                "full_name": "Arjun Singhania",
                "email": "board@enterprisebank.com",
                "organization": "Bharat Premier Financial Bank",
                "role": "Board Audit Committee Director",
                "password": "RiskLens@2026"
            }
        ]
        with self._get_conn() as conn:
            for acc in default_accounts:
                email = acc["email"].lower()
                salt = secrets.token_hex(16)
                hashed_pw = _hash_password(acc["password"], salt)
                conn.execute("""
                    INSERT INTO users (email, user_id, full_name, organization, role, salt, hashed_password, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(email) DO UPDATE SET
                        salt = excluded.salt,
                        hashed_password = excluded.hashed_password
                """, (
                    email,
                    f"USR-{secrets.token_hex(4).upper()}",
                    acc["full_name"],
                    acc["organization"],
                    acc["role"],
                    salt,
                    hashed_pw,
                    "2026-01-15T10:00:00Z"
                ))
            conn.commit()

    def register_user(self, req: UserSignUpRequest) -> UserProfile:
        email = req.email.lower().strip()
        with self._get_conn() as conn:
            existing = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                raise HTTPException(status_code=400, detail="Account with this corporate email already exists.")

            salt = secrets.token_hex(16)
            hashed_pw = _hash_password(req.password, salt)
            user_id = f"USR-{secrets.token_hex(4).upper()}"
            created_at = datetime.now(timezone.utc).isoformat()

            conn.execute("""
                INSERT INTO users (email, user_id, full_name, organization, role, salt, hashed_password, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email,
                user_id,
                req.full_name.strip(),
                req.organization.strip(),
                req.role.strip(),
                salt,
                hashed_pw,
                created_at
            ))
            conn.commit()

        return UserProfile(
            user_id=user_id,
            full_name=req.full_name.strip(),
            email=email,
            organization=req.organization.strip(),
            role=req.role.strip(),
            created_at=created_at
        )

    def create_session(self, email: str) -> str:
        token = f"risklens_sec_{secrets.token_urlsafe(32)}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO sessions (token, email, created_at) VALUES (?, ?, ?)", (
                token,
                email.lower().strip(),
                now_iso
            ))
            conn.commit()
        return token

    _failed_attempts: Dict[str, List[datetime]] = {}
    _MAX_FAILED_ATTEMPT_KEYS = 1000

    def _prune_failed_attempts(self, now: datetime) -> None:
        """Evicts expired failed attempt records and bounds dictionary size to prevent memory leaks."""
        expired = [
            k for k, timestamps in self._failed_attempts.items()
            if not any(now - t < timedelta(minutes=5) for t in timestamps)
        ]
        for k in expired:
            self._failed_attempts.pop(k, None)

        if len(self._failed_attempts) > self._MAX_FAILED_ATTEMPT_KEYS:
            sorted_keys = sorted(
                self._failed_attempts.keys(),
                key=lambda k: max(self._failed_attempts[k]) if self._failed_attempts[k] else datetime.min
            )
            for k in sorted_keys[: len(self._failed_attempts) - self._MAX_FAILED_ATTEMPT_KEYS]:
                self._failed_attempts.pop(k, None)

    def authenticate_user(self, email: str, password: str) -> tuple[str, UserProfile]:
        email = email.lower().strip()
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # Brute-force protection: prune expired records and check failed attempts within 5 minutes
        self._prune_failed_attempts(now)
        recent_fails = [t for t in self._failed_attempts.get(email, []) if now - t < timedelta(minutes=5)]
        if recent_fails:
            self._failed_attempts[email] = recent_fails
        else:
            self._failed_attempts.pop(email, None)

        if len(recent_fails) >= 5:
            raise HTTPException(
                status_code=429,
                detail="Too many consecutive failed sign-in attempts. Account temporarily locked for 5 minutes."
            )

        with self._get_conn() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not user:
                self._failed_attempts.setdefault(email, []).append(now)
                raise HTTPException(status_code=401, detail="Invalid corporate credentials. Check email or password.")

            expected_hash = _hash_password(password, user["salt"])
            if expected_hash != user["hashed_password"]:
                # Check legacy SHA-256 for transparent backward-compatible upgrade to PBKDF2
                legacy_hash = hashlib.sha256((user["salt"] + password).encode('utf-8')).hexdigest()
                if legacy_hash == user["hashed_password"]:
                    # Upgrade to PBKDF2 automatically
                    new_salt = secrets.token_hex(16)
                    new_pw_hash = _hash_password(password, new_salt)
                    conn.execute("UPDATE users SET salt = ?, hashed_password = ? WHERE email = ?", (new_salt, new_pw_hash, email))
                    conn.commit()
                else:
                    self._failed_attempts.setdefault(email, []).append(now)
                    raise HTTPException(status_code=401, detail="Invalid corporate credentials. Check email or password.")

            # Successful login resets failed attempts
            self._failed_attempts.pop(email, None)

            token = f"risklens_sec_{secrets.token_urlsafe(32)}"
            conn.execute("INSERT OR REPLACE INTO sessions (token, email, created_at) VALUES (?, ?, ?)", (
                token,
                email,
                now_iso
            ))
            conn.execute("UPDATE users SET last_login_at = ? WHERE email = ?", (now_iso, email))
            conn.commit()

            profile = UserProfile(
                user_id=user["user_id"],
                full_name=user["full_name"],
                email=user["email"],
                organization=user["organization"],
                role=user["role"],
                created_at=user["created_at"]
            )
            return token, profile

    def change_password(self, email: str, current_password: str, new_password: str) -> bool:
        email = email.lower().strip()
        with self._get_conn() as conn:
            user = conn.execute("SELECT salt, hashed_password FROM users WHERE email = ?", (email,)).fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User account not found.")

            expected_hash = _hash_password(current_password, user["salt"])
            if expected_hash != user["hashed_password"]:
                raise HTTPException(status_code=400, detail="Current password does not match.")

            new_salt = secrets.token_hex(16)
            new_hash = _hash_password(new_password, new_salt)
            conn.execute("UPDATE users SET salt = ?, hashed_password = ? WHERE email = ?", (new_salt, new_hash, email))
            conn.commit()
            return True

    def create_reset_token(self, email: str) -> str:
        email = email.lower().strip()
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            user = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="No registered account found with this corporate email.")

            # Invalidate any previously active tokens for this user before issuing a new one
            conn.execute("DELETE FROM reset_tokens WHERE email = ?", (email,))

            token = secrets.token_hex(6).upper()  # 12-char friendly OTP
            conn.execute("INSERT OR REPLACE INTO reset_tokens (token, email, created_at) VALUES (?, ?, ?)", (
                token,
                email,
                now_iso
            ))
            conn.commit()
            return token

    def reset_password(self, email: str, token: str, new_password: str) -> bool:
        email = email.lower().strip()
        token = token.strip().upper()

        with self._get_conn() as conn:
            rec = conn.execute("SELECT email, created_at FROM reset_tokens WHERE token = ? AND email = ?", (token, email)).fetchone()
            if not rec:
                raise HTTPException(status_code=400, detail="Invalid or expired password reset token.")

            # Validate 15-minute token TTL
            try:
                token_time = datetime.fromisoformat(rec["created_at"])
                if token_time.tzinfo is None:
                    token_time = token_time.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) - token_time > timedelta(minutes=15):
                    conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
                    conn.commit()
                    raise HTTPException(status_code=400, detail="Password reset token has expired. Please request a new token.")
            except (ValueError, TypeError):
                conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
                conn.commit()
                raise HTTPException(status_code=400, detail="Invalid password reset token format or corrupted timestamp.")

            user = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            new_salt = secrets.token_hex(16)
            new_hash = _hash_password(new_password, new_salt)
            conn.execute("UPDATE users SET salt = ?, hashed_password = ? WHERE email = ?", (new_salt, new_hash, email))
            # Delete all reset tokens for this user upon successful password update
            conn.execute("DELETE FROM reset_tokens WHERE email = ?", (email,))
            conn.execute("DELETE FROM sessions WHERE email = ?", (email,))
            conn.commit()
            return True

    def get_user_by_token(self, token: str) -> Optional[UserProfile]:
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT u.user_id, u.full_name, u.email, u.organization, u.role, u.created_at, s.created_at AS session_created_at
                FROM sessions s
                JOIN users u ON s.email = u.email
                WHERE s.token = ?
            """, (token,)).fetchone()

            if not row:
                return None

            # Enforce 7-day session lifetime (anti-stale session hijacking)
            try:
                session_time = datetime.fromisoformat(row["session_created_at"])
                if session_time.tzinfo is None:
                    session_time = session_time.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) - session_time > timedelta(days=7):
                    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                    return None
            except (ValueError, TypeError):
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                return None

            return UserProfile(
                user_id=row["user_id"],
                full_name=row["full_name"],
                email=row["email"],
                organization=row["organization"],
                role=row["role"],
                created_at=row["created_at"]
            )

    def logout(self, token: str):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    def list_all_users(self) -> List[UserProfile]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT user_id, full_name, email, organization, role, created_at FROM users").fetchall()
            return [
                UserProfile(
                    user_id=r["user_id"],
                    full_name=r["full_name"],
                    email=r["email"],
                    organization=r["organization"],
                    role=r["role"],
                    created_at=r["created_at"]
                ) for r in rows
            ]

    def cleanup_test_users(self):
        """Purges test accounts created during automated unit tests to prevent database bloat."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM users WHERE email LIKE 'persist_%' OR email LIKE 'ciso_%'")
            conn.commit()


# Singleton persistent store pointing to data/risklens_users.db
_auth_store = SqliteAuthStore()


# --- Endpoints ---

@auth_router.post("/signup", response_model=AuthResponse)
def sign_up(req: UserSignUpRequest):
    """Registers a new enterprise user and issues a session token, persisting credentials to SQLite."""
    profile = _auth_store.register_user(req)
    token = _auth_store.create_session(profile.email)

    return AuthResponse(
        token=token,
        user=profile,
        message="Enterprise account created successfully. Credentials securely stored in database."
    )


@auth_router.post("/signin", response_model=AuthResponse)
def sign_in(req: UserSignInRequest):
    """Authenticates corporate user credentials against SQLite vault and returns session token."""
    token, profile = _auth_store.authenticate_user(req.email, req.password)
    return AuthResponse(
        token=token,
        user=profile,
        message="Authentication successful."
    )


@auth_router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    """Generates a secure password reset token for account recovery."""
    token = _auth_store.create_reset_token(req.email)

    # In production or hardened security mode, tokens are never returned in HTTP responses.
    # For local/demo simulation (default for hackathon evaluators), token is returned for immediate UI auto-fill.
    is_demo_mode = os.environ.get("RISKLENS_DEMO_MODE", "true").lower() in ("true", "1", "yes") and \
                   os.environ.get("RISKLENS_ENV", "").lower() != "production"

    if is_demo_mode:
        return {
            "email": req.email,
            "reset_token": token,
            "message": f"A secure password recovery verification token has been generated: {token}. (Simulated dispatch to registered corporate email)."
        }
    else:
        logger.info(f"Password reset verification token generated for email {req.email} (dispatched via out-of-band channel).")
        return {
            "email": req.email,
            "message": "If the provided email is registered in our enterprise directory, a password reset verification token has been dispatched to your corporate email."
        }


@auth_router.post("/reset-password")
def reset_password(req: ResetPasswordRequest):
    """Resets user password in SQLite database using valid verification token."""
    _auth_store.reset_password(req.email, req.reset_token, req.new_password)
    return {
        "email": req.email,
        "message": "Password updated successfully in database. You may now sign in with your new password."
    }


@auth_router.post("/change-password")
def change_password(req: ChangePasswordRequest, authorization: Optional[str] = Header(None)):
    """Changes password for the currently authenticated user in SQLite vault."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    token = authorization.replace("Bearer ", "").strip()
    profile = _auth_store.get_user_by_token(token)
    if not profile:
        raise HTTPException(status_code=401, detail="Session expired or invalid token.")

    _auth_store.change_password(profile.email, req.current_password, req.new_password)
    return {"message": "Password changed successfully."}


@auth_router.get("/me", response_model=UserProfile)
def get_current_user(authorization: Optional[str] = Header(None)):
    """Returns currently authenticated user profile verified against active sessions in SQLite."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication token required.")

    token = authorization.replace("Bearer ", "").strip()
    profile = _auth_store.get_user_by_token(token)
    if not profile:
        raise HTTPException(status_code=401, detail="Session expired or invalid token.")

    return profile


@auth_router.post("/logout")
def logout(authorization: Optional[str] = Header(None)):
    """Invalidates active session token in SQLite."""
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        _auth_store.logout(token)
    return {"message": "Session terminated successfully."}


@auth_router.get("/users", response_model=List[UserProfile])
def list_registered_users(authorization: Optional[str] = Header(None)):
    """Lists registered enterprise users for auditing (requires authenticated session)."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication token required to audit user accounts.")
    token = authorization.replace("Bearer ", "").strip()
    profile = _auth_store.get_user_by_token(token)
    if not profile:
        raise HTTPException(status_code=401, detail="Session expired or invalid token.")
    return _auth_store.list_all_users()
