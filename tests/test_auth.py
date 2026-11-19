"""
Unit tests for RiskLens Authentication & User Management.
Tests Sign Up, Sign In, Token Validation, Forgot Password, Password Reset,
and PostgreSQL Persistent Credential Storage.
"""

import unittest
import os
import secrets
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from backend.main import app
from backend.api.auth import _auth_store, PostgresAuthStore, SqliteAuthStore, UserSignUpRequest


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        _auth_store.reset_demo_accounts()

    def tearDown(self):
        _auth_store.reset_demo_accounts()
        _auth_store.cleanup_test_users()

    def test_default_demo_sign_in(self):
        # Test CISO login
        resp = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": "RiskLens@2026"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("token", data)
        self.assertEqual(data["user"]["role"], "Chief Information Security Officer (CISO)")

    def test_invalid_credentials_rejected(self):
        resp = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": "WrongPassword123"
        })
        self.assertEqual(resp.status_code, 401)

    def test_sign_up_new_user(self):
        unique_email = f"ciso_{secrets.token_hex(4)}@fintechindia.org"
        resp = self.client.post("/api/auth/signup", json={
            "full_name": "Devika Nair",
            "email": unique_email,
            "organization": "Fintech Trust India",
            "role": "Head of Cyber Governance",
            "password": "SuperSecretPass@2026"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("token", data)
        self.assertEqual(data["user"]["full_name"], "Devika Nair")

        # Duplicate email should fail
        dup = self.client.post("/api/auth/signup", json={
            "full_name": "Devika Nair",
            "email": unique_email,
            "organization": "Fintech Trust India",
            "role": "Head of Cyber Governance",
            "password": "SuperSecretPass@2026"
        })
        self.assertEqual(dup.status_code, 400)

    def test_forgot_and_reset_password_flow(self):
        email = "risk@enterprisebank.com"
        # 0. Sign in to obtain an initial session token
        init_login = self.client.post("/api/auth/signin", json={
            "email": email,
            "password": "RiskLens@2026"
        })
        self.assertEqual(init_login.status_code, 200)
        old_session_token = init_login.json()["token"]

        # Verify old session token functions
        me_check = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_session_token}"})
        self.assertEqual(me_check.status_code, 200)

        # 1. Request recovery token
        fp_resp = self.client.post("/api/auth/forgot-password", json={"email": email})
        self.assertEqual(fp_resp.status_code, 200)
        token = fp_resp.json()["reset_token"]
        self.assertTrue(len(token) > 0)

        # 2. Reset password using token
        new_pw = "RiskOfficerNew@2026"
        rp_resp = self.client.post("/api/auth/reset-password", json={
            "email": email,
            "reset_token": token,
            "new_password": new_pw
        })
        self.assertEqual(rp_resp.status_code, 200)

        # 3. Old session token must now be revoked (anti-hijacking)
        revoked_check = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_session_token}"})
        self.assertEqual(revoked_check.status_code, 401)

        # 4. Log in with new password
        login_resp = self.client.post("/api/auth/signin", json={
            "email": email,
            "password": new_pw
        })
        self.assertEqual(login_resp.status_code, 200)

        # 5. Old password must be rejected (no backdoor bypass)
        old_resp = self.client.post("/api/auth/signin", json={
            "email": email,
            "password": "RiskLens@2026"
        })
        self.assertEqual(old_resp.status_code, 401)

    def test_expired_reset_token_rejected(self):
        email = "ciso@enterprisebank.com"
        fp_resp = self.client.post("/api/auth/forgot-password", json={"email": email})
        self.assertEqual(fp_resp.status_code, 200)
        token = fp_resp.json()["reset_token"]

        # Artificially age the token in PostgreSQL by 20 minutes (exceeding 15-minute TTL)
        with _auth_store._get_conn() as conn:
            from datetime import datetime, timezone, timedelta
            expired_time = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
            conn.execute("UPDATE reset_tokens SET created_at = %s WHERE token = %s", (expired_time, token))
            conn.commit()

        # Attempt reset with expired token
        rp_resp = self.client.post("/api/auth/reset-password", json={
            "email": email,
            "reset_token": token,
            "new_password": "NewExpiredPassword@2026"
        })
        self.assertEqual(rp_resp.status_code, 400)
        self.assertIn("expired", rp_resp.json()["detail"].lower())

    def test_auth_me_endpoint(self):
        # Sign in first
        resp = self.client.post("/api/auth/signin", json={
            "email": "board@enterprisebank.com",
            "password": "RiskLens@2026"
        })
        token = resp.json()["token"]

        # Call /me
        me_resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["email"], "board@enterprisebank.com")

        # Call /logout
        logout_resp = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(logout_resp.status_code, 200)

        # Token should now be invalid
        me_after = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_after.status_code, 401)

    def test_list_users_requires_auth(self):
        # Unauthenticated audit query must fail
        unauth_resp = self.client.get("/api/auth/users")
        self.assertEqual(unauth_resp.status_code, 401)

        # Authenticated query must succeed
        login_resp = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": "RiskLens@2026"
        })
        token = login_resp.json()["token"]
        auth_resp = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(auth_resp.status_code, 200)
        self.assertGreater(len(auth_resp.json()), 0)

    def test_persistent_postgres_credential_storage(self):
        """Verifies credentials persist in PostgreSQL across store re-instantiations."""
        store1 = PostgresAuthStore(db_url=_auth_store.db_url)
        test_email = f"persist_{secrets.token_hex(4)}@enterprise.com"
        password = "SecurePassword@2026"

        store1.register_user(UserSignUpRequest(
            full_name="Persistent User",
            email=test_email,
            organization="Bank of RiskLens",
            role="CISO",
            password=password
        ))

        # Create a new second store instance reading from the same PostgreSQL database
        store2 = PostgresAuthStore(db_url=_auth_store.db_url)
        token, profile = store2.authenticate_user(test_email, password)
        self.assertEqual(profile.email, test_email)
        self.assertEqual(profile.full_name, "Persistent User")
        self.assertTrue(token.startswith("risklens_sec_"))

    def test_change_password_endpoint(self):
        """Verifies authenticated user can rotate their password securely."""
        # 1. Sign in
        login_resp = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": "RiskLens@2026"
        })
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.json()["token"]

        # 2. Change password
        new_pw = "RiskLensRotated@2026"
        chg_resp = self.client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {token}"}, json={
            "current_password": "RiskLens@2026",
            "new_password": new_pw
        })
        self.assertEqual(chg_resp.status_code, 200)

        # 3. Sign in with new password succeeds
        new_login = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": new_pw
        })
        self.assertEqual(new_login.status_code, 200)

        # 4. Sign in with old password fails
        old_login = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": "RiskLens@2026"
        })
        self.assertEqual(old_login.status_code, 401)

        # 5. Restore original password for clean test isolation across suite
        self.client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {new_login.json()['token']}"}, json={
            "current_password": new_pw,
            "new_password": "RiskLens@2026"
        })

    def test_invalid_email_format_rejected(self):
        """Verifies non-RFC email formats are rejected by validation schema."""
        resp = self.client.post("/api/auth/signup", json={
            "full_name": "Invalid Email User",
            "email": "notanemail",
            "organization": "Enterprise",
            "role": "Analyst",
            "password": "ValidPassword@2026"
        })
        self.assertEqual(resp.status_code, 422)

    def test_brute_force_lockout(self):
        """Verifies account lockout triggers after 5 consecutive failed sign-in attempts."""
        test_email = "board@enterprisebank.com"
        _auth_store._failed_attempts.pop(test_email, None)

        for _ in range(5):
            r = self.client.post("/api/auth/signin", json={"email": test_email, "password": "WrongPassword"})
            self.assertEqual(r.status_code, 401)

        # 6th attempt should return 429 Too Many Requests
        lockout_resp = self.client.post("/api/auth/signin", json={"email": test_email, "password": "WrongPassword"})
        self.assertEqual(lockout_resp.status_code, 429)
        self.assertIn("locked", lockout_resp.json()["detail"].lower())

    def test_production_forgot_password_omits_cleartext_token(self):
        """Verifies SEC-01: In production mode, reset token is never exposed in API response."""
        email = "ciso@enterprisebank.com"
        old_env = os.environ.get("RISKLENS_ENV")
        old_demo = os.environ.get("RISKLENS_DEMO_MODE")
        try:
            os.environ["RISKLENS_ENV"] = "production"
            os.environ["RISKLENS_DEMO_MODE"] = "false"
            resp = self.client.post("/api/auth/forgot-password", json={"email": email})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertNotIn("reset_token", data)
            self.assertIn("dispatched", data["message"].lower())
        finally:
            if old_env is not None:
                os.environ["RISKLENS_ENV"] = old_env
            else:
                os.environ.pop("RISKLENS_ENV", None)
            if old_demo is not None:
                os.environ["RISKLENS_DEMO_MODE"] = old_demo
            else:
                os.environ.pop("RISKLENS_DEMO_MODE", None)

    def test_failed_attempts_pruning_and_bounding(self):
        """Verifies MEM-01: Failed attempts dictionary is bounded and pruned."""
        now = datetime.now(timezone.utc)
        # Populate over capacity with expired records
        for i in range(1200):
            _auth_store._failed_attempts[f"attacker_{i}@probe.com"] = [now - timedelta(minutes=10)]
        # Active attempt
        _auth_store._failed_attempts["active@target.com"] = [now - timedelta(seconds=10)]

        _auth_store._prune_failed_attempts(now)
        # All expired records should have been evicted
        self.assertLessEqual(len(_auth_store._failed_attempts), _auth_store._MAX_FAILED_ATTEMPT_KEYS)
        self.assertIn("active@target.com", _auth_store._failed_attempts)

    def test_admin_routes_auth_enforcement(self):
        """Verifies SEC-02: Administrative mutation routes enforce authentication."""
        # 1. Invalid bearer token should be rejected with 401
        inv_resp = self.client.post("/api/data/reset", headers={"Authorization": "Bearer invalid_token_12345"})
        self.assertEqual(inv_resp.status_code, 401)

        # 2. In mandatory auth mode, unauthenticated access should be rejected with 401
        old_req = os.environ.get("RISKLENS_REQUIRE_AUTH")
        try:
            os.environ["RISKLENS_REQUIRE_AUTH"] = "true"
            unauth_resp = self.client.post("/api/data/reset")
            self.assertEqual(unauth_resp.status_code, 401)

            # Valid sign in and token
            login = self.client.post("/api/auth/signin", json={
                "email": "ciso@enterprisebank.com",
                "password": "RiskLens@2026"
            })
            self.assertEqual(login.status_code, 200)
            token = login.json()["token"]

            # Authenticated admin reset should succeed
            auth_resp = self.client.post("/api/data/reset", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(auth_resp.status_code, 200)
        finally:
            if old_req is not None:
                os.environ["RISKLENS_REQUIRE_AUTH"] = old_req
            else:
                os.environ.pop("RISKLENS_REQUIRE_AUTH", None)


if __name__ == "__main__":
    unittest.main()
