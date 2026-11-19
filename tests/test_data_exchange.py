"""
Integration & Unit tests for Data Exchange (Import & Export of Real Enterprise Data).
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.ingestion.telemetry_loader import TelemetryService


class TestDataExchange(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.telemetry = TelemetryService.get_instance()
        from backend.ingestion.dataset_store import get_dataset_store
        from backend.api.auth import _auth_store
        get_dataset_store().clear()
        _auth_store.reset_demo_accounts()
        self.client.post("/api/data/reset")

    def tearDown(self):
        # Reset back to default benchmark and clear dataset store
        from backend.ingestion.dataset_store import get_dataset_store
        get_dataset_store().clear()
        self.client.post("/api/data/reset")

    def test_export_full_dossier_json(self):
        resp = self.client.get("/api/data/export?format=json&type=full")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["export_type"], "full_risk_dossier")
        self.assertIn("quantified_risk", data)
        self.assertIn("investment_optimization", data)
        self.assertIn("asset_inventory", data)
        self.assertGreater(len(data["asset_inventory"]), 0)

    def test_export_assets_csv(self):
        resp = self.client.get("/api/data/export?format=csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers["content-type"])
        text = resp.text
        self.assertIn("asset_id,name,business_unit,criticality", text)
        self.assertIn("AST-001", text)

    def test_export_with_auth_token_query_and_header(self):
        import os
        try:
            os.environ["RISKLENS_REQUIRE_AUTH"] = "true"
            # 1. Unauthenticated request blocked when strict auth required
            unauth = self.client.get("/api/data/export?format=json&type=full")
            self.assertEqual(unauth.status_code, 401)

            # 2. Login to get token
            login = self.client.post("/api/auth/signin", json={
                "email": "ciso@enterprisebank.com",
                "password": "RiskLens@2026"
            })
            self.assertEqual(login.status_code, 200)
            token = login.json()["token"]

            # 3. Export with Bearer header succeeds
            auth_header_resp = self.client.get(
                "/api/data/export?format=json&type=full",
                headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(auth_header_resp.status_code, 200)
            self.assertEqual(auth_header_resp.json()["export_type"], "full_risk_dossier")

            # 4. Export with query param token succeeds (browser direct link download)
            query_token_resp = self.client.get(f"/api/data/export?format=json&type=full&token={token}")
            self.assertEqual(query_token_resp.status_code, 200)
            self.assertEqual(query_token_resp.json()["export_type"], "full_risk_dossier")

            # 5. CSV export with query token
            csv_query_resp = self.client.get(f"/api/data/export?format=csv&token={token}")
            self.assertEqual(csv_query_resp.status_code, 200)
            self.assertIn("text/csv", csv_query_resp.headers["content-type"])
        finally:
            os.environ.pop("RISKLENS_REQUIRE_AUTH", None)

    def test_get_templates(self):
        csv_resp = self.client.get("/api/data/template?format=csv")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("asset_id,name,business_unit", csv_resp.text)

        json_resp = self.client.get("/api/data/template?format=json")
        self.assertEqual(json_resp.status_code, 200)
        self.assertIn("assets", json_resp.json())

    def test_import_real_data_csv(self):
        csv_payload = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count,cve_ids,top_cvss,top_epss\n"
            "REAL-001,High-Frequency FX Engine,Corporate & Treasury,Tier 1 - Crown Jewel,8500000,1000000,CVE-2024-21887,9.8,0.95\n"
            "REAL-002,Mobile Banking API Gateway,Retail Banking & Payments,Tier 1 - Crown Jewel,4500000,20000000,CVE-2023-4966,9.4,0.92\n"
        )
        resp = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "State Bank of XYZ",
            "sector": "Banking & Financial Services"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["imported_assets_count"], 2)
        self.assertEqual(data["dataset_name"], "State Bank of XYZ")
        self.assertEqual(data["sector"], "Banking & Financial Services")
        self.assertIn("recalculated_risk", data)
        self.assertGreater(data["recalculated_risk"]["eal_inr"], 0)

        # Verify active dataset metadata endpoint
        active_resp = self.client.get("/api/data/active-dataset")
        self.assertEqual(active_resp.status_code, 200)
        active_meta = active_resp.json()
        self.assertEqual(active_meta["name"], "State Bank of XYZ")
        self.assertEqual(active_meta["sector"], "Banking & Financial Services")
        self.assertTrue(active_meta["is_custom"])

        # Verify full export reflects target organization name
        export_resp = self.client.get("/api/data/export?format=json&type=full")
        self.assertEqual(export_resp.status_code, 200)
        export_data = export_resp.json()
        self.assertEqual(export_data["target_organization"], "State Bank of XYZ")

        # Verify assets endpoint returns newly imported real data
        assets_resp = self.client.get("/api/assets")
        self.assertEqual(assets_resp.status_code, 200)
        assets = assets_resp.json()
        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0]["asset_id"], "REAL-001")

    def test_import_real_data_json(self):
        json_payload = {
            "assets": [
                {
                    "asset_id": "CORP-DB-01",
                    "name": "Treasury Ledger Database",
                    "business_unit": "Corporate & Treasury",
                    "criticality": "Tier 1 - Crown Jewel",
                    "revenue_per_hour_inr": 6000000.0,
                    "pii_records_count": 500000,
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2024-1234",
                            "cvss_score": 9.1,
                            "epss_score": 0.88,
                            "is_cisa_kev": True
                        }
                    ]
                }
            ]
        }
        resp = self.client.post("/api/data/import", json={"format": "json", "data": json_payload})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["imported_assets_count"], 1)

    def test_reset_data(self):
        # First import custom data
        self.client.post("/api/data/import", json={
            "format": "csv",
            "content": "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\nTEMP-1,Temp,Retail,Tier 3,100,0"
        })
        self.assertEqual(len(self.client.get("/api/assets").json()), 1)

        # Reset back to default benchmark
        reset_resp = self.client.post("/api/data/reset")
        self.assertEqual(reset_resp.status_code, 200)
        self.assertEqual(reset_resp.json()["status"], "success")

        # Verify benchmark assets restored (12 default assets)
        assets = self.client.get("/api/assets").json()
        self.assertEqual(len(assets), 12)

    def test_concurrent_asset_access_thread_safety(self):
        """Verifies CON-01: Concurrent reads and writes to TelemetryService remain thread-safe."""
        import threading
        errors = []

        def reader():
            for _ in range(50):
                try:
                    assets = self.telemetry.get_all_assets()
                    self.assertIsInstance(assets, list)
                    _ = [a.asset_id for a in assets]
                except Exception as e:
                    errors.append(e)

        def writer():
            for _ in range(20):
                try:
                    current = self.telemetry.get_all_assets()
                    self.telemetry.save_assets(current, persist=False)
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(4)] + \
                  [threading.Thread(target=writer) for _ in range(2)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)

    def test_duplicate_prevention_same_name(self):
        """Prevents importing identical dataset telemetry when submitted with the same name."""
        csv_payload = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\n"
            "DUP-001,Core Banking Host,Retail,Tier 1 - Crown Jewel,5000000,500000\n"
        )
        # First import succeeds
        r1 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "State Bank of India"
        })
        self.assertEqual(r1.status_code, 200)

        # Repeated import with same name is rejected with HTTP 409
        r2 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "State Bank of India"
        })
        self.assertEqual(r2.status_code, 409)
        self.assertIn("Duplicate dataset rejected", r2.json()["detail"])

    def test_duplicate_prevention_different_name(self):
        """Prevents importing identical dataset telemetry even if user changes the dataset name."""
        csv_payload = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\n"
            "DUP-002,Payment Switch,Retail,Tier 1 - Crown Jewel,7000000,1000000\n"
        )
        # First import under Name A
        r1 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "HDFC Payment Network"
        })
        self.assertEqual(r1.status_code, 200)

        # Second import with identical telemetry under DIFFERENT Name B is blocked!
        r2 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "ICICI Alternate System"
        })
        self.assertEqual(r2.status_code, 409)
        self.assertIn("Duplicate dataset rejected", r2.json()["detail"])
        self.assertIn("HDFC Payment Network", r2.json()["detail"])

    def test_name_collision_different_content(self):
        """Rejects dataset name collisions when content differs unless overwrite is specified."""
        csv_1 = "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\nAST-A,Alpha,Retail,Tier 1,100,0\n"
        csv_2 = "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\nAST-B,Beta,Retail,Tier 2,200,0\n"

        r1 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_1,
            "dataset_name": "Shared Bank Name"
        })
        self.assertEqual(r1.status_code, 200)

        # Different telemetry with same name
        r2 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_2,
            "dataset_name": "Shared Bank Name"
        })
        self.assertEqual(r2.status_code, 409)
        self.assertIn("Dataset name collision", r2.json()["detail"])

    def test_overwrite_allows_reimport(self):
        """Verifies overwrite=True permits intentional updates and overwrites."""
        csv_payload = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\n"
            "OW-001,Updated Server,Retail,Tier 1 - Crown Jewel,9000000,200000\n"
        )
        r1 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "Apex Enterprise"
        })
        self.assertEqual(r1.status_code, 200)

        # Re-importing with overwrite=True succeeds
        r2 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "Apex Enterprise",
            "overwrite": True
        })
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["status"], "success")

    def test_persistent_database_storage_and_activation(self):
        """Verifies imported datasets are persisted to PostgreSQL database and can be activated or deleted."""
        csv_payload = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count\n"
            "STORE-01,Cloud Ledger,Corporate,Tier 1 - Crown Jewel,3000000,100000\n"
            "STORE-02,Customer Portal,Retail,Tier 2,1500000,500000\n"
        )
        r1 = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_payload,
            "dataset_name": "State Bank of Persistence",
            "sector": "Banking & Financial Services"
        })
        self.assertEqual(r1.status_code, 200)
        dataset_id = r1.json()["dataset_id"]

        # 1. List saved datasets from DB
        list_resp = self.client.get("/api/data/imports")
        self.assertEqual(list_resp.status_code, 200)
        datasets = list_resp.json()
        self.assertGreaterEqual(len(datasets), 1)
        found = [d for d in datasets if d["dataset_id"] == dataset_id]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "State Bank of Persistence")
        self.assertEqual(found[0]["asset_count"], 2)

        # 2. Reset telemetry to benchmark (12 assets)
        self.client.post("/api/data/reset")
        self.assertEqual(len(self.client.get("/api/assets").json()), 12)

        # 3. Activate the saved dataset from DB
        act_resp = self.client.post(f"/api/data/imports/{dataset_id}/activate")
        self.assertEqual(act_resp.status_code, 200)
        self.assertEqual(act_resp.json()["status"], "success")

        # Verify active assets are restored from the database
        active_assets = self.client.get("/api/assets").json()
        self.assertEqual(len(active_assets), 2)
        self.assertEqual(active_assets[0]["asset_id"], "STORE-01")

        # 4. Delete the dataset from DB
        del_resp = self.client.delete(f"/api/data/imports/{dataset_id}")
        self.assertEqual(del_resp.status_code, 200)

        # Verify deleted
        list_after = self.client.get("/api/data/imports").json()
        self.assertEqual(len([d for d in list_after if d["dataset_id"] == dataset_id]), 0)


if __name__ == "__main__":
    unittest.main()
