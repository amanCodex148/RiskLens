import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.schemas import QuantifiedRiskResult
from backend.engine.risk_engine import FairRiskEngine
from backend.ingestion.telemetry_loader import TelemetryService


class TestDynamicVaR(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.telemetry = TelemetryService.get_instance()
        self.engine = FairRiskEngine(iterations=2000)

        # Login to obtain admin auth token
        login = self.client.post("/api/auth/signin", json={
            "email": "ciso@enterprisebank.com",
            "password": "RiskLens@2026"
        })
        self.assertEqual(login.status_code, 200)
        self.token = login.json()["token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        self.telemetry.reset_to_default()
        self.engine.invalidate_cache()

    def test_var_percentiles_order_and_presence(self):
        """Verify that 90%, 95%, and 99% VaR are calculated and properly ordered."""
        res = self.engine.run_enterprise_simulation()
        self.assertIsInstance(res, QuantifiedRiskResult)
        self.assertGreater(res.var_90_inr, 0)
        self.assertGreater(res.var_95_inr, 0)
        self.assertGreater(res.var_99_inr, 0)

        # VaR must increase as confidence percentile increases (90% <= 95% <= 99%)
        self.assertLessEqual(res.var_90_inr, res.var_95_inr)
        self.assertLessEqual(res.var_95_inr, res.var_99_inr)

        # USD values must match rate
        self.assertGreater(res.var_90_usd, 0)
        self.assertGreater(res.var_95_usd, 0)
        self.assertGreater(res.var_99_usd, 0)

    def test_banking_dataset_recommends_99_var(self):
        """Banking/Financial datasets mandate 99% Tail VaR under Basel III / RBI CSCRF."""
        load_res = self.client.post("/api/datasets/DATASET-BANKING/load", headers=self.headers)
        self.assertEqual(load_res.status_code, 200)
        res = self.client.get("/api/risk/summary").json()

        self.assertEqual(res["recommended_var_percentile"], 99)
        self.assertIn("99%", res["recommended_var_reason"])
        self.assertIn("Basel III", res["recommended_var_reason"])

    def test_ecommerce_dataset_recommends_90_var(self):
        """Retail/eCommerce datasets with operational risk adapt to 90% VaR."""
        load_res = self.client.post("/api/datasets/DATASET-ECOMMERCE/load", headers=self.headers)
        self.assertEqual(load_res.status_code, 200)
        res = self.client.get("/api/risk/summary").json()

        self.assertEqual(res["recommended_var_percentile"], 90)
        self.assertIn("90%", res["recommended_var_reason"])

    def test_saas_technology_dataset_recommends_95_var(self):
        """Standard enterprise / SaaS technology datasets recommend 95% VaR."""
        load_res = self.client.post("/api/datasets/DATASET-SAAS/load", headers=self.headers)
        self.assertEqual(load_res.status_code, 200)
        res = self.client.get("/api/risk/summary").json()

        self.assertEqual(res["recommended_var_percentile"], 95)
        self.assertIn("95%", res["recommended_var_reason"])

    def test_custom_imported_bank_recommends_99_var(self):
        """Custom imported data with banking/financial name dynamically adapts to 99% VaR."""
        csv_data = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count,cve_ids\n"
            "AST-SB-01,State Bank Core Ledger,Corporate Treasury,Tier 1 (Crown Jewel),12000000,500000,CVE-2024-21626\n"
        )
        import_res = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_data,
            "name": "State Bank of India Treasury",
            "sector": "Banking & Financial Services",
            "overwrite": True
        }, headers=self.headers)
        self.assertEqual(import_res.status_code, 200)

        res = self.client.get("/api/risk/summary").json()
        self.assertEqual(res["recommended_var_percentile"], 99)
        self.assertIn("99%", res["recommended_var_reason"])
        self.assertIn("State Bank", res["recommended_var_reason"])

    def test_custom_imported_retail_recommends_90_var(self):
        """Custom imported data with retail/consumer sector dynamically adapts to 90% VaR."""
        csv_data = (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count,cve_ids\n"
            "AST-RET-01,Quick Mart Catalog Web,Enterprise Operations,Tier 3 (Operational),80000,1000,\n"
        )
        import_res = self.client.post("/api/data/import", json={
            "format": "csv",
            "content": csv_data,
            "name": "Quick Mart Grocery Chain",
            "sector": "Retail & Consumer Internet",
            "overwrite": True
        }, headers=self.headers)
        self.assertEqual(import_res.status_code, 200)

        res = self.client.get("/api/risk/summary").json()
        self.assertEqual(res["recommended_var_percentile"], 90)
        self.assertIn("90%", res["recommended_var_reason"])


if __name__ == "__main__":
    unittest.main()
