"""
Tests for the 20 Pre-Configured Industry Datasets.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app


class TestIndustryDatasets(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        # Reset back to default benchmark after each test
        self.client.post("/api/data/reset")

    def test_all_20_datasets_metadata(self):
        resp = self.client.get("/api/datasets")
        self.assertEqual(resp.status_code, 200)
        datasets = resp.json()
        self.assertEqual(len(datasets), 20)

        expected_ids = [
            "DATASET-BANKING", "DATASET-FINTECH", "DATASET-HEALTHCARE",
            "DATASET-ECOMMERCE", "DATASET-ENERGY", "DATASET-AVIATION",
            "DATASET-TELECOM", "DATASET-AUTOMOTIVE", "DATASET-SAAS",
            "DATASET-GOVERNMENT", "DATASET-PHARMA", "DATASET-DEFENSE",
            "DATASET-TRADING", "DATASET-EDUCATION", "DATASET-LOGISTICS",
            "DATASET-MEDIA", "DATASET-SMARTCITY", "DATASET-INSURANCE",
            "DATASET-HOSPITALITY", "DATASET-SEMICONDUCTOR"
        ]
        returned_ids = [d["id"] for d in datasets]
        for exp_id in expected_ids:
            self.assertIn(exp_id, returned_ids)

        for d in datasets:
            self.assertTrue(len(d["name"]) > 0)
            self.assertTrue(len(d["sector"]) > 0)
            self.assertGreater(d["asset_count"], 0)
            self.assertTrue(len(d["risk_profile"]) > 0)

    def test_get_individual_dataset(self):
        resp = self.client.get("/api/datasets/DATASET-SEMICONDUCTOR")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["metadata"]["id"], "DATASET-SEMICONDUCTOR")
        self.assertEqual(data["metadata"]["name"], "Semiconductor Foundry & Chip Fab")
        self.assertGreater(len(data["assets"]), 0)

    def test_load_dataset_recalculates_risk(self):
        resp = self.client.post("/api/datasets/DATASET-AUTOMOTIVE/load")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["loaded_dataset_id"], "DATASET-AUTOMOTIVE")
        self.assertIn("recalculated_risk", data)
        self.assertGreater(data["recalculated_risk"]["eal_inr"], 0)

        # Verify active assets changed
        assets_resp = self.client.get("/api/assets")
        self.assertEqual(assets_resp.status_code, 200)
        assets = assets_resp.json()
        self.assertEqual(len(assets), data["asset_count"])
        self.assertEqual(assets[0]["asset_id"], "AUTO-001")

    def test_invalid_dataset_id_returns_404(self):
        resp = self.client.get("/api/datasets/DATASET-DOES-NOT-EXIST")
        self.assertEqual(resp.status_code, 404)

        resp2 = self.client.post("/api/datasets/DATASET-DOES-NOT-EXIST/load")
        self.assertEqual(resp2.status_code, 404)

    def test_industry_dataset_portfolio_optimization(self):
        """Verifies that non-default industry datasets successfully optimize initiatives with positive ROSI."""
        load_resp = self.client.post("/api/datasets/DATASET-HEALTHCARE/load")
        self.assertEqual(load_resp.status_code, 200)

        opt_resp = self.client.post("/api/optimize", json={"budget_inr": 10000000.0})
        self.assertEqual(opt_resp.status_code, 200)
        data = opt_resp.json()
        self.assertGreater(len(data["selected_initiatives"]), 0)
        self.assertGreater(data["net_risk_reduction_inr"], 0)
        self.assertGreater(data["portfolio_rosi_pct"], 0)

    def test_industry_dataset_ransomware_scenario(self):
        """Verifies that What-If scenarios dynamically target the crown jewel asset of the loaded industry."""
        load_resp = self.client.post("/api/datasets/DATASET-HEALTHCARE/load")
        self.assertEqual(load_resp.status_code, 200)

        scen_resp = self.client.post("/api/scenarios/simulate", json={"scenario_id": "SCEN-RANSOM-CORE"})
        self.assertEqual(scen_resp.status_code, 200)
        data = scen_resp.json()
        self.assertIn("Epic Electronic Health Records", data["scenario_title"])
        self.assertGreater(data["delta_eal_inr"], 0)
        self.assertGreater(data["delta_percentage"], 0)


if __name__ == "__main__":
    unittest.main()
