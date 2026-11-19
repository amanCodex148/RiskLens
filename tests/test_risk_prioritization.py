"""
Unit and Integration Tests for Feature 7: Multi-Criteria Risk Prioritization.
Ranks risks based on 4 quantitative pillars:
1. Severity (25%): Technical CVSS score, weaponization, exploit complexity.
2. Business Impact (35%): Open FAIR™ EAL, Tier 1/2/3 asset criticality, downtime cost per hour, customer PII exposure records, DPDP Act liability.
3. Urgency (25%): Real-world exploit probability (EPSS), active in-the-wild exploitation (CISA KEV), and days open / SLA status.
4. Existing Controls (15%): Telemetry hygiene (MFA, EDR, network segmentation, backups), single points of failure, defensive coverage gaps.

Validates:
- Deterministic Risk Priority Index (RPI 0-100) calculation.
- Dynamic Action Tiers & SLAs (P0 48h, P1 7d, P2 30d, P3 90d).
- Live Enterprise Risk Register prioritization.
- Custom Risk List ranking with arbitrary weights.
- REST API endpoints: POST & GET /api/assistant/prioritize-risks.
- Integrated AI Assistant natural language query routing and memory integration.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_risk_prioritization import AiRiskPrioritizationEngine
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.engine.chat_memory import get_memory_store
from backend.models.schemas import PrioritizationWeights, RiskPrioritizationRequest


class TestRiskPrioritization(unittest.TestCase):
    def setUp(self):
        self.engine = AiRiskPrioritizationEngine()
        self.decision_service = AiDecisionSupportService()
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_live_enterprise_prioritization(self):
        """Verifies ranking of live enterprise assets with default weights."""
        result = self.engine.prioritize_risks(session_id="test_sess_live_prio")

        self.assertEqual(result.status, "success")
        self.assertGreater(result.total_risks_ranked, 0)
        self.assertEqual(len(result.ranked_risks), result.total_risks_ranked)

        # Check sorting order: RPI score must be monotonically non-increasing
        rpi_scores = [item.scores.composite_rpi_score for item in result.ranked_risks]
        self.assertEqual(rpi_scores, sorted(rpi_scores, reverse=True))

        # Check sequential ranks: 1, 2, 3...
        for idx, item in enumerate(result.ranked_risks, 1):
            self.assertEqual(item.rank, idx)

        # Verify #1 priority asset (Core Banking / AST-001) is P0 Immediate
        top_risk = result.ranked_risks[0]
        self.assertTrue(top_risk.priority_tier.startswith("P0"), f"Expected P0 tier for top asset, got {top_risk.priority_tier}")
        self.assertEqual(top_risk.sla_target_days, 2)
        self.assertGreaterEqual(top_risk.scores.composite_rpi_score, 80.0)

        # Validate RPI formula consistency
        w = result.weights_applied
        for item in result.ranked_risks:
            sc = item.scores
            expected_rpi = round(
                (w.weight_severity * sc.severity_score) +
                (w.weight_impact * sc.business_impact_score) +
                (w.weight_urgency * sc.urgency_score) +
                (w.weight_controls * sc.control_deficiency_score),
                1
            )
            self.assertAlmostEqual(sc.composite_rpi_score, expected_rpi, delta=0.2)

        # Check Markdown report generation
        self.assertIn("Multi-Criteria Risk Prioritization Dossier", result.markdown_report)
        self.assertIn("Multi-Criteria RPI", result.markdown_report)
        self.assertIn("Enterprise Risk Priority Rankings", result.markdown_report)
        self.assertIn("P0 (Immediate 24-48h)", result.markdown_report)

    def test_custom_risks_prioritization_and_custom_weights(self):
        """Verifies ranking custom risk definitions with custom weights."""
        custom_risks = [
            {
                "risk_id": "CR-001",
                "risk_title": "Publicly Accessible Customer PII Database",
                "asset_name": "Cloud Production Postgres",
                "business_unit": "Data Platform",
                "criticality": "Tier 1 - Mission Critical",
                "cvss_score": 9.8,
                "epss_score": 0.95,
                "is_cisa_kev": True,
                "financial_loss_inr": 85000000.0,
                "hourly_downtime_cost_inr": 2500000.0,
                "pii_records": 5000000,
                "control_hygiene_score": 20.0,
                "recommended_action": "Isolate public subnet, enable mTLS & IAM",
                "responsible_team": "Cloud SecOps"
            },
            {
                "risk_id": "CR-002",
                "risk_title": "Development Staging Server Outdated OpenSSL",
                "asset_name": "QA Build Node 4",
                "business_unit": "DevOps",
                "criticality": "Tier 3 - Low Impact",
                "cvss_score": 5.3,
                "epss_score": 0.05,
                "is_cisa_kev": False,
                "financial_loss_inr": 500000.0,
                "hourly_downtime_cost_inr": 10000.0,
                "pii_records": 0,
                "control_hygiene_score": 85.0,
                "recommended_action": "Upgrade OpenSSL package",
                "responsible_team": "DevOps"
            },
            {
                "risk_id": "CR-003",
                "risk_title": "Internal Employee HR Portal Weak Password Policy",
                "asset_name": "People Portal",
                "business_unit": "Corporate HR",
                "criticality": "Tier 2 - Business Operational",
                "cvss_score": 7.2,
                "epss_score": 0.35,
                "is_cisa_kev": False,
                "financial_loss_inr": 12000000.0,
                "hourly_downtime_cost_inr": 200000.0,
                "pii_records": 45000,
                "control_hygiene_score": 45.0,
                "recommended_action": "Enforce 14-char passphrase and FIDO2 MFA",
                "responsible_team": "IAM Team"
            }
        ]

        # Heavy weight on Urgency (40%) and Business Impact (40%)
        custom_weights = PrioritizationWeights(
            weight_severity=0.10,
            weight_impact=0.40,
            weight_urgency=0.40,
            weight_controls=0.10
        )

        result = self.engine.prioritize_risks(
            custom_risks=custom_risks,
            weights=custom_weights,
            session_id="test_sess_custom_prio"
        )

        self.assertEqual(result.status, "success")
        self.assertEqual(result.total_risks_ranked, 3)

        # CR-001 (Public DB with KEV, Tier 1, 5M PII) must rank #1
        self.assertEqual(result.ranked_risks[0].risk_id, "CR-001")
        self.assertTrue(result.ranked_risks[0].priority_tier.startswith("P0"))
        self.assertEqual(result.ranked_risks[0].sla_target_days, 2)

        # CR-002 (Staging build node) must rank #3
        self.assertEqual(result.ranked_risks[2].risk_id, "CR-002")
        self.assertTrue(result.ranked_risks[2].priority_tier.startswith("P3"))
        self.assertEqual(result.ranked_risks[2].sla_target_days, 90)

    def test_decision_service_delegation(self):
        """Verifies AiDecisionSupportService.prioritize_risks delegates cleanly."""
        res = self.decision_service.prioritize_risks()
        self.assertEqual(res.status, "success")
        self.assertGreater(res.total_risks_ranked, 0)
        self.assertIn("Core Banking", res.ranked_risks[0].asset_name)

    def test_rest_post_endpoint_default(self):
        """Tests POST /api/assistant/prioritize-risks with empty payload (live ranking)."""
        response = self.client.post("/api/assistant/prioritize-risks", json={})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertGreater(data["total_risks_ranked"], 0)
        self.assertIn("ranked_risks", data)
        self.assertIn("markdown_report", data)
        self.assertGreaterEqual(data["p0_immediate_count"], 1)

    def test_rest_post_endpoint_custom_risks(self):
        """Tests POST /api/assistant/prioritize-risks with custom risks and weights."""
        payload = {
            "custom_risks": [
                {
                    "risk_id": "TEST-1",
                    "risk_title": "Ransomware Ingress via Zero-Day VPN",
                    "asset_name": "Edge VPN Gateway",
                    "business_unit": "Network Infrastructure",
                    "criticality": "Tier 1 - Mission Critical",
                    "cvss_score": 9.9,
                    "epss_score": 0.98,
                    "is_cisa_kev": True,
                    "financial_loss_inr": 90000000.0,
                    "hourly_downtime_cost_inr": 3500000.0,
                    "pii_records": 10000000,
                    "control_hygiene_score": 15.0,
                    "recommended_action": "Emergency Out-of-Band Patch",
                    "responsible_team": "Network SecOps"
                }
            ],
            "weights": {
                "weight_severity": 0.30,
                "weight_impact": 0.30,
                "weight_urgency": 0.30,
                "weight_controls": 0.10
            }
        }
        response = self.client.post("/api/assistant/prioritize-risks", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["total_risks_ranked"], 1)
        self.assertEqual(data["ranked_risks"][0]["risk_id"], "TEST-1")
        self.assertEqual(data["ranked_risks"][0]["priority_tier"], "P0 (Immediate 24-48h)")

    def test_rest_get_endpoint(self):
        """Tests GET /api/assistant/prioritize-risks endpoint."""
        response = self.client.get("/api/assistant/prioritize-risks")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertGreater(data["total_risks_ranked"], 0)
        self.assertIn("ranked_risks", data)

    def test_natural_language_prioritization_query(self):
        """Verifies natural language prioritization query routing in ProjectKnowledgeAgent."""
        agent = ProjectKnowledgeAgent()
        query = "Rank risks based on severity, business impact, urgency and existing controls"
        res = agent.answer_query(query=query, session_id="test_sess_prio_nl")

        self.assertIn("response_markdown", res)
        md = res["response_markdown"]
        self.assertIn("Multi-Criteria Risk Prioritization Dossier", md)
        self.assertIn("Multi-Criteria RPI", md)
        self.assertIn("P0 (Immediate 24-48h)", md)
        self.assertIn("P1 (Critical 7d)", md)

        # Check structured metadata in response
        self.assertIn("data", res)
        self.assertEqual(res["data"].get("topic"), "risk_prioritization")
        self.assertGreater(res["data"].get("total_risks_ranked", 0), 0)

        # Verify chat memory vault saved the exchange
        history = self.memory_store.get_history(session_id="test_sess_prio_nl")
        self.assertGreaterEqual(len(history), 2)
        self.assertEqual(history[0]["role"], "user")
        self.assertEqual(history[1]["role"], "assistant")


if __name__ == "__main__":
    unittest.main()
