"""
Unit and Integration Tests for Feature 8: Scenario Analysis.
Answers hypothetical and What-If questions such as:
"What happens if our primary server goes offline?"
"What happens if our customer database is breached?"
"What happens if ransomware encrypts our core payment gateway?"

Validates:
1. Operational Blast Radius & Cascading Application Dependencies.
2. Financial Loss Quantification (Open FAIR™ Model):
   Direct downtime revenue losses, Monte Carlo EAL shift, 95% VaR, statutory liabilities (DPDP Act).
3. Resilience & Single Points of Failure (SPOF) assessment.
4. 3-Phase Incident Containment & Hardening Directives.
5. REST API endpoint: POST /api/assistant/scenario-analysis.
6. ProjectKnowledgeAgent natural language inquiry routing & PostgreSQL memory persistence.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_scenario_analysis import AiScenarioAnalysisEngine
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.engine.chat_memory import get_memory_store


class TestScenarioAnalysis(unittest.TestCase):
    def setUp(self):
        self.engine = AiScenarioAnalysisEngine()
        self.decision_service = AiDecisionSupportService()
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_primary_server_offline_analysis(self):
        """Verifies hypothetical question: 'What happens if our primary server goes offline?'"""
        query = "What happens if our primary server goes offline?"
        result = self.engine.analyze_scenario(query=query, session_id="test_sess_primary_server")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.scenario_query, query)
        self.assertIn("Core Banking", result.operational_impact.target_asset_name)
        self.assertEqual(result.operational_impact.target_asset_id, "AST-001")

        # Verify Financial Quantification
        fin = result.financial_impact
        self.assertGreater(fin.hourly_downtime_rate_inr, 0)
        self.assertGreater(fin.outage_duration_hours, 0)
        expected_direct_loss = fin.hourly_downtime_rate_inr * fin.outage_duration_hours
        self.assertAlmostEqual(fin.direct_downtime_loss_inr, expected_direct_loss, delta=1.0)
        self.assertGreater(fin.total_projected_loss_inr, fin.direct_downtime_loss_inr)
        self.assertGreater(fin.simulated_eal_inr, 0)

        # Verify Operational Cascading Disruptions
        op = result.operational_impact
        self.assertGreaterEqual(len(op.cascading_disruptions), 3)
        self.assertTrue(any("upi" in d.lower() or "payment" in d.lower() for d in op.cascading_disruptions))
        self.assertTrue(any("atm" in d.lower() or "netbanking" in d.lower() for d in op.cascading_disruptions))
        self.assertGreater(op.pii_records_at_risk, 1000000)

        # Verify Resilience & SPOFs
        res = result.resilience_status
        self.assertGreaterEqual(len(res.single_points_of_failure), 1)
        self.assertGreater(res.failover_readiness_score, 0)

        # Verify 3-Phase Action Plan
        self.assertEqual(len(result.action_plan), 3)
        self.assertIn("Phase 1", result.action_plan[0].phase)
        self.assertIn("Phase 2", result.action_plan[1].phase)
        self.assertIn("Phase 3", result.action_plan[2].phase)

        # Verify Markdown Dossier
        md = result.markdown_analysis
        self.assertIn("RiskLens Hypothetical Scenario Analysis (Feature 8)", md)
        self.assertIn("Financial Loss Quantification (Open FAIR™ Model)", md)
        self.assertIn("Cascading Upstream & Downstream Disruptions", md)
        self.assertIn("Phased Incident Mitigation & Business Continuity Directives", md)

    def test_custom_outage_hours_extraction(self):
        """Verifies regex extraction of custom outage duration: 'offline for 12 hours'."""
        query = "What happens if our primary server goes offline for 12 hours?"
        result = self.engine.analyze_scenario(query=query)

        fin = result.financial_impact
        self.assertEqual(fin.outage_duration_hours, 12.0)
        self.assertEqual(fin.direct_downtime_loss_inr, fin.hourly_downtime_rate_inr * 12.0)

    def test_customer_database_breach_scenario(self):
        """Verifies hypothetical question: 'What happens if our customer database is breached?'"""
        query = "What happens if our customer database is breached?"
        result = self.engine.analyze_scenario(query=query)

        self.assertEqual(result.status, "success")
        self.assertIn("Oracle", result.operational_impact.target_asset_name)
        self.assertEqual(result.operational_impact.target_asset_id, "AST-003")
        self.assertGreaterEqual(result.financial_impact.statutory_fine_exposure_inr, 25000000.0)
        self.assertIn("DPDP Act", result.markdown_analysis)

    def test_ransomware_outbreak_scenario(self):
        """Verifies hypothetical question: 'What happens if ransomware encrypts the core payment gateway?'"""
        query = "What happens if ransomware encrypts the core payment gateway?"
        result = self.engine.analyze_scenario(query=query)

        self.assertEqual(result.status, "success")
        self.assertIn("Ransomware", result.scenario_type)
        self.assertGreaterEqual(result.financial_impact.incident_response_cost_inr, 15000000.0)

    def test_decision_service_delegation(self):
        """Verifies AiDecisionSupportService.analyze_scenario delegates cleanly."""
        res = self.decision_service.analyze_scenario(query="What happens if our primary server goes offline?")
        self.assertEqual(res.status, "success")
        self.assertEqual(res.operational_impact.target_asset_id, "AST-001")

    def test_rest_post_endpoint(self):
        """Tests POST /api/assistant/scenario-analysis endpoint."""
        payload = {
            "scenario_query": "What happens if our primary server goes offline?",
            "outage_hours": 6.0
        }
        response = self.client.post("/api/assistant/scenario-analysis", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["financial_impact"]["outage_duration_hours"], 6.0)
        self.assertIn("markdown_analysis", data)
        self.assertGreater(data["financial_impact"]["direct_downtime_loss_inr"], 0)

    def test_natural_language_scenario_query_in_knowledge_agent(self):
        """Verifies ProjectKnowledgeAgent handles 'What happens if our primary server goes offline?' and saves memory."""
        agent = ProjectKnowledgeAgent()
        query = "What happens if our primary server goes offline?"
        res = agent.answer_query(query=query, session_id="test_sess_scenario_nl")

        self.assertIn("response_markdown", res)
        md = res["response_markdown"]
        self.assertIn("RiskLens Hypothetical Scenario Analysis (Feature 8)", md)
        self.assertIn("Financial Loss Quantification (Open FAIR™ Model)", md)
        self.assertIn("Cascading Upstream & Downstream Disruptions", md)

        # Check structured metadata
        self.assertIn("data", res)
        self.assertEqual(res["data"].get("topic"), "scenario_analysis")
        self.assertEqual(res["data"].get("target_asset_id"), "AST-001")
        self.assertGreater(res["data"].get("direct_downtime_loss_inr", 0), 0)

        # Verify PostgreSQL conversation memory vault persisted the exchange
        history = self.memory_store.get_history(session_id="test_sess_scenario_nl")
        self.assertGreaterEqual(len(history), 2)
        self.assertEqual(history[0]["role"], "user")
        self.assertEqual(history[1]["role"], "assistant")


if __name__ == "__main__":
    unittest.main()
