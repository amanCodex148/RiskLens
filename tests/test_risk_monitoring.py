"""
Unit and Integration Tests for Feature 10: Risk Monitoring & Continuous Reassessment.
Reassesses enterprise risks dynamically when users update assets, controls,
incidents, or other relevant threat telemetry information.

Validates:
1. Dynamic Mutation Detection across Assets, Controls, and Security Incidents.
2. Comparative Reassessment Modeling (Baseline vs Reassessed EAL, 95% VaR, Risk Score).
3. Posture Drift Classification (Posture Improved, Posture Degraded, Neutral).
4. 5x5 Matrix coordinate shifts and Priority Tier transitions (P0, P1, P2).
5. Immutable Continuous Monitoring Audit Trail.
6. REST API Endpoints: POST & GET /api/assistant/risk-monitoring/reassess and /status.
7. ProjectKnowledgeAgent natural language query routing & SQLite memory vault persistence.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_risk_monitoring import AiRiskMonitoringEngine
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.models.schemas import RiskMonitoringReassessmentRequest
from backend.engine.chat_memory import get_memory_store


class TestRiskMonitoring(unittest.TestCase):
    def setUp(self):
        self.engine = AiRiskMonitoringEngine()
        self.decision_service = AiDecisionSupportService()
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_control_update_reassessment(self):
        """Verifies that strengthening controls reduces risk and improves posture."""
        req = RiskMonitoringReassessmentRequest(
            mutation_type="control_update",
            control_id="INIT-MFA-01",
            control_updates={"telemetry_score": 0.95, "implementation_status": "Enforced"},
            session_id="test_sess_mon_ctrl"
        )
        res = self.engine.reassess_monitoring(req, session_id="test_sess_mon_ctrl")

        self.assertEqual(res.status, "success")
        self.assertEqual(res.mutation_type, "control_update")
        self.assertIn("INIT-MFA-01", res.mutation_summary)
        self.assertEqual(res.overall_posture_drift, "Risk Reduced (Posture Improved)")

        # Verify metrics comparison
        eal_comp = next((m for m in res.metrics_comparison if "Annual Loss" in m.metric_name), None)
        self.assertIsNotNone(eal_comp)
        self.assertLess(eal_comp.delta_value, 0.0)
        self.assertLess(eal_comp.delta_percentage, 0.0)

        # Verify 5x5 matrix shift
        self.assertTrue(len(res.impacted_assets) >= 1)
        shift = res.impacted_assets[0]
        self.assertLessEqual(shift.reassessed_likelihood, shift.baseline_likelihood)

        # Verify audit trail
        self.assertTrue(len(res.audit_trail) >= 2)
        latest_audit = res.audit_trail[-1]
        self.assertEqual(latest_audit.mutation_type, "control_update")
        self.assertLess(latest_audit.eal_impact_inr, 0.0)

        # Verify markdown briefing
        self.assertIn("Risk Reduced (Posture Improved)", res.markdown_briefing)
        self.assertIn("EAL", res.markdown_briefing)

    def test_asset_update_reassessment(self):
        """Verifies that increasing asset revenue exposure escalates risk."""
        req = RiskMonitoringReassessmentRequest(
            mutation_type="asset_update",
            asset_id="AST-001",
            asset_updates={"revenue_per_hour_inr": 3500000.0, "pii_records_count": 8000000},
            session_id="test_sess_mon_asset"
        )
        res = self.engine.reassess_monitoring(req, session_id="test_sess_mon_asset")

        self.assertEqual(res.status, "success")
        self.assertEqual(res.mutation_type, "asset_update")
        self.assertEqual(res.overall_posture_drift, "Risk Escalated (Posture Degraded)")

        eal_comp = next((m for m in res.metrics_comparison if "Annual Loss" in m.metric_name), None)
        self.assertIsNotNone(eal_comp)
        self.assertGreater(eal_comp.delta_value, 0.0)

        # Impacted asset check
        self.assertTrue(len(res.impacted_assets) >= 1)
        self.assertEqual(res.impacted_assets[0].asset_id, "AST-001")
        self.assertEqual(res.impacted_assets[0].priority_tier_after, "P0 (Immediate 24-48h)")

    def test_incident_update_reassessment(self):
        """Verifies that logging an active incident escalates posture to P0 immediately."""
        req = RiskMonitoringReassessmentRequest(
            mutation_type="incident_update",
            asset_id="AST-001",
            incident_details={
                "title": "Active Ransomware Lateral Infection",
                "severity": "Critical",
                "is_contained": False,
                "outage_hours": 8.0
            },
            session_id="test_sess_mon_inc"
        )
        res = self.engine.reassess_monitoring(req, session_id="test_sess_mon_inc")

        self.assertEqual(res.status, "success")
        self.assertEqual(res.mutation_type, "incident_update")
        self.assertIn("Ransomware", res.mutation_summary)
        self.assertEqual(res.overall_posture_drift, "Risk Escalated (Posture Degraded)")

        shift = res.impacted_assets[0]
        self.assertEqual(shift.reassessed_likelihood, 5)
        self.assertEqual(shift.reassessed_impact, 5)
        self.assertEqual(shift.priority_tier_after, "P0 (Immediate 24-48h)")

    def test_reassess_from_natural_language_query(self):
        """Verifies query parsing for natural language requests."""
        res_ctrl = self.engine.reassess_from_query("Reassess risks after our MFA and EDR control updates")
        self.assertEqual(res_ctrl.mutation_type, "control_update")

        res_inc = self.engine.reassess_from_query("What is our risk after the ransomware incident outage?")
        self.assertEqual(res_inc.mutation_type, "incident_update")

        res_asset = self.engine.reassess_from_query("Reassess risk after updating customer database asset revenue")
        self.assertEqual(res_asset.mutation_type, "asset_update")

    def test_rest_api_risk_monitoring_endpoints(self):
        """Verifies POST /api/assistant/risk-monitoring/reassess and GET /api/assistant/risk-monitoring/status."""
        # 1. POST endpoint
        payload = {
            "mutation_type": "control_update",
            "control_id": "INIT-MFA-01",
            "control_updates": {"telemetry_score": 0.95, "implementation_status": "Enforced"},
            "session_id": "test_api_mon_sess"
        }
        post_resp = self.client.post("/api/assistant/risk-monitoring/reassess", json=payload)
        self.assertEqual(post_resp.status_code, 200)
        data = post_resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["overall_posture_drift"], "Risk Reduced (Posture Improved)")
        self.assertTrue(len(data["metrics_comparison"]) >= 3)
        self.assertTrue(len(data["audit_trail"]) >= 1)

        # 2. GET status endpoint
        get_resp = self.client.get("/api/assistant/risk-monitoring/status?session_id=test_api_mon_sess")
        self.assertEqual(get_resp.status_code, 200)
        status_data = get_resp.json()
        self.assertEqual(status_data["status"], "success")
        self.assertTrue(len(status_data["markdown_briefing"]) > 50)

    def test_knowledge_agent_risk_monitoring_routing(self):
        """Verifies that ProjectKnowledgeAgent properly routes risk monitoring questions."""
        agent = ProjectKnowledgeAgent(
            risk_engine=self.decision_service.risk_engine,
            optimizer=self.decision_service.optimizer,
            telemetry_service=self.decision_service.telemetry_service,
            prioritization_engine=self.decision_service.prioritization_engine,
            monitoring_engine=self.engine
        )

        query = "Reassess risks after our latest asset, control, and incident updates"
        res = agent.answer_query(query, session_id="test_sess_agent_mon")

        self.assertIn("response_markdown", res)
        self.assertIn("Continuous Risk Monitoring", res["response_markdown"])
        self.assertEqual(res.get("data", {}).get("topic"), "risk_monitoring")
        self.assertTrue(len(res.get("suggested_next_questions", [])) >= 2)


if __name__ == "__main__":
    unittest.main()
