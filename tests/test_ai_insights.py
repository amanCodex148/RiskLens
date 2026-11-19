"""
Unit and Integration Tests for Feature 12: AI Insights.
Identifies recurring risks, weak controls, risk trends, and areas
requiring executive management attention.

Validates:
1. Systemic Recurring Risk Patterns (Patching SLA lags, PII exposure, lateral movement).
2. Weak & Deficient Controls Detection & FAIR Impact Analysis.
3. Multi-Horizon Inertial Risk Trends (Current Baseline, 30d, 60d, 90d drift).
4. Prioritized Areas Requiring Executive Management Attention (Urgency tiers & C-suite assignments).
5. REST API Endpoints: POST & GET /api/assistant/insights.
6. ProjectKnowledgeAgent natural language inquiry routing & PostgreSQL memory vault persistence.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_insights import AiInsightsEngine
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.models.schemas import AiInsightsRequest
from backend.engine.chat_memory import get_memory_store


class TestAiInsights(unittest.TestCase):
    def setUp(self):
        self.decision_service = AiDecisionSupportService()
        self.engine = AiInsightsEngine(
            telemetry_service=self.decision_service.telemetry_service,
            risk_engine=self.decision_service.risk_engine,
            optimizer=self.decision_service.optimizer,
            prioritization_engine=self.decision_service.prioritization_engine,
            compliance_engine=None
        )
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_ai_insights_generation(self):
        """Verifies end-to-end multi-dimensional AI Insights synthesis."""
        req = AiInsightsRequest(session_id="test_sess_ins_01")
        res = self.engine.generate_insights(req, session_id="test_sess_ins_01")

        self.assertEqual(res.status, "success")
        self.assertTrue(len(res.insights_summary) > 20)
        self.assertIn(res.overall_risk_trajectory, [
            "Escalating Risk Drift",
            "Moderate Posture Degradation",
            "Stable Posture",
            "Improving"
        ])

        # 1. Recurring Risks Verification
        self.assertTrue(len(res.recurring_risks) >= 3)
        pattern_themes = [p.risk_theme for p in res.recurring_risks]
        self.assertTrue(any("Patching SLA" in t for t in pattern_themes))
        self.assertTrue(any("PII" in t for t in pattern_themes))
        self.assertTrue(any("Lateral Movement" in t for t in pattern_themes))

        p0 = res.recurring_risks[0]
        self.assertTrue(p0.affected_assets_count >= 1)
        self.assertTrue(p0.cumulative_loss_exposure_inr > 0.0)
        self.assertTrue(len(p0.root_cause_driver) > 10)

        # 2. Weak Controls Verification
        self.assertTrue(len(res.weak_controls) >= 3)
        ctrl_ids = [w.control_id for w in res.weak_controls]
        self.assertIn("CTRL-VM-SLA", ctrl_ids)
        self.assertIn("CTRL-CSPM-AUD", ctrl_ids)

        vm_ctrl = next(w for w in res.weak_controls if w.control_id == "CTRL-VM-SLA")
        self.assertLess(vm_ctrl.telemetry_score, 0.70)
        self.assertIn("FAIR", vm_ctrl.fair_impact)
        self.assertIn("INIT-PATCH-04", vm_ctrl.recommended_initiative)

        # 3. Risk Trends Verification
        self.assertEqual(len(res.risk_trends), 4)  # Baseline, 30d, 60d, 90d
        horizons = [t.horizon for t in res.risk_trends]
        self.assertIn("Current Baseline", horizons)
        self.assertIn("30-Day Inertial Drift", horizons)
        self.assertIn("60-Day Inertial Drift", horizons)
        self.assertIn("90-Day Inertial Drift", horizons)

        # Drift should be non-decreasing over time
        self.assertEqual(res.risk_trends[0].drift_percentage, 0.0)
        self.assertGreater(res.risk_trends[1].drift_percentage, 0.0)
        self.assertGreater(res.risk_trends[2].drift_percentage, res.risk_trends[1].drift_percentage)
        self.assertGreater(res.risk_trends[3].drift_percentage, res.risk_trends[2].drift_percentage)

        # 4. Management Attention Verification
        self.assertTrue(len(res.management_attention_areas) >= 3)
        urgencies = [a.urgency_level for a in res.management_attention_areas]
        self.assertTrue(any("Immediate" in u for u in urgencies))
        self.assertTrue(any("High Priority" in u for u in urgencies))
        self.assertTrue(any("Strategic" in u for u in urgencies))

        attn0 = res.management_attention_areas[0]
        self.assertTrue(len(attn0.responsible_executive) > 3)
        self.assertTrue(len(attn0.mandated_action) > 10)
        self.assertTrue(attn0.financial_exposure_at_risk_inr > 0.0)

        # 5. Executive Markdown Dossier Verification
        self.assertIn("AI Insights", res.markdown_briefing)
        self.assertIn("Recurring Risk Patterns", res.markdown_briefing)
        self.assertIn("Weak & Deficient Controls", res.markdown_briefing)
        self.assertIn("action:tab:boardroom", res.markdown_briefing)

    def test_natural_language_query_parsing(self):
        """Verifies filtering by query for specific focus areas."""
        res_rec = self.engine.generate_from_query("What are our recurring risk patterns across departments?")
        self.assertEqual(res_rec.status, "success")
        self.assertTrue(len(res_rec.recurring_risks) >= 3)

        res_weak = self.engine.generate_from_query("Which security controls are weak or deficient?")
        self.assertEqual(res_weak.status, "success")
        self.assertTrue(len(res_weak.weak_controls) >= 3)

        res_trend = self.engine.generate_from_query("What is our 90-day cyber risk trajectory trend?")
        self.assertEqual(res_trend.status, "success")
        self.assertEqual(len(res_trend.risk_trends), 4)

    def test_rest_api_insights_endpoints(self):
        """Verifies POST /api/assistant/insights and GET /api/assistant/insights."""
        # 1. POST endpoint
        payload = {
            "focus_area": "all",
            "time_horizon_days": 90,
            "session_id": "test_api_ins_sess"
        }
        post_resp = self.client.post("/api/assistant/insights", json=payload)
        self.assertEqual(post_resp.status_code, 200)
        data = post_resp.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(len(data["recurring_risks"]) >= 3)
        self.assertTrue(len(data["weak_controls"]) >= 3)
        self.assertTrue(len(data["risk_trends"]) == 4)
        self.assertTrue(len(data["management_attention_areas"]) >= 3)

        # 2. GET endpoint
        get_resp = self.client.get("/api/assistant/insights?session_id=test_api_ins_sess")
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertEqual(get_data["status"], "success")
        self.assertTrue(len(get_data["markdown_briefing"]) > 100)

    def test_knowledge_agent_insights_routing(self):
        """Verifies that ProjectKnowledgeAgent properly routes AI Insights inquiries."""
        agent = ProjectKnowledgeAgent(
            risk_engine=self.decision_service.risk_engine,
            optimizer=self.decision_service.optimizer,
            telemetry_service=self.decision_service.telemetry_service,
            prioritization_engine=self.decision_service.prioritization_engine,
            insights_engine=self.engine
        )

        query = "Identify recurring risks, weak controls, risk trends and areas requiring management attention"
        res = agent.answer_query(query, session_id="test_sess_agent_ins")

        self.assertIn("response_markdown", res)
        self.assertIn("AI Insights", res["response_markdown"])
        self.assertEqual(res.get("data", {}).get("topic"), "ai_insights")
        self.assertTrue(len(res.get("suggested_next_questions", [])) >= 2)


if __name__ == "__main__":
    unittest.main()
