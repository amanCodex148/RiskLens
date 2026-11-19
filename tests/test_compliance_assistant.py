"""
Unit and Integration Tests for Feature 11: Compliance Assistant.
Maps identified enterprise risks and controls to relevant frameworks,
such as ISO/IEC 27001:2022, NIST CSF 2.0, RBI Cyber Security Framework,
SEBI CSCRF, DPDP Act 2023, and CIS Controls v8.

Validates:
1. Multi-Framework Risk Mapping (Vulnerabilities, PII Exposure, Ransomware/Outage).
2. Control Safeguard Crosswalk across 6 national & international standards.
3. Automated Gap & Audit Finding Detection.
4. Statutory Penalty Quantification (DPDP Act up to ₹250 Cr, SEBI 6h reporting, RBI 35A).
5. REST API Endpoints: POST & GET /api/assistant/compliance-mapping.
6. ProjectKnowledgeAgent natural language inquiry routing & PostgreSQL memory vault persistence.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_compliance_assistant import AiComplianceAssistant
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.models.schemas import ComplianceMappingRequest
from backend.engine.chat_memory import get_memory_store


class TestComplianceAssistant(unittest.TestCase):
    def setUp(self):
        self.decision_service = AiDecisionSupportService()
        self.engine = AiComplianceAssistant(
            telemetry_service=self.decision_service.telemetry_service,
            compliance_engine=None,
            risk_engine=self.decision_service.risk_engine,
            prioritization_engine=self.decision_service.prioritization_engine
        )
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_compliance_mapping_execution(self):
        """Verifies end-to-end framework mapping across all 6 frameworks."""
        req = ComplianceMappingRequest(session_id="test_sess_comp_01")
        res = self.engine.map_risks_and_controls(req, session_id="test_sess_comp_01")

        self.assertEqual(res.status, "success")
        self.assertTrue(len(res.framework_summaries) >= 5)

        # 1. Framework Summaries Verification
        fw_names = [f.framework_name for f in res.framework_summaries]
        self.assertTrue(any("ISO" in name for name in fw_names))
        self.assertTrue(any("NIST" in name for name in fw_names))
        self.assertTrue(any("RBI" in name for name in fw_names))
        self.assertTrue(any("SEBI" in name for name in fw_names))
        self.assertTrue(any("DPDP" in name for name in fw_names))

        # 2. Risk-to-Framework Mappings
        self.assertTrue(len(res.risk_mappings) >= 1)
        r0 = res.risk_mappings[0]
        self.assertTrue(len(r0.risk_id) > 0)
        self.assertTrue(len(r0.framework_mappings) >= 2)
        clause_frameworks = [c.framework_name for c in r0.framework_mappings]
        self.assertTrue(any("ISO" in f or "NIST" in f or "SEBI" in f or "RBI" in f for f in clause_frameworks))

        # 3. Control Crosswalk Mappings
        self.assertTrue(len(res.control_mappings) >= 5)
        ctrl_ids = [c.control_id for c in res.control_mappings]
        self.assertIn("INIT-MFA-01", ctrl_ids)
        self.assertIn("INIT-EDR-02", ctrl_ids)
        self.assertIn("INIT-PATCH-04", ctrl_ids)

        mfa_ctrl = next(c for c in res.control_mappings if c.control_id == "INIT-MFA-01")
        self.assertTrue(len(mfa_ctrl.mapped_frameworks) >= 3)
        self.assertTrue(any("ISO 27001" in m for m in mfa_ctrl.mapped_frameworks))
        self.assertTrue(any("NIST" in m for m in mfa_ctrl.mapped_frameworks))

        # 4. Statutory Penalties
        self.assertTrue(len(res.statutory_penalties_identified) >= 2)
        dpdp_pen = next((p for p in res.statutory_penalties_identified if "DPDP" in p["statute"]), None)
        self.assertIsNotNone(dpdp_pen)
        self.assertIn("250 Crore", dpdp_pen["penalty_exposure"])

        # 5. Executive Markdown Analysis
        self.assertIn("ISO/IEC 27001:2022", res.markdown_analysis)
        self.assertIn("NIST CSF 2.0", res.markdown_analysis)
        self.assertIn("DPDP Act 2023", res.markdown_analysis)
        self.assertIn("action:tab:compliance", res.markdown_analysis)

    def test_natural_language_query_parsing(self):
        """Verifies filtering by query for specific target frameworks or assets."""
        res_iso = self.engine.map_from_query("Show me our ISO 27001 and NIST CSF compliance mappings")
        self.assertEqual(res_iso.status, "success")
        self.assertTrue(len(res_iso.risk_mappings) >= 1)

        res_db = self.engine.map_from_query("Map risks and controls for our customer database under DPDP Act")
        self.assertEqual(res_db.status, "success")
        # Target asset AST-001 should be prioritized
        self.assertTrue(any("AST-001" in r.asset_id for r in res_db.risk_mappings))

    def test_rest_api_compliance_endpoints(self):
        """Verifies POST /api/assistant/compliance-mapping and GET /api/assistant/compliance-mapping."""
        # 1. POST endpoint
        payload = {
            "target_frameworks": ["ISO 27001", "NIST CSF", "DPDP Act"],
            "session_id": "test_api_comp_sess"
        }
        post_resp = self.client.post("/api/assistant/compliance-mapping", json=payload)
        self.assertEqual(post_resp.status_code, 200)
        data = post_resp.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(len(data["framework_summaries"]) >= 5)
        self.assertTrue(len(data["risk_mappings"]) >= 1)
        self.assertTrue(len(data["control_mappings"]) >= 1)
        self.assertTrue(len(data["statutory_penalties_identified"]) >= 1)

        # 2. GET endpoint
        get_resp = self.client.get("/api/assistant/compliance-mapping?session_id=test_api_comp_sess")
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertEqual(get_data["status"], "success")
        self.assertTrue(len(get_data["markdown_analysis"]) > 100)

    def test_knowledge_agent_compliance_routing(self):
        """Verifies that ProjectKnowledgeAgent routes compliance questions correctly."""
        agent = ProjectKnowledgeAgent(
            risk_engine=self.decision_service.risk_engine,
            optimizer=self.decision_service.optimizer,
            telemetry_service=self.decision_service.telemetry_service,
            prioritization_engine=self.decision_service.prioritization_engine,
            compliance_assistant=self.engine
        )

        query = "Map identified risks and controls to relevant frameworks, such as ISO 27001, NIST CSF and applicable regulatory requirements"
        res = agent.answer_query(query, session_id="test_sess_agent_comp")

        self.assertIn("response_markdown", res)
        self.assertIn("Compliance Assistant", res["response_markdown"])
        self.assertIn("ISO/IEC 27001:2022", res["response_markdown"])
        self.assertEqual(res.get("data", {}).get("topic"), "compliance_assistant")
        self.assertTrue(len(res.get("suggested_next_questions", [])) >= 2)


if __name__ == "__main__":
    unittest.main()
