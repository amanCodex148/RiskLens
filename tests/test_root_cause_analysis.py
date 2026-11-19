"""
Unit and Integration Tests for Feature 9: Root Cause Analysis (RCA).
Identifies underlying causes and dependencies behind a risk, rather than simply describing the symptoms.

Validates:
1. Symptom vs. Root Cause Disambiguation (Observable technical flaws vs. systemic architectural/governance failures).
2. 5-Whys Progressive Depth Decomposition (Levels 1 to 5).
3. Ishikawa Multi-Factor Causal Taxonomy (Architecture, IAM Governance, Process/Patching, IaC Drift, Observability).
4. Upstream & Downstream Dependency Chain Analysis.
5. Corrective and Preventive Action (CAPA) Roadmap (Immediate 24h, Corrective 7d, Preventive 30-90d).
6. REST API Endpoints: POST & GET /api/assistant/root-cause-analysis.
7. ProjectKnowledgeAgent natural language inquiry routing & SQLite memory vault persistence.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_root_cause_analysis import AiRootCauseAnalysisEngine
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.engine.chat_memory import get_memory_store


class TestRootCauseAnalysis(unittest.TestCase):
    def setUp(self):
        self.engine = AiRootCauseAnalysisEngine()
        self.decision_service = AiDecisionSupportService()
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_live_top_risk_root_cause_analysis(self):
        """Verifies RCA on enterprise top risk (AST-001 Core Banking)."""
        result = self.engine.analyze_root_cause(session_id="test_sess_rca_live")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.target_asset_id, "AST-001")
        self.assertIn("Core Banking", result.target_asset_name)

        # 1. Symptom vs Root Cause Disambiguation
        self.assertIn("CVE-2023-4966", result.surface_symptom)
        self.assertIn("Zero-Trust", result.primary_root_cause)

        # 2. 5-Whys Progressive Depth Decomposition
        self.assertEqual(len(result.five_whys), 5)
        for idx, step in enumerate(result.five_whys, 1):
            self.assertEqual(step.level, idx)
            self.assertTrue(len(step.question) > 5)
            self.assertTrue(len(step.finding) > 5)

        # 3. Ishikawa 5 Causal Categories
        self.assertEqual(len(result.causal_factors), 5)
        categories = [f.category for f in result.causal_factors]
        self.assertIn("Architecture & Infrastructure", categories)
        self.assertIn("Identity & Access Governance", categories)
        self.assertIn("Process & Patch Lifecycle", categories)
        self.assertIn("Configuration & IaC Drift", categories)
        self.assertIn("Observability & Telemetry Deficiencies", categories)

        # 4. Dependency Chain
        self.assertGreaterEqual(len(result.dependency_chain), 3)
        dep_types = [d.dependency_type for d in result.dependency_chain]
        self.assertIn("Upstream Dependency", dep_types)
        self.assertIn("Direct Asset", dep_types)
        self.assertIn("Downstream Consumer", dep_types)

        # 5. CAPA Roadmap
        self.assertEqual(len(result.capa_roadmap), 3)
        self.assertIn("Immediate Containment", result.capa_roadmap[0].action_type)
        self.assertIn("Corrective Action", result.capa_roadmap[1].action_type)
        self.assertIn("Preventive Action", result.capa_roadmap[2].action_type)

        # 6. Markdown Dossier
        md = result.markdown_analysis
        self.assertIn("RiskLens Root Cause Analysis (RCA) Dossier (Feature 9)", md)
        self.assertIn("The 5-Whys Progressive Root Cause Drilldown", md)
        self.assertIn("Ishikawa Multi-Factor Causal Taxonomy", md)
        self.assertIn("Corrective and Preventive Actions (CAPA Roadmap)", md)

    def test_database_exposure_root_cause_analysis(self):
        """Verifies RCA on customer database exposure inquiry."""
        query = "Our customer database is publicly accessible on port 5432"
        result = self.engine.analyze_root_cause(risk_description_or_id=query)

        self.assertEqual(result.status, "success")
        self.assertEqual(result.target_asset_id, "AST-003")
        self.assertIn("port 5432", result.surface_symptom.lower())
        self.assertIn("private vpc", result.primary_root_cause.lower())

        # Validate 5-Whys drilldown
        self.assertEqual(len(result.five_whys), 5)
        self.assertIn("security group", result.five_whys[0].finding.lower())
        self.assertIn("jit", result.five_whys[4].finding.lower())

    def test_decision_service_delegation(self):
        """Verifies AiDecisionSupportService.analyze_root_cause delegates cleanly."""
        res = self.decision_service.analyze_root_cause()
        self.assertEqual(res.status, "success")
        self.assertEqual(res.target_asset_id, "AST-001")

    def test_rest_post_endpoint(self):
        """Tests POST /api/assistant/root-cause-analysis endpoint."""
        payload = {
            "risk_description_or_id": "Our customer database is publicly accessible"
        }
        response = self.client.post("/api/assistant/root-cause-analysis", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["target_asset_id"], "AST-003")
        self.assertEqual(len(data["five_whys"]), 5)
        self.assertEqual(len(data["causal_factors"]), 5)
        self.assertIn("markdown_analysis", data)

    def test_rest_get_endpoint(self):
        """Tests GET /api/assistant/root-cause-analysis endpoint."""
        response = self.client.get("/api/assistant/root-cause-analysis")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["target_asset_id"], "AST-001")
        self.assertIn("markdown_analysis", data)

    def test_natural_language_root_cause_query_in_knowledge_agent(self):
        """Verifies ProjectKnowledgeAgent handles RCA inquiries and records chat memory."""
        agent = ProjectKnowledgeAgent()
        query = "Perform root cause analysis on our top risk to identify underlying causes and dependencies"
        res = agent.answer_query(query=query, session_id="test_sess_rca_nl")

        self.assertIn("response_markdown", res)
        md = res["response_markdown"]
        self.assertIn("RiskLens Root Cause Analysis (RCA) Dossier (Feature 9)", md)
        self.assertIn("The 5-Whys Progressive Root Cause Drilldown", md)
        self.assertIn("Ishikawa Multi-Factor Causal Taxonomy", md)

        # Check structured metadata
        self.assertIn("data", res)
        self.assertEqual(res["data"].get("topic"), "root_cause_analysis")
        self.assertEqual(res["data"].get("target_asset_id"), "AST-001")
        self.assertEqual(res["data"].get("five_whys_count"), 5)

        # Verify SQLite conversation memory vault saved the exchange
        history = self.memory_store.get_history(session_id="test_sess_rca_nl")
        self.assertGreaterEqual(len(history), 2)
        self.assertEqual(history[0]["role"], "user")
        self.assertEqual(history[1]["role"], "assistant")


if __name__ == "__main__":
    unittest.main()
