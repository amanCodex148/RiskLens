"""
Comprehensive Test Suite for RiskLens AI Project & Cyber Risk Copilot.
Verifies that the integrated AI agent possesses exhaustive knowledge of:
1. Every single dashboard and component on the main web page.
2. How the platform works, architectural pipeline, and mathematical foundations.
3. FAIR-CAM Monte Carlo, EAL, VaR, CVaR, Loss Exceedance Curve.
4. Investment Optimizer, 0-1 Knapsack MILP, Efficient Frontier, Diminishing Returns.
5. What-If Scenario Studio, strategic stress tests, and mathematical drivers.
6. Regulatory Compliance Radar, RBI CSF, SEBI CSCRF, DPDP Act 2023, ISO 27001, NIST CSF 2.0.
7. Asset Explorer, EPSS vs CVSS exploit matrix, and CISA KEV prioritization.
8. 20 Pre-configured enterprise industry datasets and Data Exchange import/export.
"""

import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app
from backend.engine.ai_knowledge import ProjectKnowledgeAgent, WEB_COMPONENTS_CATALOG
from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer
from backend.ingestion.telemetry_loader import TelemetryService


class TestAiKnowledgeAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.telemetry = TelemetryService.get_instance()
        cls.telemetry.reset_to_default()
        cls.risk_engine = FairRiskEngine(iterations=1000)
        cls.risk_engine.invalidate_cache()
        cls.optimizer = InvestmentOptimizer(risk_engine=cls.risk_engine)
        cls.agent = ProjectKnowledgeAgent(
            risk_engine=cls.risk_engine,
            optimizer=cls.optimizer,
            telemetry_service=cls.telemetry
        )

    @classmethod
    def tearDownClass(cls):
        try:
            cls.telemetry.reset_to_default()
            cls.risk_engine.invalidate_cache()
        except Exception:
            pass

    def test_catalog_integrity(self):
        """Verifies that all 7 primary UI areas are cataloged with components."""
        self.assertIn("boardroom", WEB_COMPONENTS_CATALOG)
        self.assertIn("optimizer", WEB_COMPONENTS_CATALOG)
        self.assertIn("scenarios", WEB_COMPONENTS_CATALOG)
        self.assertIn("compliance", WEB_COMPONENTS_CATALOG)
        self.assertIn("assets", WEB_COMPONENTS_CATALOG)
        self.assertIn("data_exchange", WEB_COMPONENTS_CATALOG)
        self.assertIn("header", WEB_COMPONENTS_CATALOG)
        self.assertGreaterEqual(len(WEB_COMPONENTS_CATALOG["boardroom"]["components"]), 6)
        self.assertGreaterEqual(len(WEB_COMPONENTS_CATALOG["optimizer"]["components"]), 4)

    def test_ai_knows_all_web_components_and_dashboards(self):
        """Verifies AI provides an exhaustive walkthrough of every dashboard and component on the main page."""
        res = self.agent.answer_query("Explain every single dashboard and component on main web page")
        md = res["response_markdown"]
        self.assertIn("Top Navigation Header", md)
        self.assertIn("Executive Boardroom Dashboard", md)
        self.assertIn("Investment Optimizer", md)
        self.assertIn("What-If Scenario Studio", md)
        self.assertIn("Regulatory & Compliance Dashboard", md)
        self.assertIn("Asset & CVE Explorer", md)
        self.assertIn("Enterprise Risk Data Exchange Modal", md)
        self.assertIn("action:tab:boardroom", md)
        self.assertIn("action:tab:optimizer", md)
        self.assertIn("action:tab:scenarios", md)
        self.assertIn("action:tab:compliance", md)
        self.assertIn("action:tab:assets", md)
        self.assertIn("suggested_next_questions", res)
        self.assertGreaterEqual(len(res["suggested_next_questions"]), 2)

    def test_ai_knows_how_it_works_and_mathematics(self):
        """Verifies AI explains the architecture, FAIR-CAM, and Monte Carlo mathematics."""
        res = self.agent.answer_query("How does RiskLens work and what are its mathematical foundations?")
        md = res["response_markdown"]
        self.assertIn("Open FAIR™", md)
        self.assertIn("Monte Carlo", md)
        self.assertIn("Beta-PERT", md)
        self.assertIn("Poisson", md)
        self.assertIn("Expected Annual Loss", md)
        self.assertIn("Value at Risk (VaR)", md)
        self.assertIn("0-1 Knapsack", md)
        self.assertIn("Return on Security Investment (ROSI)", md)

    def test_ai_knows_boardroom_components(self):
        """Verifies AI explains the Executive Boardroom components and current metrics."""
        res = self.agent.answer_query("What components are inside the Executive Boardroom dashboard?")
        md = res["response_markdown"]
        self.assertIn("Enterprise Risk Score", md)
        self.assertIn("Expected Annual Loss (EAL)", md)
        self.assertIn("95% Value at Risk (VaR)", md)
        self.assertIn("Conditional VaR", md)
        self.assertIn("Loss Exceedance Curve", md)
        self.assertIn("Loss by Business Unit", md)
        self.assertIn("Primary vs Secondary Loss", md)
        self.assertIn("action:tab:boardroom", md)

    def test_ai_knows_optimizer_and_diminishing_returns(self):
        """Verifies AI explains the Investment Optimizer, Knapsack DP, and Diminishing Returns threshold."""
        res = self.agent.answer_query("How does the Investment Optimizer work and what is diminishing returns?")
        md = res["response_markdown"]
        self.assertIn("Knapsack", md)
        self.assertIn("ROSI", md)
        self.assertIn("Efficient Frontier", md)
        self.assertIn("Diminishing Returns", md)
        self.assertIn("action:tab:optimizer", md)

    def test_ai_knows_what_if_scenarios(self):
        """Verifies AI details the 5 stress test scenarios in What-If Studio."""
        res = self.agent.answer_query("Explain the What-If Scenario Studio and available stress tests")
        md = res["response_markdown"]
        self.assertIn("SCEN-MFA-ALL", md)
        self.assertIn("SCEN-PATCH-DELAY-30", md)
        self.assertIn("SCEN-ZERO-DAY-WEB", md)
        self.assertIn("SCEN-RANSOM-CORE", md)
        self.assertIn("SCEN-MICROSEG-CLOUD", md)
        self.assertIn("action:tab:scenarios", md)

    def test_ai_knows_compliance_radar(self):
        """Verifies AI details the 5 regulatory frameworks and radar chart."""
        res = self.agent.answer_query("Explain the Regulatory Compliance Framework Radar")
        md = res["response_markdown"]
        self.assertIn("RBI Cyber Security Framework", md)
        self.assertIn("SEBI", md)
        self.assertIn("ISO/IEC 27001", md)
        self.assertIn("NIST Cybersecurity Framework", md)
        self.assertIn("CIS Critical Security Controls", md)
        self.assertIn("action:tab:compliance", md)

    def test_ai_knows_asset_explorer_and_epss(self):
        """Verifies AI explains EPSS vs CVSS matrix and CISA KEV prioritization."""
        res = self.agent.answer_query("How does the EPSS vs CVSS exploit matrix prioritize vulnerabilities?")
        md = res["response_markdown"]
        self.assertIn("CVSS", md)
        self.assertIn("EPSS", md)
        self.assertIn("CISA KEV", md)
        self.assertIn("Upper-Right Quadrant", md)
        self.assertIn("action:tab:assets", md)

    def test_ai_knows_20_datasets_and_data_exchange(self):
        """Verifies AI describes the 20 industry datasets and import/export capabilities."""
        res = self.agent.answer_query("What are the 20 pre-configured enterprise industry datasets?")
        md = res["response_markdown"]
        self.assertIn("20 Pre-Configured Industry Datasets", md)
        self.assertIn("Retail & Commercial Banking", md)
        self.assertIn("Healthcare", md)
        self.assertIn("FinTech", md)
        self.assertIn("action:modal:data", md)

    def test_ai_query_via_fastapi_endpoint(self):
        """Verifies end-to-end HTTP POST to /api/assistant/query with comprehensive knowledge."""
        resp = self.client.post("/api/assistant/query", json={
            "query": "Give me an overview of all dashboards and components on the main web page"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("response_markdown", data)
        self.assertIn("Executive Boardroom Dashboard", data["response_markdown"])
        self.assertIn("Investment Optimizer", data["response_markdown"])
        self.assertIn("suggested_next_questions", data)
        self.assertTrue(data.get("memory_active"))

    def test_chat_memory_store_lifecycle(self):
        """Verifies PostgreSQL persistent chat memory save, retrieve, and clear operations."""
        from backend.engine.chat_memory import ChatMemoryStore
        store = ChatMemoryStore(db_path=":memory:")
        sess = "test_sess_101"

        # Save turns
        m1 = store.save_message(sess, "user", "What is our highest risk asset?", user_email="ciso@test.com")
        self.assertGreater(m1, 0)
        m2 = store.save_message(sess, "assistant", "Our highest risk is Core Transaction Engine.", user_email="ciso@test.com")
        self.assertGreater(m2, m1)

        # Retrieve history
        hist = store.get_history(session_id=sess)
        self.assertEqual(len(hist), 2)
        self.assertEqual(hist[0]["role"], "user")
        self.assertEqual(hist[1]["role"], "assistant")
        self.assertIn("Core Transaction Engine", hist[1]["content"])

        # Clear history
        cleared = store.clear_history(session_id=sess)
        self.assertEqual(cleared, 2)
        self.assertEqual(len(store.get_history(session_id=sess)), 0)
        store.close()

    def test_ai_multi_turn_anaphora_memory(self):
        """Verifies AI resolves follow-up pronoun 'its' to the previously discussed asset."""
        # Turn 1
        t1_query = "What is our highest financial cyber risk today?"
        t1_res = self.agent.answer_query(t1_query)
        self.assertIn("Top Financial Cyber Risk", t1_res["response_markdown"])

        ctx = self.agent._get_live_context_snapshot()
        expected_top = ctx["top_asset"]["asset_name"] if ctx.get("top_asset") else "Core Transaction Engine"
        self.assertIn(expected_top, t1_res["response_markdown"])

        # History with Turn 1
        history = [
            {"role": "user", "content": t1_query},
            {"role": "assistant", "content": t1_res["response_markdown"]}
        ]

        # Turn 2: Follow-up using pronoun "its top CVE" without mentioning asset name
        t2_query = "What is its top CVE and exploit probability?"
        t2_res = self.agent.answer_query(t2_query, history=history)
        md2 = t2_res["response_markdown"]
        self.assertIn("Context Memory Follow-Up", md2)
        self.assertIn(expected_top, md2)

        # Turn 3: Follow-up asking for hourly downtime cost
        history.extend([
            {"role": "user", "content": t2_query},
            {"role": "assistant", "content": md2}
        ])
        t3_query = "What is its downtime cost per hour?"
        t3_res = self.agent.answer_query(t3_query, history=history)
        md3 = t3_res["response_markdown"]
        self.assertIn("Context Memory Follow-Up", md3)
        self.assertIn("Hourly Outage Cost", md3)

    def test_ai_chat_summary_memory(self):
        """Verifies AI summarizes past conversation history upon request."""
        history = [
            {"role": "user", "content": "What is our highest financial risk?"},
            {"role": "assistant", "content": "Our highest risk is Core Transaction Engine contributing ₹3.5 Cr in EAL."},
            {"role": "user", "content": "How should we allocate a 1 crore budget?"},
            {"role": "assistant", "content": "Allocating ₹1.00 Crore achieves 450% portfolio ROSI."}
        ]
        res = self.agent.answer_query("Summarize our chat history so far", history=history)
        md = res["response_markdown"]
        self.assertIn("Active Conversation Memory Summary", md)
        self.assertIn("What is our highest financial risk?", md)
        self.assertIn("How should we allocate a 1 crore budget?", md)

    def test_history_rest_endpoints(self):
        """Verifies GET and DELETE /api/assistant/history endpoints."""
        sess_id = "test_rest_sess_999"

        # 1. Post query with session_id
        post_resp = self.client.post("/api/assistant/query", json={
            "query": "What is our highest financial cyber risk today?",
            "session_id": sess_id
        })
        self.assertEqual(post_resp.status_code, 200)

        # 2. Retrieve history
        get_resp = self.client.get(f"/api/assistant/history?session_id={sess_id}")
        self.assertEqual(get_resp.status_code, 200)
        hist_data = get_resp.json()
        self.assertGreaterEqual(hist_data["total_messages"], 2)
        self.assertEqual(hist_data["messages"][0]["role"], "user")
        self.assertEqual(hist_data["messages"][1]["role"], "assistant")

        # 3. Clear history
        del_resp = self.client.delete(f"/api/assistant/history?session_id={sess_id}")
        self.assertEqual(del_resp.status_code, 200)
        self.assertGreaterEqual(del_resp.json()["cleared_count"], 2)

        # 4. Verify empty
        get_empty = self.client.get(f"/api/assistant/history?session_id={sess_id}")
        self.assertEqual(get_empty.json()["total_messages"], 0)

    def test_ai_custom_budget_optimization_and_action_link(self):
        """Verifies AI solves Knapsack dynamically for custom budget and provides action button."""
        res = self.agent.answer_query("How should we allocate a 1.5 crore budget?")
        md = res["response_markdown"]
        self.assertIn("Optimal", md)
        self.assertIn("Portfolio ROSI", md)
        self.assertIn("action:set_budget:", md)
        self.assertIn("action:tab:optimizer", md)

    def test_ai_risk_trajectory_and_drift_forecast(self):
        """Verifies AI calculates 30/60/90-day risk drift and velocity."""
        res = self.agent.answer_query("What is our 90-day risk trajectory forecast if we do nothing?")
        md = res["response_markdown"]
        self.assertIn("Unmitigated Risk Trajectory", md)
        self.assertIn("30-Day Projected Exposure", md)
        self.assertIn("90-Day Projected Exposure", md)
        self.assertIn("monthly drift", md)
        self.assertIn("action:tab:scenarios", md)

    def test_ai_dpdp_statutory_penalties(self):
        """Verifies AI details DPDP Act 2023 Section 33 statutory liabilities and crown jewel PII."""
        res = self.agent.answer_query("What is our statutory penalty exposure under DPDP Act 2023?")
        md = res["response_markdown"]
        self.assertIn("DPDP Act 2023", md)
        self.assertIn("250 Crore", md)
        self.assertIn("reasonable security safeguards", md)
        self.assertIn("action:tab:compliance", md)

    def test_ai_scenario_and_dataset_actions(self):
        """Verifies AI generates 1-click execution actions for scenarios and datasets."""
        # Scenario run request
        scen_res = self.agent.answer_query("Run ransomware scenario on core switch")
        self.assertIn("action:run_scenario:SCEN-RANSOM-CORE", scen_res["response_markdown"])

        # Dataset load request
        data_res = self.agent.answer_query("Switch to healthcare dataset")
        self.assertIn("action:load_dataset:healthcare", data_res["response_markdown"])
        self.assertIn("Healthcare", data_res["response_markdown"])

        # Currency request
        curr_res = self.agent.answer_query("Switch to USD display")
        self.assertIn("action:set_currency:USD", curr_res["response_markdown"])

    def test_ai_user_preferences_extraction_and_endpoint(self):
        """Verifies extraction and REST retrieval of self-declared personas and constraints."""
        sess_id = "test_pref_sess_101"
        query_text = "I am the CISO and our budget limit is 80 lakhs with focus on DPDP Act 2023"

        post_resp = self.client.post("/api/assistant/query", json={
            "query": query_text,
            "session_id": sess_id,
            "active_tab": "optimizer"
        })
        self.assertEqual(post_resp.status_code, 200)

        # Query preferences endpoint
        pref_resp = self.client.get(f"/api/assistant/preferences?session_id={sess_id}")
        self.assertEqual(pref_resp.status_code, 200)
        prefs = pref_resp.json()["preferences"]
        self.assertEqual(prefs.get("user_role"), "CISO")
        self.assertEqual(prefs.get("compliance_focus"), "DPDP Act 2023")
        self.assertIn("80", prefs.get("budget_preference", ""))

    def test_ai_risk_identification_customer_database(self):
        """
        Verifies Feature 1: AI Risk Identification for publicly exposed database scenario:
        Identifies potential risks, root causes, affected assets, and consequences.
        """
        query = "Our customer database is publicly accessible"
        res = self.agent.answer_query(query)
        md = res["response_markdown"]

        # 1. Header and classification
        self.assertIn("AI Cyber Risk Identification Report", md)
        self.assertIn("System Misconfiguration & Exposure", md)
        self.assertIn("CRITICAL", md)

        # 2. Identified risks
        self.assertIn("Massive Data Exposure", md)
        self.assertIn("Unauthorized System Ingress", md)
        self.assertIn("Statutory Regulatory Non-Compliance", md)

        # 3. Root causes
        self.assertIn("Permissive Security Group", md)
        self.assertIn("0.0.0.0/0", md)

        # 4. Affected assets
        self.assertIn("Customer Master PII", md)

        # 5. Consequences & Penalties
        self.assertIn("DPDP Act 2023", md)
        self.assertIn("250 Crore", md)
        self.assertIn("Operational Downtime", md)

        # 6. Actionable mitigations
        self.assertIn("INIT-MICRO-05", md)
        self.assertIn("action:set_budget:", md)

    def test_ai_risk_identification_cloud_migration_project(self):
        """Verifies AI Risk Identification for a cloud architecture/migration project."""
        query = "We are migrating our on-premises payment gateway and database to AWS EKS cluster"
        res = self.agent.answer_query(query)
        md = res["response_markdown"]

        self.assertIn("AI Cyber Risk Identification Report", md)
        self.assertIn("Cloud Architecture & Transformation Project", md)
        self.assertIn("Payment", md)
        self.assertIn("Zero-Trust", md)

    def test_ai_risk_identification_phishing_incident(self):
        """Verifies AI Risk Identification for an active spear-phishing credential incident."""
        query = "An employee clicked a spear-phishing link and entered domain credentials"
        res = self.agent.answer_query(query)
        md = res["response_markdown"]

        self.assertIn("AI Cyber Risk Identification Report", md)
        self.assertIn("Active Security Incident", md)
        self.assertIn("Unauthorized", md)
        self.assertIn("INIT-MFA-01", md)

    def test_ai_risk_identification_vendor_process(self):
        """Verifies AI Risk Identification for third-party file upload process exposure."""
        query = "Third-party vendors upload invoice CSV files directly into our production S3 bucket without scanning"
        res = self.agent.answer_query(query)
        md = res["response_markdown"]

        self.assertIn("AI Cyber Risk Identification Report", md)
        self.assertIn("Supply Chain", md)
        self.assertIn("Supply Chain Ingestion", md)

    def test_ai_risk_identification_rest_endpoint(self):
        """Verifies dedicated POST /api/assistant/identify-risk endpoint."""
        resp = self.client.post("/api/assistant/identify-risk", json={
            "description": "Our customer database is publicly accessible",
            "session_id": "test_risk_id_sess_555"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["scenario_type"], "System Misconfiguration & Exposure")
        self.assertEqual(data["overall_risk_severity"], "CRITICAL")
        self.assertGreaterEqual(len(data["identified_risks"]), 3)
        self.assertGreaterEqual(len(data["root_causes"]), 2)
        self.assertGreaterEqual(len(data["consequences"]), 2)
        self.assertGreaterEqual(len(data["statutory_penalties"]), 2)
        self.assertGreaterEqual(len(data["recommended_mitigations"]), 2)
        self.assertIn("250 Crore", data["markdown_report"])

    def test_ai_risk_scoring_and_classification_inherent_vs_residual(self):
        """
        Verifies Feature 2: Risk Scoring & Classification:
        - Assesses each risk using Likelihood (1-5) and Impact (1-5)
        - Classifies risks as Critical, High, Medium, or Low
        - Calculates inherent risk (before controls) and residual risk (after controls)
        - Renders position on a 5x5 Risk Matrix with matrix shift and reduction score
        """
        id_res = self.agent.risk_identifier.identify_risks("Our customer database is publicly accessible")

        # 1. Overall Scoring verification
        self.assertIsNotNone(id_res.overall_scoring)
        ov = id_res.overall_scoring

        # Inherent: L=5, I=5, Score=25, Critical
        self.assertEqual(ov.inherent_risk.likelihood, 5)
        self.assertEqual(ov.inherent_risk.impact, 5)
        self.assertEqual(ov.inherent_risk.score, 25)
        self.assertEqual(ov.inherent_risk.classification, "Critical")
        self.assertEqual(ov.inherent_risk.matrix_coord, "L5:I5")

        # Residual: L<=2, I<=2, Score<=4, Low
        self.assertLessEqual(ov.residual_risk.likelihood, 2)
        self.assertLessEqual(ov.residual_risk.impact, 2)
        self.assertEqual(ov.residual_risk.score, 4)
        self.assertEqual(ov.residual_risk.classification, "Low")
        self.assertEqual(ov.residual_risk.matrix_coord, "L2:I2")

        # Risk reduction % (from 25 to 4 = 84% reduction)
        self.assertGreaterEqual(ov.risk_reduction_pct, 80.0)
        self.assertIn("L5:I5", ov.matrix_shift_summary)
        self.assertIn("L2:I2", ov.matrix_shift_summary)
        self.assertIn("Risk Appetite", ov.tolerance_status)

        # 2. Per-Risk Scoring & Classification verification
        for r in id_res.identified_risks:
            self.assertIsNotNone(r.inherent_risk)
            self.assertIsNotNone(r.residual_risk)
            self.assertIsNotNone(r.risk_reduction_pct)

            # Likelihood and Impact bounded in [1, 5]
            self.assertIn(r.inherent_risk.likelihood, [1, 2, 3, 4, 5])
            self.assertIn(r.inherent_risk.impact, [1, 2, 3, 4, 5])
            self.assertIn(r.residual_risk.likelihood, [1, 2, 3, 4, 5])
            self.assertIn(r.residual_risk.impact, [1, 2, 3, 4, 5])

            # Inherent score >= Residual score
            self.assertGreater(r.inherent_risk.score, r.residual_risk.score)
            self.assertGreater(r.risk_reduction_pct, 50.0)
            self.assertIn(r.inherent_risk.classification, ["Critical", "High", "Medium", "Low"])
            self.assertIn(r.residual_risk.classification, ["Critical", "High", "Medium", "Low"])

        # 3. 5x5 Matrix Rendering in Markdown Report
        md = id_res.markdown_report
        self.assertIn("Enterprise 5x5 Risk Matrix & Control Shift", md)
        self.assertIn("Risk Scoring & Classification (Before & After Controls)", md)
        self.assertIn("[⚠️ INHERENT]", md)
        self.assertIn("[🛡️ RESIDUAL]", md)
        self.assertIn("Likelihood \\ Impact", md)
        self.assertIn("5 - Almost Certain", md)
        self.assertIn("1 - Rare", md)

        # 4. ASCII Matrix view
        self.assertIsNotNone(id_res.matrix_view)
        self.assertIn("Likelihood (1-5)", id_res.matrix_view)
        self.assertIn("Impact (1-5)", id_res.matrix_view)
        self.assertIn("[INH:25]⚠️", id_res.matrix_view)
        self.assertIn("[RES:4]🛡️", id_res.matrix_view)

    def test_ai_risk_scoring_matrix_classification_thresholds(self):
        """Verifies exact 5x5 mathematical scoring thresholds and classification tiers."""
        engine = self.agent.risk_identifier

        # Critical: >= 20
        c1 = engine.compute_risk_score(5, 5)
        self.assertEqual(c1.score, 25)
        self.assertEqual(c1.classification, "Critical")
        self.assertIn("🔴", c1.badge)

        c2 = engine.compute_risk_score(4, 5)
        self.assertEqual(c2.score, 20)
        self.assertEqual(c2.classification, "Critical")

        # High: 12 to 19
        h1 = engine.compute_risk_score(4, 4)
        self.assertEqual(h1.score, 16)
        self.assertEqual(h1.classification, "High")
        self.assertIn("🟠", h1.badge)

        h2 = engine.compute_risk_score(3, 4)
        self.assertEqual(h2.score, 12)
        self.assertEqual(h2.classification, "High")

        # Medium: 6 to 11
        m1 = engine.compute_risk_score(3, 3)
        self.assertEqual(m1.score, 9)
        self.assertEqual(m1.classification, "Medium")
        self.assertIn("🟡", m1.badge)

        m2 = engine.compute_risk_score(2, 3)
        self.assertEqual(m2.score, 6)
        self.assertEqual(m2.classification, "Medium")

        # Low: 1 to 5
        l1 = engine.compute_risk_score(1, 5)
        self.assertEqual(l1.score, 5)
        self.assertEqual(l1.classification, "Low")
        self.assertIn("🟢", l1.badge)

        l2 = engine.compute_risk_score(2, 2)
        self.assertEqual(l2.score, 4)
        self.assertEqual(l2.classification, "Low")

        l3 = engine.compute_risk_score(1, 1)
        self.assertEqual(l3.score, 1)
        self.assertEqual(l3.classification, "Low")

    def test_ai_risk_scoring_query_natural_language(self):
        """Verifies natural language query specifically asking for risk scoring and 5x5 matrix."""
        query = "Assess each risk using likelihood and impact, show its position on a risk matrix, and include inherent risk and residual risk"
        res = self.agent.answer_query(query)
        md = res["response_markdown"]

        self.assertIn("Enterprise 5x5 Risk Matrix & Control Shift", md)
        self.assertIn("Risk Scoring & Classification (Before & After Controls)", md)
        self.assertIn("[⚠️ INHERENT]", md)
        self.assertIn("[🛡️ RESIDUAL]", md)
        self.assertIn("L5:I5", md)
        self.assertIn("Critical", md)
        self.assertIn("Low", md)

    def test_ai_risk_scoring_rest_endpoint_payload(self):
        """Verifies that POST /api/assistant/identify-risk returns full scoring and matrix payload."""
        resp = self.client.post("/api/assistant/identify-risk", json={
            "description": "Our customer database is publicly accessible",
            "session_id": "test_risk_scoring_payload_888"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Overall scoring structure
        self.assertIn("overall_scoring", data)
        ov = data["overall_scoring"]
        self.assertEqual(ov["inherent_risk"]["score"], 25)
        self.assertEqual(ov["inherent_risk"]["classification"], "Critical")
        self.assertEqual(ov["residual_risk"]["score"], 4)
        self.assertEqual(ov["residual_risk"]["classification"], "Low")
        self.assertGreaterEqual(ov["risk_reduction_pct"], 80.0)

        # ASCII matrix and grid markdown
        self.assertIn("matrix_view", data)
        self.assertIn("Likelihood (1-5)", data["matrix_view"])
        self.assertIn("matrix_grid_markdown", data)
        self.assertIn("Likelihood \\ Impact", data["matrix_grid_markdown"])

        # Per-risk scoring
        first_risk = data["identified_risks"][0]
        self.assertIn("inherent_risk", first_risk)
        self.assertIn("residual_risk", first_risk)
        self.assertIn("risk_reduction_pct", first_risk)
        self.assertEqual(first_risk["inherent_risk"]["score"], 25)
        self.assertEqual(first_risk["residual_risk"]["score"], 2)

    def test_ai_mitigation_recommendations_ordered_by_priority(self):
        """
        Verifies Feature 3: AI Mitigation Recommendations:
        - Recommends practical controls for each risk
        - Controls are strictly ordered by priority (P0, P1, P2...)
        - Includes concrete implementation steps
        - Includes expected risk reduction (% and loss reduction INR)
        - Includes effort duration and effort tier
        - Includes responsible team and secondary teams
        """
        id_res = self.agent.risk_identifier.identify_risks("Our customer database is publicly accessible")

        mitigations = id_res.recommended_mitigations
        self.assertGreaterEqual(len(mitigations), 4)

        # 1. Strictly ordered by priority
        priorities = [m.priority for m in mitigations]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual(mitigations[0].priority, 1)
        self.assertIn("P0", mitigations[0].priority_label)

        # 2. Check required attributes on every mitigation
        for m in mitigations:
            self.assertIsNotNone(m.initiative_id)
            self.assertIsNotNone(m.title)
            self.assertIsNotNone(m.target_risk)
            self.assertGreater(m.expected_risk_reduction_pct, 50.0)
            self.assertGreater(m.expected_loss_reduction_inr, 0)
            self.assertIsNotNone(m.effort)
            self.assertIn(m.effort_level, ["Low", "Medium", "High"])
            self.assertIsNotNone(m.responsible_team)
            self.assertGreaterEqual(len(m.implementation_steps), 3)
            self.assertIsNotNone(m.verification_metric)

        # Priority 1: Zero-Trust Microsegmentation
        m1 = mitigations[0]
        self.assertEqual(m1.initiative_id, "INIT-MICRO-05")
        self.assertIn("Zero-Trust", m1.title)
        self.assertIn("Massive Data Exposure", m1.target_risk)
        self.assertEqual(m1.expected_risk_reduction_pct, 82.0)
        self.assertIn("Cloud Infrastructure & Network SecOps", m1.responsible_team)
        self.assertEqual(m1.effort_level, "Low")
        self.assertIn("Immediate Ingress Containment", m1.implementation_steps[0])
        self.assertIn("External Ingress Validation", m1.implementation_steps[-1])

        # Priority 2: Universal FIDO2 MFA
        m2 = mitigations[1]
        self.assertEqual(m2.initiative_id, "INIT-MFA-01")
        self.assertIn("FIDO2", m2.title)
        self.assertEqual(m2.expected_risk_reduction_pct, 74.0)
        self.assertIn("Identity & Access Management", m2.responsible_team)
        self.assertEqual(m2.effort_level, "Medium")

        # 3. Check each identified risk has associated recommended controls
        for r in id_res.identified_risks:
            self.assertIsNotNone(r.recommended_mitigations)
            self.assertGreaterEqual(len(r.recommended_mitigations), 1)

        # 4. Check Markdown Report formatting
        md = id_res.markdown_report
        self.assertIn("Recommended Practical Control", md)
        self.assertIn("Priority", md)
        self.assertIn("Responsible Team", md)
        self.assertIn("Actionable Implementation Steps", md)
        self.assertIn("Verification Metric", md)
        self.assertIn("Cloud Infrastructure & Network SecOps", md)
        self.assertIn("Identity & Access Management (IAM)", md)

    def test_ai_mitigation_recommendations_scenario_adaptation(self):
        """Verifies controls are dynamically re-prioritized based on scenario context."""
        engine = self.agent.risk_identifier

        # Vendor upload scenario prioritizes Vendor Ingestion Gateway (INIT-VENDOR-02)
        vendor_res = engine.identify_risks("Third-party vendors upload invoice CSV files directly into production S3")
        top_vendor_m = vendor_res.recommended_mitigations[0]
        self.assertEqual(top_vendor_m.initiative_id, "INIT-VENDOR-02")
        self.assertEqual(top_vendor_m.priority, 1)
        self.assertIn("Application Security & Cloud Architecture", top_vendor_m.responsible_team)

        # Cloud migration scenario prioritizes IaC Security Gate (INIT-IAC-01)
        cloud_res = engine.identify_risks("We are migrating payment systems to AWS EKS kubernetes cluster")
        top_cloud_m = cloud_res.recommended_mitigations[0]
        self.assertEqual(top_cloud_m.initiative_id, "INIT-IAC-01")
        self.assertEqual(top_cloud_m.priority, 1)
        self.assertIn("DevSecOps & Platform Engineering", top_cloud_m.responsible_team)

    def test_ai_mitigation_query_natural_language(self):
        """Verifies natural language query asking for practical controls, steps, effort, and teams."""
        query = "Recommend practical controls for each risk, ordered by priority. Include implementation steps, expected risk reduction, effort, and responsible team"
        res = self.agent.answer_query(query)
        md = res["response_markdown"]

        self.assertIn("Recommended Practical Control", md)
        self.assertIn("Implementation Effort", md)
        self.assertIn("Responsible Team", md)
        self.assertIn("Actionable Implementation Steps", md)
        self.assertIn("Expected Risk Reduction", md)
        self.assertIn("Zero-Trust", md)
        self.assertIn("Cloud Infrastructure & Network SecOps", md)

    def test_ai_mitigation_recommendations_rest_endpoint(self):
        """Verifies POST /api/assistant/identify-risk returns full mitigation recommendations schema."""
        resp = self.client.post("/api/assistant/identify-risk", json={
            "description": "Our customer database is publicly accessible",
            "session_id": "test_mitigation_endpoint_777"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("recommended_mitigations", data)
        mitigs = data["recommended_mitigations"]
        self.assertGreaterEqual(len(mitigs), 4)

        # First mitigation verification
        m1 = mitigs[0]
        self.assertEqual(m1["priority"], 1)
        self.assertEqual(m1["initiative_id"], "INIT-MICRO-05")
        self.assertGreaterEqual(len(m1["implementation_steps"]), 3)
        self.assertEqual(m1["expected_risk_reduction_pct"], 82.0)
        self.assertIn("SecOps", m1["responsible_team"])
        self.assertIn("effort", m1)
        self.assertEqual(m1["effort_level"], "Low")

    # =========================================================================
    # FEATURE 4: RISKLENS AI CHAT ASSISTANT (TOP 5 RISKS & CAUSAL WHY HIGH)
    # =========================================================================

    def test_ai_chat_assistant_five_most_critical_risks(self):
        """Verifies natural language query: 'What are our five most critical risks?' returns Top 5 ranked risks."""
        res = self.agent.answer_query("What are our five most critical risks?")
        self.assertEqual(res["data"]["topic"], "top_5_critical_risks")
        self.assertEqual(len(res["data"]["top_assets"]), 5)
        self.assertGreater(res["data"]["total_top5_eal_inr"], 0)
        self.assertGreater(res["data"]["pct_of_enterprise_risk"], 0)

        md = res["response_markdown"]
        self.assertIn("RiskLens Enterprise Risk Register: Top 5 Most Critical Risks", md)
        self.assertIn("Executive Risk Register Comparison Table", md)
        self.assertIn("Criticality Tier", md)
        self.assertIn("Top Weaponized CVE", md)
        self.assertIn("Hourly Downtime", md)
        self.assertIn("Expected Annual Loss (EAL)", md)
        self.assertIn("Recommended Control", md)
        self.assertIn("DPDP Act 2023", md)
        self.assertIn("action:tab:assets", md)
        self.assertIn("action:tab:optimizer", md)
        self.assertIn("action:tab:scenarios", md)
        self.assertIn("Why is this risk rated high?", res["suggested_next_questions"])

    def test_ai_chat_assistant_why_is_this_risk_rated_high(self):
        """Verifies natural language query: 'Why is this risk rated high?' returns 4-pillar causal analysis."""
        res = self.agent.answer_query("Why is this risk rated high?")
        self.assertEqual(res["data"]["topic"], "risk_rating_causal_analysis")
        self.assertEqual(res["data"]["rating"], "Critical / High")
        self.assertEqual(len(res["data"]["four_pillars"]), 4)
        self.assertIn("INIT-MFA-01", res["data"]["remediation_initiatives"])

        md = res["response_markdown"]
        self.assertIn("Risk Rating Causal Analysis", md)
        self.assertIn("Four-Pillar Causal Breakdown: Why is this Risk Rated High?", md)
        self.assertIn("Pillar 1: Loss Magnitude & Financial Blast Radius", md)
        self.assertIn("Pillar 2: Active Weaponized Threat Exploitability & Threat Event Frequency", md)
        self.assertIn("Pillar 3: Control Telemetry Deficiencies & Low Resistance Strength", md)
        self.assertIn("Pillar 4: Open FAIR™ Mathematical Formulation & Matrix Placement", md)
        self.assertIn("DPDP Act 2023", md)
        self.assertIn("EPSS", md)
        self.assertIn("CTRL-IAM-MFA", md)
        self.assertIn("CTRL-NET-SEG", md)
        self.assertIn("CTRL-VM-SLA", md)
        self.assertIn("Actionable Path to Downgrade Risk to Low / Medium", md)
        self.assertIn("Residual Score", md)

    def test_ai_chat_assistant_multi_turn_anaphora_why_rated_high(self):
        """Verifies multi-turn memory where Turn 2 resolves 'this risk' to the #1 asset from Turn 1."""
        t1_res = self.agent.answer_query("What are our five most critical risks?")
        top_asset_t1 = t1_res["data"]["top_assets"][0]

        history = [
            {"role": "user", "content": "What are our five most critical risks?"},
            {"role": "assistant", "content": t1_res["response_markdown"]}
        ]

        t2_res = self.agent.answer_query("Why is this risk rated high?", history=history)
        self.assertEqual(t2_res["data"]["topic"], "risk_rating_causal_analysis")
        self.assertEqual(t2_res["data"]["asset_id"], top_asset_t1["id"])
        self.assertEqual(t2_res["data"]["asset_name"], top_asset_t1["name"])

        md = t2_res["response_markdown"]
        self.assertIn(top_asset_t1["name"], md)
        self.assertIn("preceding conversation context", md)
        self.assertIn("Four-Pillar Causal Breakdown", md)

    def test_ai_chat_assistant_explicit_named_asset_why_rated_high(self):
        """Verifies explicit asset name resolution in 'Why is Core Banking rated high?'."""
        res = self.agent.answer_query("Why is Core Banking rated high?")
        self.assertEqual(res["data"]["topic"], "risk_rating_causal_analysis")
        self.assertEqual(res["data"]["asset_id"], "AST-001")
        self.assertIn("Core Banking", res["data"]["asset_name"])

        md = res["response_markdown"]
        self.assertIn("Core Banking Transaction Switch", md)
        self.assertIn("CVE-2023-4966", md)
        self.assertIn("Four-Pillar Causal Breakdown", md)

    def test_ai_chat_assistant_rest_endpoint_top_risks_and_why_high(self):
        """Verifies REST API POST /api/assistant/query handles both feature queries with persistent memory."""
        # Query 1: Top 5 critical risks
        resp1 = self.client.post("/api/assistant/query", json={
            "query": "What are our five most critical risks?",
            "session_id": "test_session_chat_assistant_99"
        })
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertEqual(data1["data"]["topic"], "top_5_critical_risks")
        self.assertEqual(len(data1["data"]["top_assets"]), 5)
        self.assertTrue(data1["memory_active"])

        # Query 2: Why is this risk rated high? (relies on session memory)
        resp2 = self.client.post("/api/assistant/query", json={
            "query": "Why is this risk rated high?",
            "session_id": "test_session_chat_assistant_99"
        })
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertEqual(data2["data"]["topic"], "risk_rating_causal_analysis")
        self.assertIn("four_pillars", data2["data"])
        self.assertEqual(len(data2["data"]["four_pillars"]), 4)

    @patch("httpx.Client.post")
    def test_gemini_api_payload_retains_system_instruction_on_multi_turn(self, mock_post):
        """Verifies LLM-01: Gemini API payload includes system_instruction even when multi-turn history is provided."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [{
                "content": {
                    "parts": [{"text": "Synthetic Gemini test response."}]
                }
            }]
        }
        mock_post.return_value = mock_response

        history = [
            {"role": "user", "content": "What is our EAL?"},
            {"role": "assistant", "content": "Your EAL is ₹3.5 Crore."}
        ]
        res = self.agent._call_gemini_api(
            query="How can we reduce it?",
            api_key="fake-key-for-test",
            history=history
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["response_markdown"], "Synthetic Gemini test response.")

        # Inspect payload sent to Gemini
        args, kwargs = mock_post.call_args
        payload = kwargs.get("json", {})
        self.assertIn("system_instruction", payload)
        sys_text = payload["system_instruction"]["parts"][0]["text"]
        self.assertIn("RiskLens AI Cyber Risk Intelligence Copilot", sys_text)
        self.assertIn("Live enterprise metrics", sys_text)

        # Inspect multi-turn contents
        contents = payload.get("contents", [])
        self.assertEqual(len(contents), 3)  # turn1 user, turn1 assistant (model), turn2 query
        self.assertEqual(contents[0]["role"], "user")
        self.assertEqual(contents[1]["role"], "model")
        self.assertEqual(contents[2]["role"], "user")
        self.assertEqual(contents[2]["parts"][0]["text"], "How can we reduce it?")


if __name__ == "__main__":
    unittest.main()
