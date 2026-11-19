"""
Unit and Integration Test Suite for RiskLens Platform.
Verifies Monte Carlo simulation, MILP Knapsack optimization, What-If scenarios,
Compliance framework crosswalk, and FastAPI REST endpoints.
"""

import unittest
import numpy as np
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.compliance import ComplianceFrameworkEngine
from backend.ingestion.telemetry_loader import TelemetryService


class TestFairRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FairRiskEngine(iterations=1500, seed=123)

    def test_simulation_convergence_and_metrics(self):
        res = self.engine.run_enterprise_simulation()
        self.assertGreater(res.expected_annual_loss_inr, 0)
        self.assertGreater(res.var_95_inr, 0)
        self.assertGreater(res.cvar_95_inr, 0)
        # In risk distributions with positive skew, VaR 95 and CVaR 95 exceed the mean (EAL)
        self.assertGreaterEqual(res.cvar_95_inr, res.var_95_inr)
        self.assertTrue(0 <= res.enterprise_risk_score <= 100)

    def test_loss_exceedance_curve_monotonicity(self):
        res = self.engine.run_enterprise_simulation()
        lec = res.loss_exceedance_curve
        self.assertGreater(len(lec), 0)
        # As exceedance probability decreases (e.g. from 90% down to 1%),
        # the required threshold loss amount should increase or stay flat
        # Verify: amounts sorted by probability descending are non-decreasing
        probs = [p.exceedance_probability for p in lec]
        amounts = [p.loss_amount_inr for p in lec]
        for i in range(len(amounts) - 1):
            if probs[i] > probs[i+1]:
                self.assertLessEqual(amounts[i], amounts[i+1])


class TestInvestmentOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = InvestmentOptimizer(risk_engine=FairRiskEngine(iterations=1000))

    def test_knapsack_budget_constraint(self):
        budget = 10000000.0  # ₹1.00 Crore
        res = self.optimizer.optimize_security_investment(budget_inr=budget)
        total_spent = sum(i.cost_inr for i in res.selected_initiatives)
        self.assertLessEqual(total_spent, budget)
        self.assertGreater(len(res.selected_initiatives), 0)
        self.assertGreater(res.portfolio_rosi_pct, 0)

    def test_efficient_frontier_generation(self):
        res = self.optimizer.optimize_security_investment(budget_inr=15000000.0)
        frontier = res.efficient_frontier
        self.assertGreater(len(frontier), 5)
        # As budget increases along the frontier, risk reduction should be non-decreasing
        reductions = [p["risk_reduction_inr"] for p in frontier]
        for i in range(len(reductions) - 1):
            self.assertLessEqual(reductions[i], reductions[i+1] + 1e-5)


class TestAiDecisionSupport(unittest.TestCase):
    def setUp(self):
        self.ai_service = AiDecisionSupportService(risk_engine=FairRiskEngine(iterations=1000))

    def test_mfa_scenario_reduces_risk(self):
        res = self.ai_service.simulate_scenario("SCEN-MFA-ALL")
        self.assertLess(res.delta_eal_inr, 0, "MFA scenario should reduce Expected Annual Loss")
        self.assertLess(res.delta_percentage, 0)
        self.assertIn("MFA", res.ai_executive_summary)

    def test_patch_delay_scenario_escalates_risk(self):
        res = self.ai_service.simulate_scenario("SCEN-PATCH-DELAY-30")
        self.assertGreater(res.delta_eal_inr, 0, "Remediation delay should escalate Expected Annual Loss")
        self.assertGreater(res.delta_percentage, 0)

    def test_natural_language_copilot(self):
        reply = self.ai_service.process_natural_language_query("What is our highest financial cyber risk today?")
        self.assertIn("response_markdown", reply)
        self.assertIn("Top Financial Cyber Risk", reply["response_markdown"])


class TestComplianceEngine(unittest.TestCase):
    def setUp(self):
        self.comp_engine = ComplianceFrameworkEngine()

    def test_framework_scoring(self):
        frameworks = self.comp_engine.get_all_framework_scores()
        self.assertEqual(len(frameworks), 5)
        ids = [f.framework_id for f in frameworks]
        self.assertIn("FW-RBI-CSF", ids)
        self.assertIn("FW-SEBI-CSCRF", ids)
        self.assertIn("FW-ISO-27001", ids)
        self.assertIn("FW-NIST-CSF", ids)
        self.assertIn("FW-CIS-V8", ids)

        for f in frameworks:
            self.assertTrue(0 <= f.overall_compliance_pct <= 100)

    def test_dynamic_board_compliance_report(self):
        report = self.comp_engine.generate_board_compliance_report()
        self.assertIn("report_title", report)
        self.assertIn("critical_audit_findings", report)
        self.assertIsInstance(report["critical_audit_findings"], list)
        self.assertTrue(len(report["critical_audit_findings"]) > 0)
        finding = report["critical_audit_findings"][0]
        self.assertIn("finding_id", finding)
        self.assertIn("framework_clause", finding)
        self.assertIn("severity", finding)
        self.assertIn("associated_monetary_risk", finding)
        self.assertIn("recommended_remediation", finding)


class TestApiRoutes(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_summary_endpoint(self):
        resp = self.client.get("/api/risk/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("expected_annual_loss_inr", data)
        self.assertIn("var_95_inr", data)

    def test_health_endpoints(self):
        resp_root = self.client.get("/health")
        self.assertEqual(resp_root.status_code, 200)
        self.assertEqual(resp_root.json()["status"], "healthy")

        resp_api = self.client.get("/api/health")
        self.assertEqual(resp_api.status_code, 200)
        self.assertEqual(resp_api.json()["status"], "healthy")

    def test_optimize_endpoint(self):
        resp = self.client.post("/api/optimize", json={"budget_inr": 10000000.0})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("selected_initiatives", data)
        self.assertIn("portfolio_rosi_pct", data)

    def test_optimize_endpoint_with_budget_usd(self):
        # Verify that providing budget_usd without budget_inr calculates budget in USD accurately
        resp = self.client.post("/api/optimize", json={"budget_usd": 30000.0})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["budget_usd"], 30000.0)
        self.assertEqual(data["budget_inr"], 30000.0 * 84.0)
        self.assertLessEqual(data["total_spent_inr"], data["budget_inr"])

    def test_targeted_resistance_boost(self):
        telemetry = TelemetryService.get_instance()
        # AST-005 (Active Directory) is not targeted by INIT-WAF-08 (which targets AST-002 and AST-007)
        untargeted_asset = telemetry.get_asset("AST-005")
        targeted_asset = telemetry.get_asset("AST-002")

        base_untargeted = telemetry.compute_asset_resistance(untargeted_asset)
        boosted_untargeted = telemetry.compute_asset_resistance(untargeted_asset, {"INIT-WAF-08": 0.24})
        self.assertAlmostEqual(base_untargeted, boosted_untargeted, places=4)

        base_targeted = telemetry.compute_asset_resistance(targeted_asset)
        boosted_targeted = telemetry.compute_asset_resistance(targeted_asset, {"INIT-WAF-08": 0.24})
        self.assertGreater(boosted_targeted, base_targeted)

    def test_assistant_query_endpoint(self):
        resp = self.client.post("/api/assistant/query", json={"query": "What is our highest risk?"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("response_markdown", data)

    def test_assistant_usd_budget_query(self):
        resp = self.client.post("/api/assistant/query", json={"query": "How should we allocate a $2.5 million budget?"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("response_markdown", data)
        self.assertIn("$2,500,000 USD", data["response_markdown"])

    def test_assistant_var_and_cvar_query(self):
        resp = self.client.post("/api/assistant/query", json={"query": "What is our 95% Value at Risk and CVaR?"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("response_markdown", data)
        self.assertIn("Value at Risk (VaR)", data["response_markdown"])
        self.assertIn("Conditional VaR", data["response_markdown"])

    def test_assistant_compliance_findings_query(self):
        resp = self.client.post("/api/assistant/query", json={"query": "What are our compliance audit findings?"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("response_markdown", data)
        self.assertIn("Compliance & Audit Governance", data["response_markdown"])


if __name__ == "__main__":
    unittest.main()
