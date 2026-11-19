"""
Comprehensive Test Suite for AI Risk Reports Engine (Feature 5).
Verifies:
1. Executive Summary Report generation (Board & C-Suite risk exposure, EAL, VaR, CVaR).
2. Risk Assessment Report generation (FAIR decomposition, crown jewels, 5x5 matrix).
3. Mitigation Plan Report generation (0-1 Knapsack capital allocation, P0/P1/P2 priorities, steps, teams, ROSI).
4. Department-Wise Risk Summaries generation (5 business units, risk shares, crown jewels, accountability).
5. Master Comprehensive Dossier generation.
6. Rigorous verification of Evidence and Assumptions behind every report.
7. REST API endpoint POST /api/assistant/reports.
8. Natural language report query routing in ProjectKnowledgeAgent.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.schemas import RiskReportRequest, RiskReportResult
from backend.engine.ai_reports import AiRiskReportEngine
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer
from backend.ingestion.telemetry_loader import TelemetryService


class TestAiRiskReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.risk_engine = FairRiskEngine(iterations=1000)
        cls.optimizer = InvestmentOptimizer(risk_engine=cls.risk_engine)
        cls.telemetry = TelemetryService.get_instance()
        cls.report_engine = AiRiskReportEngine(
            telemetry_service=cls.telemetry,
            risk_engine=cls.risk_engine,
            optimizer=cls.optimizer
        )
        cls.agent = ProjectKnowledgeAgent(
            risk_engine=cls.risk_engine,
            optimizer=cls.optimizer,
            telemetry_service=cls.telemetry,
            report_engine=cls.report_engine
        )

    def test_executive_summary_report_generation(self):
        """Verifies Executive Summary Report contains boardroom KPIs, primary vs secondary loss, and evidence/assumptions."""
        report = self.report_engine.generate_executive_summary_report()
        self.assertEqual(report.report_type, "executive_summary")
        self.assertIn("Executive Cyber Risk & Financial Loss Quantification Report", report.title)
        self.assertGreater(report.metrics["expected_annual_loss_inr"], 0)
        self.assertGreater(report.metrics["enterprise_risk_score"], 0)
        self.assertGreaterEqual(report.evidence.total_assets_monitored, 10)
        self.assertIn("Open FAIR", report.assumptions.simulation_engine)

        md = report.markdown_report
        self.assertIn("Executive Cyber Risk & Financial Loss Quantification Report", md)
        self.assertIn("Enterprise Risk Scorecard & Balance-Sheet Exposure", md)
        self.assertIn("Expected Annual Loss (EAL)", md)
        self.assertIn("95% Value at Risk (VaR)", md)
        self.assertIn("Primary vs. Secondary Blast Radius", md)
        self.assertIn("DPDP Act 2023", md)
        self.assertIn("Top 3 Financial Risk Drivers", md)
        self.assertIn("Quantitative Evidence Base Behind Analysis", md)
        self.assertIn("Methodological Modeling Assumptions", md)

    def test_risk_assessment_report_generation(self):
        """Verifies Risk Assessment Report includes technical threat modeling, 5x5 matrix, and FAIR ontology."""
        report = self.report_engine.generate_risk_assessment_report()
        self.assertEqual(report.report_type, "risk_assessment")
        self.assertIn("Enterprise Cyber Risk Assessment & Threat Modeling Dossier", report.title)
        self.assertGreater(len(report.evidence.crown_jewel_assets), 0)

        md = report.markdown_report
        self.assertIn("Enterprise Cyber Risk Assessment & Threat Modeling Dossier", md)
        self.assertIn("Crown Jewel Asset Assessment & Threat Exposure Matrix", md)
        self.assertIn("5x5 Risk Matrix & Inherent vs. Residual Evaluation", md)
        self.assertIn("INHERENT RISK", md)
        self.assertIn("RESIDUAL RISK", md)
        self.assertIn("Open FAIR™ Factor Analysis & Risk Decomposition", md)
        self.assertIn("Loss Event Frequency (LEF)", md)
        self.assertIn("Loss Magnitude (LM)", md)
        self.assertIn("Quantitative Evidence Base Behind Analysis", md)
        self.assertIn("Methodological Modeling Assumptions", md)

    def test_mitigation_plan_report_generation(self):
        """Verifies Mitigation Plan Report provides 0-1 Knapsack capital allocation, P0/P1/P2 priorities, steps, and teams."""
        report = self.report_engine.generate_mitigation_plan_report(custom_budget_inr=18000000.0)
        self.assertEqual(report.report_type, "mitigation_plan")
        self.assertIn("Strategic Cyber Risk Mitigation Plan", report.title)
        self.assertIsNotNone(report.recommended_mitigations)
        self.assertGreaterEqual(len(report.recommended_mitigations), 4)

        # Check first recommendation has required fields
        m1 = report.recommended_mitigations[0]
        self.assertIn("P0", m1.priority_label)
        self.assertGreaterEqual(len(m1.implementation_steps), 3)
        self.assertIsNotNone(m1.responsible_team)
        self.assertGreater(m1.expected_risk_reduction_pct, 50.0)
        self.assertGreater(m1.rosi_pct, 100.0)

        md = report.markdown_report
        self.assertIn("Strategic Cyber Risk Mitigation Plan & Capital Allocation Blueprint", md)
        self.assertIn("Capital Allocation & ROSI Executive Summary", md)
        self.assertIn("Prioritized Security Mitigation Initiatives Table", md)
        self.assertIn("Actionable Implementation Guides per Initiative", md)
        self.assertIn("Efficient Frontier & Diminishing Returns Analysis", md)
        self.assertIn("Quantitative Evidence Base Behind Analysis", md)
        self.assertIn("Methodological Modeling Assumptions", md)

    def test_department_summary_report_generation(self):
        """Verifies Department-Wise Risk Summary details the 5 operational departments, risk shares, and crown jewels."""
        report = self.report_engine.generate_department_summary_report()
        self.assertEqual(report.report_type, "department_summary")
        self.assertIn("Department-Wise Cyber Risk & Business Unit Exposure Summary", report.title)
        self.assertIsNotNone(report.department_summaries)
        self.assertEqual(len(report.department_summaries), 5)

        # Ensure top 2 departments represent highest loss
        d1 = report.department_summaries[0]
        d2 = report.department_summaries[1]
        self.assertGreater(d1.risk_share_pct + d2.risk_share_pct, 70.0)
        self.assertIn("Retail Banking", d1.department_name)
        self.assertIsNotNone(d1.critical_asset_name)
        self.assertIsNotNone(d1.responsible_team)

        md = report.markdown_report
        self.assertIn("Department-Wise Cyber Risk & Business Unit Exposure Summary", md)
        self.assertIn("Cross-Department Comparative Risk Matrix Table", md)
        self.assertIn("Retail Banking, Core Switch & Payments", md)
        self.assertIn("Cloud Platforms & Core Infrastructure", md)
        self.assertIn("Corporate Treasury & Interbank SWIFT Network", md)
        self.assertIn("Departmental Governance & Remediation SLA Matrix", md)
        self.assertIn("Quantitative Evidence Base Behind Analysis", md)
        self.assertIn("Methodological Modeling Assumptions", md)

    def test_comprehensive_report_generation(self):
        """Verifies Master Dossier combines Executive Summary, Assessment, Mitigation Plan, and Department Summaries."""
        report = self.report_engine.generate_comprehensive_report()
        self.assertEqual(report.report_type, "comprehensive")
        self.assertIn("Master Enterprise Cyber Risk", report.title)
        self.assertIsNotNone(report.department_summaries)
        self.assertIsNotNone(report.recommended_mitigations)

        md = report.markdown_report
        self.assertIn("TABLE OF CONTENTS", md)
        self.assertIn("Executive Summary & Board Scorecard", md)
        self.assertIn("Enterprise Cyber Risk Assessment & Threat Modeling", md)
        self.assertIn("Strategic Mitigation Plan & Capital Allocation Blueprint", md)
        self.assertIn("Department-Wise Risk & Business Unit Exposure Summary", md)
        self.assertIn("Quantitative Evidence Base Behind Analysis", md)
        self.assertIn("Methodological Modeling Assumptions", md)

    def test_evidence_and_assumptions_integrity(self):
        """Verifies the evidence base and methodological assumptions are rigorously populated."""
        evidence, assumptions, metrics = self.report_engine._gather_evidence_and_assumptions()

        # Evidence checks
        self.assertGreaterEqual(evidence.total_assets_monitored, 10)
        self.assertGreaterEqual(evidence.total_cves_analyzed, 5)
        self.assertGreater(evidence.hourly_downtime_exposure_inr, 5000000.0)
        self.assertGreater(evidence.customer_pii_records_exposed, 10000000)
        self.assertIn("MFA_Enforcement", evidence.control_hygiene_scores)
        self.assertIn("Network_Microsegmentation", evidence.control_hygiene_scores)
        self.assertIn("Vulnerability_Patch_SLA", evidence.control_hygiene_scores)
        self.assertGreaterEqual(len(evidence.statutory_citations), 3)

        # Assumptions checks
        self.assertIn("Open FAIR", assumptions.simulation_engine)
        self.assertIn("10,000 Monte Carlo", assumptions.simulation_engine)
        self.assertIn("Beta-PERT", assumptions.loss_distributions)
        self.assertEqual(assumptions.currency_exchange_rate, 84.0)
        self.assertEqual(assumptions.risk_tolerance_threshold_inr, 500000000.0)
        self.assertIn("Knapsack", assumptions.budget_optimization_algorithm)

    def test_ai_reports_rest_api_endpoint(self):
        """Verifies REST API POST /api/assistant/reports handles all 4 report requests successfully."""
        report_types = ["executive_summary", "risk_assessment", "mitigation_plan", "department_summary", "comprehensive"]

        for rtype in report_types:
            resp = self.client.post("/api/assistant/reports", json={
                "report_type": rtype,
                "session_id": f"test_api_session_{rtype}"
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["report_type"], rtype)
            self.assertIn("evidence", data)
            self.assertIn("assumptions", data)
            self.assertIn("metrics", data)
            self.assertIn("markdown_report", data)
            self.assertIn("Quantitative Evidence Base Behind Analysis", data["markdown_report"])
            self.assertIn("Methodological Modeling Assumptions", data["markdown_report"])

    def test_natural_language_report_generation_queries(self):
        """Verifies that natural language questions to ProjectKnowledgeAgent trigger the proper report types."""
        test_cases = [
            ("Generate an executive summary risk report", "executive_summary"),
            ("Generate a risk assessment report", "risk_assessment"),
            ("Generate an AI mitigation plan report", "mitigation_plan"),
            ("Generate department-wise risk summaries", "department_summary"),
            ("What are the evidence and assumptions behind our risk analysis?", "executive_summary"),
        ]

        for query, expected_type in test_cases:
            res = self.agent.answer_query(query)
            self.assertEqual(res["data"]["topic"], "ai_risk_report")
            self.assertEqual(res["data"]["report_type"], expected_type)
            self.assertIn("evidence", res["data"])
            self.assertIn("assumptions", res["data"])

            md = res["response_markdown"]
            self.assertIn("Quantitative Evidence Base Behind Analysis", md)
            self.assertIn("Methodological Modeling Assumptions", md)


if __name__ == "__main__":
    unittest.main()
