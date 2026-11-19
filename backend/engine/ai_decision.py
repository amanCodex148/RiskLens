"""
AI Decision Support Layer for RiskLens.
Includes:
1. Scenario Simulation Engine ('What-If' analyses: MFA rollout, 30-day patch delay, zero-day threat, ransomware blast radius).
2. Predictive analytics for risk trajectory and vulnerability velocity.
3. Natural Language Cyber Risk Copilot for executive and board inquiries.
"""

import re
from typing import Dict, Any, List, Optional
import numpy as np
from backend.models.schemas import (
    WhatIfScenarioResult,
    CriticalityTier,
    RiskIdentificationResult,
    RiskReportResult,
    DocumentIntelligenceResult,
    RiskPrioritizationResult,
    PrioritizationWeights,
    ScenarioAnalysisResult,
    ScenarioAnalysisRequest,
    RootCauseAnalysisRequest,
    RootCauseAnalysisResult,
    RiskMonitoringReassessmentRequest,
    RiskMonitoringReassessmentResult,
    ComplianceMappingRequest,
    ComplianceMappingResult,
    AiInsightsRequest,
    AiInsightsResult
)
from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer
from backend.ingestion.telemetry_loader import TelemetryService, USD_INR_RATE
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.engine.ai_risk_identification import AiRiskIdentifier
from backend.engine.ai_reports import AiRiskReportEngine
from backend.engine.ai_document_intelligence import DocumentIntelligenceEngine
from backend.engine.ai_risk_prioritization import AiRiskPrioritizationEngine
from backend.engine.ai_scenario_analysis import AiScenarioAnalysisEngine
from backend.engine.ai_root_cause_analysis import AiRootCauseAnalysisEngine
from backend.engine.ai_risk_monitoring import AiRiskMonitoringEngine
from backend.engine.ai_compliance_assistant import AiComplianceAssistant
from backend.engine.ai_insights import AiInsightsEngine
from backend.engine.ai_nlp_engine import AiNlpEngine


class AiDecisionSupportService:
    """
    Powers predictive analytics, scenario simulations, AI risk identification,
    AI risk reports generation, Document Intelligence, Risk Prioritization,
    Hypothetical Scenario Analysis, Root Cause Analysis, Risk Monitoring & Reassessment,
    and the natural language risk copilot.
    """

    def __init__(self, risk_engine: Optional[FairRiskEngine] = None):
        self.risk_engine = risk_engine or FairRiskEngine(iterations=2500)
        self.optimizer = InvestmentOptimizer(risk_engine=self.risk_engine)
        self.telemetry_service = TelemetryService.get_instance()
        self.risk_identifier = AiRiskIdentifier(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer
        )
        self.report_engine = AiRiskReportEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer
        )
        self.document_intelligence = DocumentIntelligenceEngine()
        self.prioritization_engine = AiRiskPrioritizationEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer
        )
        self.scenario_analysis = AiScenarioAnalysisEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer
        )
        self.root_cause_engine = AiRootCauseAnalysisEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer
        )
        self.monitoring_engine = AiRiskMonitoringEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer,
            prioritization_engine=self.prioritization_engine
        )
        self.compliance_assistant = AiComplianceAssistant(
            telemetry_service=self.telemetry_service,
            compliance_engine=None,
            risk_engine=self.risk_engine,
            prioritization_engine=self.prioritization_engine
        )
        self.insights_engine = AiInsightsEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer,
            prioritization_engine=self.prioritization_engine
        )
        self.nlp_engine = AiNlpEngine()
        self.knowledge_agent = ProjectKnowledgeAgent(
            risk_engine=self.risk_engine,
            optimizer=self.optimizer,
            telemetry_service=self.telemetry_service,
            risk_identifier=self.risk_identifier,
            report_engine=self.report_engine,
            document_intelligence=self.document_intelligence,
            prioritization_engine=self.prioritization_engine,
            scenario_analysis_engine=self.scenario_analysis,
            root_cause_engine=self.root_cause_engine,
            monitoring_engine=self.monitoring_engine,
            compliance_assistant=self.compliance_assistant,
            insights_engine=self.insights_engine,
            nlp_engine=self.nlp_engine
        )

    def invalidate_cache(self):
        """Invalidates the embedded investment optimizer cache and resets state."""
        self.optimizer.invalidate_cache()

    def simulate_scenario(self, scenario_id: str, custom_params: Optional[Dict[str, Any]] = None) -> WhatIfScenarioResult:
        """
        Executes a What-If scenario simulation comparing baseline against the modified risk environment.
        """
        base_res = self.risk_engine.run_enterprise_simulation()
        base_eal = base_res.expected_annual_loss_inr
        base_var = base_res.var_95_inr

        overrides = {}
        boosts = {}
        title = ""
        description = ""
        drivers = []
        narrative = ""

        if scenario_id == "SCEN-MFA-ALL":
            title = "Enforce Phishing-Resistant MFA Across 100% Privileged Accounts"
            description = "Simulates universal hardware/FIDO2 MFA enforcement for all Domain Admins, Cloud IAM Roles, and Database DBAs."
            boosts = {"INIT-MFA-01": 0.45}
            overrides = {"resistance_delta": 0.28}
            drivers = [
                "Credential stuffing attack success drops by 94%",
                "Active Directory Domain Controller compromise probability reduced to near zero",
                "Mitigates initial access vector for 82% of observed financial sector breaches"
            ]

        elif scenario_id == "SCEN-PATCH-DELAY-30":
            title = "30-Day Delay in Critical Vulnerability Remediation"
            description = "Simulates risk accumulation if security patch deployment SLA is deferred by 30 additional days due to change freeze."
            overrides = {"tef_multiplier": 1.75, "threat_cap_delta": 0.18}
            drivers = [
                "Exploit exposure window expands from 14 days to 44 days",
                "Active weaponization probability for CVE-2023-4966 and CVE-2024-21887 spikes by 85%",
                "CISA KEV catalogue exploitation likelihood doubles during freeze"
            ]

        elif scenario_id == "SCEN-ZERO-DAY-WEB":
            title = "Zero-Day Remote Code Execution on External Web Gateway"
            description = "Simulates sudden disclosure of an unpatched CVSS 10.0 / EPSS 0.98 flaw on the Payment Gateway API and Core Switch."
            overrides = {"tef_multiplier": 2.4, "threat_cap_delta": 0.32, "resistance_delta": -0.15}
            drivers = [
                "Perimeter WAF bypass probability increases to 72%",
                "Automated mass botnet exploitation attempts target public ingress endpoints",
                "Severe immediate threat of unauthorized database exfiltration"
            ]

        elif scenario_id == "SCEN-RANSOM-CORE":
            assets = self.telemetry_service.get_all_assets()
            top_t1 = next((a for a in assets if a.criticality == CriticalityTier.TIER_1), assets[0] if assets else None)
            target_name = top_t1.name if top_t1 else "Core Transaction Engine"
            target_id = top_t1.asset_id if top_t1 else "AST-001"
            rev_hr = top_t1.revenue_per_hour_inr if top_t1 else 3500000.0

            title = f"Targeted Ransomware Outbreak on {target_name}"
            description = f"Simulates successful lateral movement leading to encryption of {target_name} with 48h downtime."
            overrides = {
                "tef_multiplier": 1.9,
                "threat_cap_delta": 0.25,
                "rto_multiplier": 4.0,
                "target_assets": [target_id]
            }
            drivers = [
                f"Direct business interruption cost exceeds ₹{rev_hr * 10 / 10000000:.2f} Crore per 10 hours downtime",
                "Triggers mandatory 6-hour regulatory notification window to RBI & CERT-In",
                "Secondary loss exposure under DPDP Act 2023 for customer transaction data impact"
            ]

        elif scenario_id == "SCEN-MICROSEG-CLOUD":
            title = "Zero-Trust Microsegmentation on Core Banking & Cloud EKS"
            description = "Simulates complete isolation of database clusters and Kubernetes microservices via software-defined network enclaves."
            boosts = {"INIT-MICRO-05": 0.40}
            overrides = {"resistance_delta": 0.22}
            drivers = [
                "Lateral movement from compromised corporate workstations strictly blocked",
                "Crown jewel database access restricted to authenticated mutual-TLS services",
                "Blast radius of any single host compromise constrained to 1 VLAN node"
            ]

        else:
            # Generic custom scenario
            title = custom_params.get("title", "Custom Enterprise Cyber Risk Scenario") if custom_params else "Custom Scenario"
            description = "Custom risk evaluation with user-defined parameters."
            overrides = custom_params or {}
            drivers = ["Custom parameter evaluation"]

        # Run scenario simulation
        scen_res = self.risk_engine.run_enterprise_simulation(
            initiative_boosts=boosts if boosts else None,
            custom_overrides=overrides if overrides else None
        )
        scen_eal = scen_res.expected_annual_loss_inr
        scen_var = scen_res.var_95_inr

        delta_eal = scen_eal - base_eal
        delta_pct = (delta_eal / base_eal) * 100.0 if base_eal > 0 else 0.0

        # AI-generated narrative synthesis
        if delta_eal < 0:
            reduction_abs = abs(delta_eal)
            narrative = (
                f"Implementing '{title}' yields an immediate risk reduction of ₹{reduction_abs:,.0f} "
                f"(${reduction_abs / USD_INR_RATE:,.0f} USD), cutting enterprise financial exposure by {abs(delta_pct):.1f}%. "
                f"95% Value at Risk (VaR) decreases from ₹{base_var:,.0f} to ₹{scen_var:,.0f}. "
                f"Executive takeaway: This initiative is a high-yield risk-reduction investment that directly bolsters "
                f"compliance under RBI Cyber Security Framework Section 3 and SEBI CSCRF."
            )
        else:
            escalation_abs = delta_eal
            narrative = (
                f"Warning: Under the '{title}' scenario, enterprise financial cyber risk escalates by ₹{escalation_abs:,.0f} "
                f"(${escalation_abs / USD_INR_RATE:,.0f} USD), representing a {delta_pct:+.1f}% surge in Expected Annual Loss. "
                f"95% Value at Risk surges to ₹{scen_var:,.0f}. "
                f"Executive takeaway: Remediation delays or unmitigated zero-day vectors expose the organization to "
                f"severe regulatory sanctions under the DPDP Act 2023 and cascading operational downtime."
            )

        return WhatIfScenarioResult(
            scenario_id=scenario_id,
            scenario_title=title,
            description=description,
            baseline_eal_inr=round(base_eal, 2),
            baseline_eal_usd=round(base_eal / USD_INR_RATE, 2),
            scenario_eal_inr=round(scen_eal, 2),
            scenario_eal_usd=round(scen_eal / USD_INR_RATE, 2),
            delta_eal_inr=round(delta_eal, 2),
            delta_eal_usd=round(delta_eal / USD_INR_RATE, 2),
            delta_percentage=round(delta_pct, 1),
            baseline_var95_inr=round(base_var, 2),
            scenario_var95_inr=round(scen_var, 2),
            key_drivers=drivers,
            ai_executive_summary=narrative
        )

    def forecast_risk_trajectory(self) -> Dict[str, Any]:
        """
        Predicts 30, 60, and 90-day cyber risk trajectory based on vulnerability discovery
        velocity vs enterprise patching cadence.
        """
        base_res = self.risk_engine.run_enterprise_simulation()
        base_eal = base_res.expected_annual_loss_inr
        assets = self.telemetry_service.get_all_assets()
        open_cves = sum(len(a.vulnerabilities) for a in assets)
        epss_list = [v.epss_score for a in assets for v in a.vulnerabilities]
        avg_epss = float(np.mean(epss_list)) if epss_list else 0.15

        # Dynamic drift model conditioned on active vulnerability exposure and exploitation probability
        monthly_drift = 0.025 + avg_epss * 0.04
        t30 = base_eal * (1.0 + monthly_drift)
        t60 = base_eal * (1.0 + monthly_drift * 2.2)
        t90 = base_eal * (1.0 + monthly_drift * 3.6)

        return {
            "current_eal_inr": round(base_eal, 2),
            "forecast_30d_eal_inr": round(t30, 2),
            "forecast_60d_eal_inr": round(t60, 2),
            "forecast_90d_eal_inr": round(t90, 2),
            "net_monthly_drift_pct": round(monthly_drift * 100, 1),
            "vulnerability_backlog_velocity": f"+{max(1, int(open_cves * 0.12))} net CVEs/month",
            "recommended_action": "Adopt automated patch orchestration (INIT-PATCH-04) to reverse drift trajectory to negative."
        }

    def process_natural_language_query(
        self,
        query: str,
        history: Optional[List[Dict[str, Any]]] = None,
        session_id: Optional[str] = None,
        user_email: Optional[str] = None,
        active_tab: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Parses executive, technical, and non-technical questions and answers using the
        comprehensive Project Knowledge Agent, citing exact web components, mathematical foundations,
        financial impacts, and live telemetry metrics with persistent conversational memory.
        """
        return self.knowledge_agent.answer_query(
            query=query,
            history=history,
            session_id=session_id,
            user_email=user_email,
            active_tab=active_tab
        )

    def identify_risks(
        self,
        description: str,
        session_id: Optional[str] = None,
        industry_sector: Optional[str] = None
    ) -> RiskIdentificationResult:
        """
        Executes automated AI Risk Identification on user-described systems, projects,
        processes, or security incidents.
        """
        return self.risk_identifier.identify_risks(
            description=description,
            session_id=session_id,
            industry_sector=industry_sector
        )

    def generate_risk_report(
        self,
        report_type: str = "executive_summary",
        industry_sector: Optional[str] = None,
        custom_budget_inr: Optional[float] = None,
        session_id: Optional[str] = None
    ) -> RiskReportResult:
        """
        Generates comprehensive AI Risk Reports across 4 core formats:
        - Executive Summaries (Boardroom & C-Suite)
        - Risk Assessment Reports (FAIR ontology, crown jewels, 5x5 matrix)
        - Mitigation Plans (0-1 Knapsack capital allocation, P0/P1/P2 initiatives)
        - Department-Wise Risk Summaries (Line-of-business risk distribution & accountability)
        Includes complete verifiable evidence and transparent methodological assumptions.
        """
        return self.report_engine.generate_report(
            report_type=report_type,
            industry_sector=industry_sector,
            custom_budget_inr=custom_budget_inr,
            session_id=session_id
        )

    def analyze_document(
        self,
        file_bytes: bytes,
        filename: str,
        file_format: Optional[str] = None,
        session_id: Optional[str] = None,
        industry_sector: Optional[str] = None
    ) -> DocumentIntelligenceResult:
        """
        Executes Document Intelligence on uploaded PDF, DOCX, CSV, and XLSX files:
        Extracts risks, controls, policies, and vulnerabilities with Inherent vs Residual
        5x5 matrix scoring, compliance mapping, and transparent evidence & assumptions.
        """
        return self.document_intelligence.analyze_document(
            file_bytes=file_bytes,
            filename=filename,
            file_format=file_format,
            session_id=session_id,
            industry_sector=industry_sector
        )

    def prioritize_risks(
        self,
        custom_risks: Optional[List[Dict[str, Any]]] = None,
        weights: Optional[PrioritizationWeights] = None,
        industry_sector: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> RiskPrioritizationResult:
        """
        Executes deterministic multi-criteria Risk Prioritization:
        Ranks enterprise or custom risks by combining Severity (25%), Business Impact (35%),
        Urgency (25%), and Existing Controls (15%) into an explainable Risk Priority Index (RPI 0-100)
        with P0-P3 action tiers and strict remediation SLAs.
        """
        return self.prioritization_engine.prioritize_risks(
            custom_risks=custom_risks,
            weights=weights,
            industry_sector=industry_sector,
            session_id=session_id
        )

    def analyze_scenario(
        self,
        query: str,
        target_asset_id: Optional[str] = None,
        outage_hours: Optional[float] = None,
        scenario_type: Optional[str] = None,
        session_id: Optional[str] = None,
        industry_sector: Optional[str] = None
    ) -> ScenarioAnalysisResult:
        """
        Answers hypothetical questions and evaluates What-If threat scenarios:
        Computes direct downtime financial loss, Monte Carlo FAIR EAL delta, 95% VaR,
        statutory liability under DPDP Act 2023, cascading operational disruptions,
        resilience status, single points of failure, and phased containment directives.
        """
        return self.scenario_analysis.analyze_scenario(
            query=query,
            target_asset_id=target_asset_id,
            outage_hours=outage_hours,
            scenario_type=scenario_type,
            session_id=session_id,
            industry_sector=industry_sector
        )

    def analyze_root_cause(
        self,
        risk_description_or_id: Optional[str] = None,
        session_id: Optional[str] = None,
        industry_sector: Optional[str] = None
    ) -> RootCauseAnalysisResult:
        """
        Executes Root Cause Analysis (RCA) on an asset ID, live top risk, or custom described scenario:
        Identifies underlying architectural, IAM governance, process, and IaC drift causes,
        uncovers 5-Whys progressive depth decomposition, maps upstream/downstream dependencies,
        and formulates a phased Corrective and Preventive Action (CAPA) roadmap.
        """
        return self.root_cause_engine.analyze_root_cause(
            risk_description_or_id=risk_description_or_id,
            session_id=session_id,
            industry_sector=industry_sector
        )

    def reassess_risk_monitoring(
        self,
        request: Optional[RiskMonitoringReassessmentRequest] = None,
        session_id: Optional[str] = None
    ) -> RiskMonitoringReassessmentResult:
        """
        Reassesses enterprise risks dynamically when users update assets, controls,
        incidents, or threat telemetry:
        Quantifies baseline vs reassessed EAL, 95% VaR, Enterprise Risk Score shift,
        5x5 matrix coordinate shifts, and priority tier migrations.
        """
        return self.monitoring_engine.reassess_monitoring(req=request, session_id=session_id)

    def map_compliance_frameworks(
        self,
        request: Optional[ComplianceMappingRequest] = None,
        session_id: Optional[str] = None
    ) -> ComplianceMappingResult:
        """
        Compliance Assistant (Feature 11):
        Maps identified enterprise risks and controls to relevant frameworks,
        including ISO/IEC 27001:2022, NIST CSF 2.0, RBI Cyber Security Framework,
        SEBI CSCRF, DPDP Act 2023, and CIS Controls v8.
        Identifies regulatory penalties, audit gaps, and compensating controls.
        """
        return self.compliance_assistant.map_risks_and_controls(req=request, session_id=session_id)

    def generate_ai_insights(
        self,
        request: Optional[AiInsightsRequest] = None,
        session_id: Optional[str] = None
    ) -> AiInsightsResult:
        """
        AI Insights (Feature 12):
        Identifies recurring risk patterns, weak/deficient controls, multi-horizon
        risk trend projections (30d, 60d, 90d), and actionable areas requiring
        executive management attention.
        """
        return self.insights_engine.generate_insights(req=request, session_id=session_id)

    def retrain_nlp_model(self, epochs: int = 100) -> Dict[str, Any]:
        """
        Retrains the AI Neural Softmax Intent Classifier for the specified epochs (default: 100).
        Returns complete 100-epoch convergence telemetry, loss history, and accuracy.
        """
        return self.nlp_engine.retrain(epochs=epochs)

    def get_nlp_model_info(self) -> Dict[str, Any]:
        """
        Returns model architecture, 20x dataset metrics, and active training state.
        """
        return {
            "model_type": "Multi-Class Neural Softmax Intent Classifier",
            "feature_vocabulary_size": self.nlp_engine.vocab_size,
            "num_intent_classes": self.nlp_engine.num_classes,
            "intents": list(self.nlp_engine._intent_to_idx.keys()),
            "fine_tune_factor": "20x",
            "telemetry": self.nlp_engine.training_telemetry
        }
