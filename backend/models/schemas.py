"""
Pydantic data schemas for the RiskLens platform.
Covers Assets, Vulnerabilities, Controls, Threat Intel, Simulation Outputs,
Optimization Results, Scenarios, and Compliance Frameworks.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class CriticalityTier(str, Enum):
    TIER_1 = "Tier 1 - Crown Jewel"
    TIER_2 = "Tier 2 - Business Operational"
    TIER_3 = "Tier 3 - Supporting"


class BusinessUnit(str, Enum):
    RETAIL_BANKING = "Retail Banking & Payments"
    CARDS_WEALTH = "Cards & Wealth Management"
    CORPORATE_TREASURY = "Corporate & Treasury"
    CLOUD_INFRASTRUCTURE = "Cloud & Core Infrastructure"
    ENTERPRISE_OPS = "Enterprise Operations & HR"


class ControlTelemetry(BaseModel):
    control_id: str
    name: str
    category: str
    framework_mappings: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="e.g. {'ISO_27001': ['A.9.4.2'], 'NIST_CSF': ['PR.AC-1'], 'RBI': ['3.1'], 'SEBI': ['Annexure-1.4']}"
    )
    telemetry_score: float = Field(..., ge=0.0, le=1.0, description="0.0 (failing/absent) to 1.0 (fully enforced/optimal)")
    implementation_status: str = "Enforced"
    description: str = ""


class VulnerabilityFinding(BaseModel):
    cve_id: str
    asset_id: str
    title: str
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    epss_score: float = Field(..., ge=0.0, le=1.0, description="Exploit Prediction Scoring System probability")
    is_cisa_kev: bool = False
    patch_available: bool = True
    remediation_status: str = "Open"
    days_open: int = 15
    attack_vector: str = "Network"


class Asset(BaseModel):
    asset_id: str
    name: str
    business_unit: BusinessUnit
    criticality: CriticalityTier
    revenue_per_hour_inr: float = Field(..., description="Revenue loss per hour of complete outage in INR")
    pii_records_count: int = Field(default=0, description="Number of sensitive customer / financial records")
    data_classification: str = "Confidential"
    rto_hours: float = 4.0
    rpo_hours: float = 1.0
    controls: List[ControlTelemetry] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    ip_or_endpoint: str = ""
    cloud_provider: str = "AWS"


class SecurityInitiative(BaseModel):
    initiative_id: str
    title: str
    category: str
    cost_inr: float = Field(..., description="Annual total cost in INR (implementation + licensing + ops)")
    cost_usd: float = Field(..., description="Annual total cost in USD")
    target_controls: List[str] = Field(default_factory=list)
    target_asset_tiers: List[CriticalityTier] = Field(default_factory=list)
    target_assets: List[str] = Field(default_factory=list)
    resistance_boost: float = Field(0.25, ge=0.0, le=1.0, description="Relative boost in control resistance")
    annual_risk_reduction_inr: float = 0.0
    annual_risk_reduction_usd: float = 0.0
    rosi_percentage: float = 0.0
    description: str = ""
    implementation_weeks: int = 4


class LossExceedancePoint(BaseModel):
    loss_amount_inr: float
    loss_amount_usd: float
    exceedance_probability: float  # e.g. 0.05 for 5% chance of exceeding this amount


class QuantifiedRiskResult(BaseModel):
    currency_base: str = "INR"
    expected_annual_loss_inr: float
    expected_annual_loss_usd: float
    var_90_inr: float = 0.0
    var_90_usd: float = 0.0
    var_95_inr: float
    var_95_usd: float
    var_99_inr: float
    var_99_usd: float
    cvar_95_inr: float
    cvar_95_usd: float
    recommended_var_percentile: int = 95
    recommended_var_reason: str = "Standard Enterprise Baseline (1-in-20 Year Event)"
    enterprise_risk_score: float = Field(..., ge=0, le=100)
    loss_exceedance_curve: List[LossExceedancePoint]
    loss_by_bu_inr: Dict[str, float]
    loss_by_bu_usd: Dict[str, float]
    loss_by_tier_inr: Dict[str, float]
    loss_by_tier_usd: Dict[str, float]
    top_risk_assets: List[Dict[str, Any]]
    primary_loss_breakdown_inr: Dict[str, float]
    secondary_loss_breakdown_inr: Dict[str, float]
    total_simulations: int = 10000


class OptimizationResult(BaseModel):
    budget_inr: float
    budget_usd: float
    selected_initiatives: List[SecurityInitiative]
    total_spent_inr: float
    total_spent_usd: float
    budget_utilization_pct: float
    baseline_eal_inr: float
    baseline_eal_usd: float
    post_mitigation_eal_inr: float
    post_mitigation_eal_usd: float
    net_risk_reduction_inr: float
    net_risk_reduction_usd: float
    portfolio_rosi_pct: float
    efficient_frontier: List[Dict[str, float]]
    diminishing_returns_threshold_inr: float
    diminishing_returns_threshold_usd: float


class WhatIfScenarioRequest(BaseModel):
    scenario_id: str
    custom_params: Dict[str, Any] = Field(default_factory=dict)


class WhatIfScenarioResult(BaseModel):
    scenario_id: str
    scenario_title: str
    description: str
    baseline_eal_inr: float
    baseline_eal_usd: float
    scenario_eal_inr: float
    scenario_eal_usd: float
    delta_eal_inr: float
    delta_eal_usd: float
    delta_percentage: float
    baseline_var95_inr: float
    scenario_var95_inr: float
    key_drivers: List[str]
    ai_executive_summary: str


class FrameworkScore(BaseModel):
    framework_id: str
    framework_name: str
    overall_compliance_pct: float
    category_scores: Dict[str, float]
    status: str
    open_deficiencies_count: int
    regulatory_mandate: str


# ================= AI RISK IDENTIFICATION & SCORING MODELS =================

class RiskScoreProfile(BaseModel):
    likelihood: int  # 1 to 5: 1=Rare, 2=Unlikely, 3=Moderate, 4=Likely, 5=Almost Certain
    likelihood_label: str
    impact: int  # 1 to 5: 1=Negligible, 2=Minor, 3=Moderate, 4=Major, 5=Catastrophic
    impact_label: str
    score: int  # likelihood * impact (1 to 25)
    score_100: float  # (score / 25) * 100
    classification: str  # Critical, High, Medium, Low
    matrix_position: Dict[str, int]  # {"likelihood": likelihood, "impact": impact, "row": likelihood, "col": impact}
    matrix_coord: str  # e.g. "L5:I5"
    badge: str  # e.g. "🔴 Critical"


class MitigationRecommendation(BaseModel):
    priority: int  # Priority ranking order: 1, 2, 3...
    priority_label: str  # e.g. "P0 - Immediate Remediation", "P1 - High Priority"
    initiative_id: str  # e.g. "INIT-MICRO-05"
    title: str  # e.g. "Zero-Trust Network Microsegmentation & Ingress Enclave"
    target_risk: str  # The specific risk this control mitigates
    action_type: str  # e.g. "Immediate Technical Remediation", "Identity Hardening"
    cost_inr: float
    cost_usd: float
    expected_risk_reduction_pct: float  # e.g. 82.0
    expected_loss_reduction_inr: Optional[float] = None
    expected_loss_reduction_usd: Optional[float] = None
    rosi_pct: float
    effort: str  # e.g. "Low (2-4 hours)" or "Medium (1-2 weeks)"
    effort_level: str  # "Low", "Medium", "High"
    responsible_team: str  # Primary team responsible, e.g. "Cloud Infrastructure & Network SecOps"
    secondary_teams: Optional[List[str]] = None  # Supporting teams
    implementation_steps: List[str]  # Actionable, step-by-step implementation instructions
    verification_metric: Optional[str] = None  # Verification or validation criteria
    description: str
    action_link: Optional[str] = None

    def __getitem__(self, item):
        return getattr(self, item)

    def get(self, item, default=None):
        return getattr(self, item, default)


class IdentifiedRiskItem(BaseModel):
    risk_title: str
    category: str  # Confidentiality, Integrity, Availability, Compliance, Financial, Reputational
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    inherent_risk: Optional[RiskScoreProfile] = None
    residual_risk: Optional[RiskScoreProfile] = None
    risk_reduction_pct: Optional[float] = None
    recommended_mitigations: Optional[List[MitigationRecommendation]] = None


class OverallRiskScoring(BaseModel):
    inherent_risk: RiskScoreProfile
    residual_risk: RiskScoreProfile
    risk_reduction_pct: float
    matrix_shift_summary: str
    tolerance_status: str


class ConsequenceItem(BaseModel):
    impact_type: str  # Operational Downtime, Statutory / Regulatory, Direct Financial, Reputational
    details: str
    estimated_cost_inr: Optional[float] = None
    estimated_cost_usd: Optional[float] = None


class RiskIdentificationRequest(BaseModel):
    description: str
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class RiskIdentificationResult(BaseModel):
    description: str
    scenario_type: str  # System Misconfiguration, Security Incident, Project / Cloud Migration, Process Flaw, IAM Exposure
    executive_summary: str
    identified_risks: List[IdentifiedRiskItem]
    root_causes: List[str]
    affected_assets: List[Dict[str, Any]]
    consequences: List[ConsequenceItem]
    statutory_penalties: List[str]
    recommended_mitigations: List[MitigationRecommendation]
    overall_risk_severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    suggested_actions: List[Dict[str, str]]
    markdown_report: str
    overall_scoring: Optional[OverallRiskScoring] = None
    matrix_view: Optional[str] = None
    matrix_grid_markdown: Optional[str] = None


class ReportEvidence(BaseModel):
    total_assets_monitored: int
    total_cves_analyzed: int
    critical_cves_count: int
    cisa_kev_active_count: int
    crown_jewel_assets: List[Dict[str, Any]]
    control_hygiene_scores: Dict[str, float]
    hourly_downtime_exposure_inr: float
    customer_pii_records_exposed: int
    statutory_citations: List[str]


class ReportAssumptions(BaseModel):
    simulation_engine: str
    confidence_level: str
    loss_distributions: str
    threat_capability_baseline: str
    currency_exchange_rate: float
    remediation_sla_baseline: str
    risk_tolerance_threshold_inr: float
    budget_optimization_algorithm: str


class DepartmentRiskItem(BaseModel):
    department_name: str
    business_unit: str
    risk_share_pct: float
    expected_annual_loss_inr: float
    expected_annual_loss_usd: float
    critical_asset_name: str
    critical_asset_id: str
    open_cves_count: int
    top_cve: str
    top_epss: float
    responsible_team: str
    priority_control: str


class RiskReportRequest(BaseModel):
    report_type: str = "executive_summary"  # executive_summary, risk_assessment, mitigation_plan, department_summary, comprehensive
    industry_sector: Optional[str] = None
    session_id: Optional[str] = None
    custom_budget_inr: Optional[float] = None


class RiskReportResult(BaseModel):
    report_type: str
    title: str
    generated_at: str
    executive_summary: str
    evidence: ReportEvidence
    assumptions: ReportAssumptions
    metrics: Dict[str, Any]
    department_summaries: Optional[List[DepartmentRiskItem]] = None
    recommended_mitigations: Optional[List[MitigationRecommendation]] = None
    markdown_report: str
    suggested_actions: List[Dict[str, str]]


# =========================================================
# Feature 6: Document Intelligence Schemas
# =========================================================

class ExtractedRisk(BaseModel):
    id: str
    title: str
    description: str
    category: str
    affected_assets: List[str]
    root_causes: List[str]
    potential_consequences: List[str]
    inherent_likelihood: int  # 1-5
    inherent_impact: int      # 1-5
    inherent_level: str       # Critical, High, Medium, Low
    residual_likelihood: int  # 1-5
    residual_impact: int      # 1-5
    residual_level: str       # Critical, High, Medium, Low
    estimated_loss_range_inr: Optional[str] = None


class ExtractedControl(BaseModel):
    id: str
    name: str
    control_type: str         # Preventive, Detective, Corrective, Compensating
    status: str               # Implemented, Partially Implemented, Deficient, Missing / Gap
    coverage_score: float     # 0.0 to 1.0
    implementation_steps: List[str]
    responsible_team: str
    effort: str               # Low, Medium, High
    expected_risk_reduction_pct: float


class ExtractedPolicy(BaseModel):
    id: str
    title: str
    standard_or_framework: str  # DPDP Act 2023, RBI CSFS, ISO 27001, NIST CSF, PCI-DSS, etc.
    clause_or_section: Optional[str] = None
    compliance_status: str      # Compliant, Partially Compliant, Non-Compliant, Gap Identified
    key_requirements: List[str]
    evidence_or_findings: str
    gap_severity: Optional[str] = "Medium"


class ExtractedVulnerability(BaseModel):
    id: str
    title: str
    cve_id: Optional[str] = None
    cvss_score: float           # 0.0 - 10.0
    severity: str               # Critical, High, Medium, Low
    epss_score: Optional[float] = None
    cisa_kev: bool = False
    affected_systems: List[str]
    description: str
    remediation_guidance: str


class DocumentMetadata(BaseModel):
    filename: str
    file_type: str              # pdf, docx, csv, xlsx
    file_size_bytes: int
    total_pages_or_sheets: int
    word_count: int
    extracted_entities_count: Dict[str, int]
    analyzed_at: str


class DocumentIntelligenceRequest(BaseModel):
    filename: str
    file_format: Optional[str] = None  # pdf, docx, csv, xlsx (inferred if None)
    content_base64: Optional[str] = None
    text_content: Optional[str] = None
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class DocumentIntelligenceResult(BaseModel):
    status: str = "success"
    metadata: DocumentMetadata
    executive_summary: str
    risks: List[ExtractedRisk]
    controls: List[ExtractedControl]
    policies: List[ExtractedPolicy]
    vulnerabilities: List[ExtractedVulnerability]
    posture_score: float        # 0.0 - 100.0
    risk_matrix_summary: Dict[str, int]
    evidence_and_assumptions: Dict[str, Any]
    suggested_next_questions: List[str]
    markdown_summary: str


# =========================================================
# Feature 7: Risk Prioritization Schemas
# =========================================================

class PrioritizationScores(BaseModel):
    severity_score: float            # 0.0 - 100.0 (CVSS, Threat Capability)
    business_impact_score: float     # 0.0 - 100.0 (EAL, Tier, Revenue/hr, PII)
    urgency_score: float             # 0.0 - 100.0 (EPSS, CISA KEV, Days open)
    control_deficiency_score: float  # 0.0 - 100.0 (100 - Existing Control Hygiene)
    composite_rpi_score: float       # 0.0 - 100.0 (Risk Priority Index)


class PrioritizedRiskItem(BaseModel):
    rank: int                        # 1, 2, 3...
    risk_id: str                     # e.g. "AST-001" or "DOC-RISK-001"
    risk_title: str                  # e.g. "Core Banking Unauthenticated Session Hijacking"
    asset_name: str
    business_unit: str
    priority_tier: str               # P0 (Immediate 24-48h), P1 (Critical 7d), P2 (High 30d), P3 (Medium 90d)
    sla_target_days: int             # 2, 7, 30, 90
    scores: PrioritizationScores
    severity_drivers: List[str]      # Technical CVE, weaponization, exploit complexity
    impact_drivers: List[str]        # EAL, hourly downtime cost, PII records, statutory liability
    urgency_drivers: List[str]       # EPSS velocity, CISA KEV active exploitation, days open
    existing_controls_summary: str   # Existing control hygiene & single points of failure
    recommended_action: str          # Control initiative, steps, effort
    responsible_team: str


class PrioritizationWeights(BaseModel):
    weight_severity: float = 0.25
    weight_impact: float = 0.35
    weight_urgency: float = 0.25
    weight_controls: float = 0.15


class RiskPrioritizationRequest(BaseModel):
    custom_risks: Optional[List[Dict[str, Any]]] = None  # None uses live enterprise assets
    weights: Optional[PrioritizationWeights] = None
    industry_sector: Optional[str] = None
    session_id: Optional[str] = None


class RiskPrioritizationResult(BaseModel):
    status: str = "success"
    prioritized_at: str
    total_risks_ranked: int
    p0_immediate_count: int
    p1_critical_count: int
    p2_high_count: int
    p3_medium_count: int
    weights_applied: PrioritizationWeights
    ranked_risks: List[PrioritizedRiskItem]
    methodology_and_evidence: Dict[str, Any]
    markdown_report: str
    suggested_next_questions: List[str]


# ================= FEATURE 8: SCENARIO ANALYSIS SCHEMAS =================

class FinancialImpactBreakdown(BaseModel):
    direct_downtime_loss_inr: float
    hourly_downtime_rate_inr: float
    outage_duration_hours: float
    baseline_eal_inr: float
    simulated_eal_inr: float
    delta_eal_inr: float
    delta_percentage: float
    baseline_var95_inr: float
    simulated_var95_inr: float
    statutory_fine_exposure_inr: float
    incident_response_cost_inr: float
    total_projected_loss_inr: float


class OperationalImpact(BaseModel):
    target_asset_id: str
    target_asset_name: str
    criticality_tier: str
    business_unit: str
    estimated_rto_hours: float
    mtpd_hours: float
    pii_records_at_risk: int
    cascading_disruptions: List[str]
    sla_breach_probability_pct: float


class ResilienceStatus(BaseModel):
    has_active_redundancy: bool
    failover_readiness_score: float  # 0 to 100
    backup_integrity_status: str
    existing_defenses: List[str]
    single_points_of_failure: List[str]


class ScenarioMitigationStep(BaseModel):
    phase: str
    action: str
    responsible_team: str
    estimated_time: str


class ScenarioAnalysisRequest(BaseModel):
    scenario_query: str  # e.g. "What happens if our primary server goes offline?"
    target_asset_id: Optional[str] = None
    outage_hours: Optional[float] = None
    scenario_type: Optional[str] = None  # outage, ransomware, data_breach, patch_delay, zero_day, cloud_outage, custom
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class ScenarioAnalysisResult(BaseModel):
    status: str = "success"
    analyzed_at: str
    scenario_query: str
    scenario_title: str
    scenario_type: str
    severity_classification: str  # "Catastrophic", "Critical", "High", "Moderate"
    summary_narrative: str
    financial_impact: FinancialImpactBreakdown
    operational_impact: OperationalImpact
    resilience_status: ResilienceStatus
    action_plan: List[ScenarioMitigationStep]
    markdown_analysis: str
    suggested_next_questions: List[str]


# ================= FEATURE 9: ROOT CAUSE ANALYSIS SCHEMAS =================

class CausalFactor(BaseModel):
    category: str  # "Architecture & Infrastructure", "Identity & Access Governance", "Process & Patch Lifecycle", "Configuration & IaC Drift", "Observability & Telemetry"
    underlying_cause: str
    contributing_factors: List[str]
    evidence_and_telemetry: str
    preventability_score: float  # 0.0 - 100.0


class FiveWhysStep(BaseModel):
    level: int  # 1 to 5
    question: str
    finding: str
    systemic_layer: str


class DependencyChainNode(BaseModel):
    dependency_type: str  # "Upstream Dependency", "Direct Asset", "Downstream Consumer"
    entity_name: str
    impact_mode: str


class CapaAction(BaseModel):
    action_type: str  # "Immediate Containment (0-24h)", "Corrective Action (7d)", "Preventive Action (30-90d)"
    action_title: str
    description: str
    responsible_team: str
    success_kpi: str


class RootCauseAnalysisRequest(BaseModel):
    risk_description_or_id: Optional[str] = None  # None analyzes enterprise top risk AST-001
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class RootCauseAnalysisResult(BaseModel):
    status: str = "success"
    analyzed_at: str
    target_risk_title: str
    target_asset_name: str
    target_asset_id: str
    surface_symptom: str
    primary_root_cause: str
    causal_factors: List[CausalFactor]
    five_whys: List[FiveWhysStep]
    dependency_chain: List[DependencyChainNode]
    capa_roadmap: List[CapaAction]
    markdown_analysis: str
    suggested_next_questions: List[str]


# ================= FEATURE 10: RISK MONITORING SCHEMAS =================

class MetricComparison(BaseModel):
    metric_name: str
    baseline_value: float
    reassessed_value: float
    delta_value: float
    delta_percentage: float
    unit: str  # "INR", "USD", "Score", "Hours", "%"


class AssetMatrixShift(BaseModel):
    asset_id: str
    asset_name: str
    baseline_likelihood: int
    baseline_impact: int
    baseline_level: str
    reassessed_likelihood: int
    reassessed_impact: int
    reassessed_level: str
    priority_tier_before: str
    priority_tier_after: str


class MonitoringAuditEntry(BaseModel):
    timestamp: str
    mutation_type: str
    entity_id: str
    change_summary: str
    eal_impact_inr: float


class RiskMonitoringReassessmentRequest(BaseModel):
    mutation_type: str = "full_reassessment"  # asset_update, control_update, incident_update, threat_update, full_reassessment
    asset_id: Optional[str] = None
    asset_updates: Optional[Dict[str, Any]] = None
    control_id: Optional[str] = None
    control_updates: Optional[Dict[str, Any]] = None
    incident_details: Optional[Dict[str, Any]] = None
    apply_permanently: bool = False
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class RiskMonitoringReassessmentResult(BaseModel):
    status: str = "success"
    reassessed_at: str
    mutation_type: str
    mutation_summary: str
    overall_posture_drift: str  # "Risk Reduced (Posture Improved)", "Risk Escalated (Posture Degraded)", "Stable / Neutral"
    metrics_comparison: List[MetricComparison]
    impacted_assets: List[AssetMatrixShift]
    audit_trail: List[MonitoringAuditEntry]
    markdown_briefing: str
    suggested_next_questions: List[str]


# ==============================================================================
# FEATURE 11: COMPLIANCE ASSISTANT SCHEMAS
# ==============================================================================

class FrameworkClauseMapping(BaseModel):
    framework_name: str  # "ISO/IEC 27001:2022", "NIST CSF 2.0", "RBI Cyber Security Framework", "SEBI CSCRF", "DPDP Act 2023", "CIS Controls v8"
    clause_id: str  # e.g. "A.8.8", "PR.AC-1", "Section 3.1", "Section 2.5", "Section 8(5)", "CIS-6.3"
    clause_title: str
    compliance_status: str  # "Compliant", "Partially Compliant", "Non-Compliant / Audit Finding"
    gap_description: Optional[str] = None
    audit_readiness_score: float  # 0.0 to 100.0


class RiskFrameworkMapping(BaseModel):
    risk_id: str
    risk_title: str
    asset_id: str
    asset_name: str
    threat_category: str
    severity: str  # "Critical", "High", "Medium", "Low"
    framework_mappings: List[FrameworkClauseMapping]
    primary_regulatory_exposure: str
    recommended_compensating_controls: List[str]


class ControlFrameworkMapping(BaseModel):
    control_id: str
    control_name: str
    category: str
    telemetry_score: float
    implementation_status: str  # "Enforced", "Partially Enforced", "Deficient"
    mapped_frameworks: List[str]
    expected_risk_reduction_pct: float


class ComplianceFrameworkSummary(BaseModel):
    framework_name: str
    overall_compliance_pct: float
    status: str  # "Compliant (Audit Ready)", "Conditionally Compliant", "Requires Remediation"
    total_controls_mapped: int
    covered_clauses_count: int
    open_audit_findings_count: int
    statutory_fine_exposure: Optional[str] = None


class ComplianceMappingRequest(BaseModel):
    query: Optional[str] = None
    target_frameworks: Optional[List[str]] = None
    target_risk_id: Optional[str] = None
    target_asset_id: Optional[str] = None
    target_control_id: Optional[str] = None
    include_audit_findings: bool = True
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class ComplianceMappingResult(BaseModel):
    status: str = "success"
    generated_at: str
    scope_summary: str
    framework_summaries: List[ComplianceFrameworkSummary]
    risk_mappings: List[RiskFrameworkMapping]
    control_mappings: List[ControlFrameworkMapping]
    statutory_penalties_identified: List[Dict[str, str]]
    markdown_analysis: str
    suggested_next_questions: List[str]


# ==============================================================================
# FEATURE 12: AI INSIGHTS SCHEMAS
# ==============================================================================

class RecurringRiskPattern(BaseModel):
    pattern_id: str
    risk_theme: str
    recurrence_frequency: str
    affected_assets_count: int
    affected_assets: List[str]
    root_cause_driver: str
    cumulative_loss_exposure_inr: float
    trend_direction: str  # "Escalating", "Stable", "Declining"


class WeakControlFinding(BaseModel):
    control_id: str
    control_name: str
    category: str
    telemetry_score: float
    deficiency_severity: str  # "Critical Deficiency", "High Degradation", "Moderate Gap"
    impacted_tier1_assets: List[str]
    fair_impact: str
    recommended_initiative: str


class RiskTrendProjection(BaseModel):
    horizon: str  # "Current Baseline", "30-Day Inertial Drift", "60-Day Inertial Drift", "90-Day Inertial Drift"
    projected_eal_inr: float
    projected_eal_usd: float
    projected_var95_inr: float
    projected_risk_score: float
    drift_percentage: float
    key_trend_drivers: List[str]


class ManagementAttentionArea(BaseModel):
    attention_id: str
    title: str
    urgency_level: str  # "Immediate Action (0-48h)", "High Priority (7-14d)", "Strategic Reform (30-60d)"
    executive_summary: str
    financial_exposure_at_risk_inr: float
    responsible_executive: str
    mandated_action: str
    governance_framework_impact: str


class AiInsightsRequest(BaseModel):
    query: Optional[str] = None
    focus_area: Optional[str] = "all"  # "all", "recurring_risks", "weak_controls", "risk_trends", "management_attention"
    time_horizon_days: int = 90
    session_id: Optional[str] = None
    industry_sector: Optional[str] = None


class AiInsightsResult(BaseModel):
    status: str = "success"
    generated_at: str
    insights_summary: str
    overall_risk_trajectory: str  # "Escalating Risk Drift", "Moderate Posture Degradation", "Stable Posture", "Improving"
    recurring_risks: List[RecurringRiskPattern]
    weak_controls: List[WeakControlFinding]
    risk_trends: List[RiskTrendProjection]
    management_attention_areas: List[ManagementAttentionArea]
    markdown_briefing: str
    suggested_next_questions: List[str]
