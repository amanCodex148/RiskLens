"""
REST API Routes for RiskLens platform.
"""

from fastapi import APIRouter, HTTPException, Query, Response, Header, File, UploadFile, Form
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import json
import base64
import secrets
import threading
import re
from datetime import datetime

from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer
from backend.engine.ai_decision import AiDecisionSupportService
from backend.engine.compliance import ComplianceFrameworkEngine
from backend.engine.chat_memory import get_memory_store
from backend.ingestion.telemetry_loader import TelemetryService, USD_INR_RATE
from backend.ingestion.industry_datasets import get_all_industry_datasets_metadata, get_industry_dataset_by_id
from backend.ingestion.dataset_store import get_dataset_store, compute_asset_fingerprint
from backend.models.schemas import (
    WhatIfScenarioRequest,
    RiskIdentificationRequest,
    RiskIdentificationResult,
    RiskReportRequest,
    RiskReportResult,
    DocumentIntelligenceRequest,
    DocumentIntelligenceResult,
    RiskPrioritizationRequest,
    RiskPrioritizationResult,
    PrioritizationWeights,
    ScenarioAnalysisRequest,
    ScenarioAnalysisResult,
    RootCauseAnalysisRequest,
    RootCauseAnalysisResult,
    RiskMonitoringReassessmentRequest,
    RiskMonitoringReassessmentResult,
    ComplianceMappingRequest,
    ComplianceMappingResult,
    AiInsightsRequest,
    AiInsightsResult
)

api_router = APIRouter()

# Singletons
_risk_engine = FairRiskEngine(iterations=5000)
_optimizer = InvestmentOptimizer(risk_engine=_risk_engine)
_ai_service = AiDecisionSupportService(risk_engine=_risk_engine)
_compliance_engine = ComplianceFrameworkEngine()
_telemetry_service = TelemetryService.get_instance()
_mutation_lock = threading.RLock()


class OptimizeRequest(BaseModel):
    budget_inr: Optional[float] = None
    budget_usd: Optional[float] = None


class AssistantQueryRequest(BaseModel):
    query: str
    session_id: Optional[str] = None
    history: Optional[List[Dict[str, Any]]] = None
    active_tab: Optional[str] = None


class NlpRetrainRequest(BaseModel):
    epochs: Optional[int] = 100
    learning_rate: Optional[float] = 0.85


@api_router.get("/risk/summary")
def get_risk_summary():
    """Returns top-level enterprise risk metrics (EAL, VaR, CVaR, Risk Score, Top Risk Assets)."""
    res = _risk_engine.run_enterprise_simulation()
    return res


@api_router.get("/risk/loss-exceedance")
def get_loss_exceedance_curve():
    """Returns coordinates for the Loss Exceedance Curve (P(Loss >= x))."""
    res = _risk_engine.run_enterprise_simulation()
    return {"curve": res.loss_exceedance_curve}


@api_router.get("/risk/breakdown")
def get_risk_breakdowns():
    """Returns loss distributions by Business Unit and Criticality Tier."""
    res = _risk_engine.run_enterprise_simulation()
    return {
        "by_bu_inr": res.loss_by_bu_inr,
        "by_bu_usd": res.loss_by_bu_usd,
        "by_tier_inr": res.loss_by_tier_inr,
        "by_tier_usd": res.loss_by_tier_usd,
        "primary_losses_inr": res.primary_loss_breakdown_inr,
        "secondary_losses_inr": res.secondary_loss_breakdown_inr
    }


@api_router.get("/initiatives")
def list_initiatives():
    """Returns candidate security initiatives evaluated with estimated ROSI."""
    return _optimizer.compute_initiative_effectiveness()


@api_router.post("/optimize")
def optimize_portfolio(req: OptimizeRequest):
    """Solves budget-constrained portfolio optimization and returns Efficient Frontier."""
    if req.budget_inr is not None and req.budget_inr >= 0:
        budget = req.budget_inr
    elif req.budget_usd is not None and req.budget_usd >= 0:
        budget = req.budget_usd * USD_INR_RATE
    else:
        budget = 10000000.0  # ₹1.00 Crore default

    return _optimizer.optimize_security_investment(budget_inr=budget)


@api_router.get("/scenarios/list")
def list_scenarios():
    """Lists available pre-configured What-If scenarios."""
    return [
        {
            "id": "SCEN-MFA-ALL",
            "title": "Phishing-Resistant MFA on 100% Privileged Accounts",
            "category": "Identity Security",
            "impact_type": "Risk Reduction"
        },
        {
            "id": "SCEN-PATCH-DELAY-30",
            "title": "30-Day Delay in Critical Vulnerability Remediation",
            "category": "Vulnerability Risk",
            "impact_type": "Risk Escalation"
        },
        {
            "id": "SCEN-ZERO-DAY-WEB",
            "title": "Zero-Day Exploit on Public Web Gateway",
            "category": "Threat Intelligence",
            "impact_type": "Risk Escalation"
        },
        {
            "id": "SCEN-RANSOM-CORE",
            "title": "Ransomware Outbreak on Core Banking Switch",
            "category": "Cyber Extortion",
            "impact_type": "Disaster Scenario"
        },
        {
            "id": "SCEN-MICROSEG-CLOUD",
            "title": "Zero-Trust Microsegmentation on Cloud & DB Clusters",
            "category": "Network Architecture",
            "impact_type": "Risk Reduction"
        }
    ]


@api_router.post("/scenarios/simulate")
def simulate_scenario(req: WhatIfScenarioRequest):
    """Simulates a What-If scenario comparing baseline against post-condition."""
    return _ai_service.simulate_scenario(req.scenario_id, req.custom_params)


@api_router.get("/forecast")
def get_risk_forecast():
    """Returns 30, 60, and 90-day cyber risk trajectory forecasting."""
    return _ai_service.forecast_risk_trajectory()


@api_router.get("/compliance/frameworks")
def get_compliance_frameworks():
    """Returns compliance posture across ISO 27001, NIST CSF 2.0, CIS v8, RBI, and SEBI CSCRF."""
    return _compliance_engine.get_all_framework_scores()


@api_router.get("/compliance/report")
def get_board_compliance_report():
    """Returns board-ready executive audit governance report."""
    return _compliance_engine.generate_board_compliance_report()


@api_router.get("/assets")
def list_assets():
    """Returns enterprise asset inventory with telemetry, open CVEs, and EPSS scores."""
    return _telemetry_service.get_all_assets()


@api_router.post("/assistant/query")
def assistant_query(
    req: AssistantQueryRequest,
    authorization: Optional[str] = Header(None)
):
    """Conversational natural language risk assistant with persistent memory."""
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    memory_store = get_memory_store()
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    # Resolve session_id
    session_id = req.session_id or (f"user_{user_email}" if user_email else None)
    if not session_id:
        session_id = f"sess_{secrets.token_hex(8)}"

    # Fetch existing conversation history from SQLite if not passed explicitly
    history = req.history
    if history is None:
        history = memory_store.get_recent_turns(session_id=session_id, user_email=user_email, max_turns=6)

    # Save user message into persistent memory
    memory_store.save_message(
        session_id=session_id,
        role="user",
        content=req.query.strip(),
        user_email=user_email
    )
    # Extract and remember any user-stated constraints, personas, or preferences
    try:
        memory_store.extract_and_store_preferences(
            text=req.query.strip(),
            session_id=session_id,
            user_email=user_email
        )
    except Exception:
        pass

    # Execute query resolution with multi-turn context
    result = _ai_service.process_natural_language_query(
        query=req.query,
        history=history,
        session_id=session_id,
        user_email=user_email,
        active_tab=req.active_tab
    )

    # Save assistant message into persistent memory
    memory_store.save_message(
        session_id=session_id,
        role="assistant",
        content=result.get("response_markdown", ""),
        user_email=user_email,
        metadata={
            "suggested_next_questions": result.get("suggested_next_questions", [])
        }
    )

    # Append session and memory metadata to response
    result["session_id"] = session_id
    result["memory_active"] = True
    result["turns_remembered"] = len(history) + 2

    return result


@api_router.post("/assistant/identify-risk", response_model=RiskIdentificationResult)
def identify_cyber_risks(
    req: RiskIdentificationRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Automated AI Risk Identification endpoint.
    Users describe a project, system, business process, or incident.
    The AI identifies potential risks, root causes, affected assets, and statutory consequences.
    """
    if not req.description.strip():
        raise HTTPException(status_code=400, detail="Description cannot be empty")

    memory_store = get_memory_store()
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else f"sess_{secrets.token_hex(8)}")

    # Execute AI Risk Identification
    result = _ai_service.identify_risks(
        description=req.description,
        session_id=session_id,
        industry_sector=req.industry_sector
    )

    # Persist in conversation memory
    try:
        memory_store.save_message(
            session_id=session_id,
            role="user",
            content=f"Identify risks in: {req.description}",
            user_email=user_email
        )
        memory_store.save_message(
            session_id=session_id,
            role="assistant",
            content=result.markdown_report,
            user_email=user_email,
            metadata={
                "topic": "ai_risk_identification",
                "scenario_type": result.scenario_type,
                "overall_severity": result.overall_risk_severity
            }
        )
    except Exception:
        pass

    return result


@api_router.post("/assistant/reports", response_model=RiskReportResult)
def generate_ai_risk_report(
    req: RiskReportRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Automated AI Risk Reports generation endpoint.
    Produces:
    1. Executive Summaries (Boardroom & C-Suite)
    2. Risk Assessment Reports (FAIR ontology, crown jewels, 5x5 matrix)
    3. Mitigation Plans (0-1 Knapsack capital allocation, P0/P1/P2 initiatives)
    4. Department-Wise Risk Summaries (Line-of-business risk distribution & accountability)
    5. Master Enterprise Risk Dossier (Comprehensive multi-chapter report)
    Every report includes verifiable evidence and transparent methodological assumptions.
    """
    memory_store = get_memory_store()
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else f"sess_{secrets.token_hex(8)}")

    result = _ai_service.generate_risk_report(
        report_type=req.report_type,
        industry_sector=req.industry_sector,
        custom_budget_inr=req.custom_budget_inr,
        session_id=session_id
    )

    # Persist in conversation memory so user can ask follow-up questions
    try:
        memory_store.save_message(
            session_id=session_id,
            role="user",
            content=f"Generate {req.report_type} risk report",
            user_email=user_email
        )
        memory_store.save_message(
            session_id=session_id,
            role="assistant",
            content=result.markdown_report[:1200] + "\n\n*(Full report generated)*",
            user_email=user_email,
            metadata={"report_type": result.report_type, "title": result.title}
        )
    except Exception:
        pass

    return result


MAX_DOCUMENT_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB max upload ceiling to prevent OOM DoS


@api_router.post("/assistant/document-intelligence", response_model=DocumentIntelligenceResult)
def analyze_document_intelligence(
    req: DocumentIntelligenceRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Analyzes an uploaded document (PDF, DOCX, CSV, XLSX) provided as base64 or raw text.
    Extracts:
    1. Risks (Inherent & Residual 5x5 matrix scoring, causes, assets, consequences)
    2. Controls (Hygiene, implementation status, coverage, effort, teams, steps)
    3. Policies (DPDP Act 2023, RBI CSFS, ISO 27001, NIST CSF, PCI-DSS compliance gaps)
    4. Vulnerabilities (CVE IDs, CVSS scores, EPSS probabilities, CISA KEV, remediations)
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    if req.content_base64:
        try:
            file_bytes = base64.b64decode(req.content_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {e}")
    elif req.text_content:
        file_bytes = req.text_content.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Either 'content_base64' or 'text_content' must be provided.")

    if len(file_bytes) > MAX_DOCUMENT_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File payload size ({len(file_bytes) / (1024*1024):.1f}MB) exceeds maximum allowed limit of {MAX_DOCUMENT_UPLOAD_SIZE // (1024*1024)}MB."
        )

    return _ai_service.analyze_document(
        file_bytes=file_bytes,
        filename=req.filename,
        file_format=req.file_format,
        session_id=session_id,
        industry_sector=req.industry_sector
    )


@api_router.post("/assistant/document-intelligence/upload", response_model=DocumentIntelligenceResult)
async def upload_and_analyze_document(
    file: UploadFile = File(...),
    session_id: Optional[str] = Form(None),
    industry_sector: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None)
):
    """
    Multipart upload endpoint for Document Intelligence.
    Accepts PDF, DOCX, CSV, and XLSX files directly via drag-and-drop or file picker.
    Extracts risks, controls, policies, and vulnerabilities with Inherent vs Residual scoring.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    resolved_session_id = session_id or (f"user_{user_email}" if user_email else None)
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(file_bytes) > MAX_DOCUMENT_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file size ({len(file_bytes) / (1024*1024):.1f}MB) exceeds maximum allowed limit of {MAX_DOCUMENT_UPLOAD_SIZE // (1024*1024)}MB."
        )

    return _ai_service.analyze_document(
        file_bytes=file_bytes,
        filename=file.filename or "uploaded_document",
        file_format=None,
        session_id=resolved_session_id,
        industry_sector=industry_sector
    )


@api_router.post("/assistant/prioritize-risks", response_model=RiskPrioritizationResult)
def prioritize_risks_endpoint(
    req: RiskPrioritizationRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Ranks risks based on 4 quantitative pillars:
    - Severity (25% default)
    - Business Impact (35% default)
    - Urgency (25% default)
    - Existing Controls (15% default)
    Returns deterministic Risk Priority Index (RPI 0-100), P0-P3 action tiers, SLAs, and markdown dossier.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.prioritize_risks(
        custom_risks=req.custom_risks,
        weights=req.weights,
        industry_sector=req.industry_sector,
        session_id=session_id
    )


@api_router.get("/assistant/prioritize-risks", response_model=RiskPrioritizationResult)
def get_live_prioritized_risks(
    industry_sector: Optional[str] = None,
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieves live risk prioritization of enterprise assets and telemetry vulnerabilities.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    resolved_session_id = session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.prioritize_risks(
        custom_risks=None,
        weights=None,
        industry_sector=industry_sector,
        session_id=resolved_session_id
    )


@api_router.post("/assistant/scenario-analysis", response_model=ScenarioAnalysisResult)
def analyze_hypothetical_scenario(
    req: ScenarioAnalysisRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Answers hypothetical questions (e.g. "What happens if our primary server goes offline?"):
    Analyzes:
    1. Operational Blast Radius & Cascading Application Dependencies
    2. Open FAIR™ Financial Loss Quantification (Direct Downtime Losses, EAL & 95% VaR shift)
    3. Resilience Telemetry, Failover Readiness, and Single Points of Failure
    4. Phased Incident Response (0-2h, 2-6h, Hardening)
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.analyze_scenario(
        query=req.scenario_query,
        target_asset_id=req.target_asset_id,
        outage_hours=req.outage_hours,
        scenario_type=req.scenario_type,
        session_id=session_id,
        industry_sector=req.industry_sector
    )


@api_router.post("/assistant/root-cause-analysis", response_model=RootCauseAnalysisResult)
def perform_root_cause_analysis(
    req: RootCauseAnalysisRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Executes Root Cause Analysis (RCA) on an asset ID, live top risk, or custom described scenario:
    Identifies underlying architectural, IAM governance, process, and IaC drift causes,
    uncovers 5-Whys progressive depth decomposition, maps upstream/downstream dependencies,
    and formulates a phased Corrective and Preventive Action (CAPA) roadmap.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.analyze_root_cause(
        risk_description_or_id=req.risk_description_or_id,
        session_id=session_id,
        industry_sector=req.industry_sector
    )


@api_router.get("/assistant/root-cause-analysis", response_model=RootCauseAnalysisResult)
def get_live_top_risk_root_cause(
    industry_sector: Optional[str] = None,
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieves automated Root Cause Analysis on the active enterprise top risk asset.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    resolved_session_id = session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.analyze_root_cause(
        risk_description_or_id=None,
        session_id=resolved_session_id,
        industry_sector=industry_sector
    )


@api_router.post("/assistant/risk-monitoring/reassess", response_model=RiskMonitoringReassessmentResult)
def reassess_risk_monitoring(
    req: RiskMonitoringReassessmentRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Executes dynamic Risk Monitoring and Reassessment when assets, controls,
    incidents, or threat telemetry information mutate.
    Returns baseline vs post-update EAL/VaR metrics, posture drift, 5x5 matrix shifts,
    priority tier migrations, and audit trail entries.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.reassess_risk_monitoring(
        request=req,
        session_id=session_id
    )


@api_router.get("/assistant/risk-monitoring/status", response_model=RiskMonitoringReassessmentResult)
def get_risk_monitoring_status(
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieves the current continuous risk monitoring status and latest reassessment state.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    resolved_session_id = session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.reassess_risk_monitoring(
        request=None,
        session_id=resolved_session_id
    )


@api_router.post("/assistant/compliance-mapping", response_model=ComplianceMappingResult)
def perform_compliance_mapping(
    req: ComplianceMappingRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Compliance Assistant (Feature 11):
    Maps identified risks and controls to relevant frameworks:
    ISO/IEC 27001:2022, NIST CSF 2.0, RBI Cyber Security Framework,
    SEBI CSCRF, DPDP Act 2023, and CIS Controls v8.
    Quantifies regulatory penalties, audit gaps, and compensating controls.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.map_compliance_frameworks(
        request=req,
        session_id=session_id
    )


@api_router.get("/assistant/compliance-mapping", response_model=ComplianceMappingResult)
def get_enterprise_compliance_mapping(
    target_framework: Optional[str] = None,
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieves complete enterprise risk-to-framework and control crosswalk mappings.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    resolved_session_id = session_id or (f"user_{user_email}" if user_email else None)
    req = ComplianceMappingRequest(
        target_frameworks=[target_framework] if target_framework else None,
        session_id=resolved_session_id
    )

    return _ai_service.map_compliance_frameworks(
        request=req,
        session_id=resolved_session_id
    )


@api_router.post("/assistant/insights", response_model=AiInsightsResult)
def generate_ai_insights(
    req: AiInsightsRequest,
    authorization: Optional[str] = Header(None)
):
    """
    AI Insights (Feature 12):
    Identifies recurring risk patterns, weak/deficient controls, multi-horizon
    risk trend projections (30d, 60d, 90d), and actionable areas requiring
    executive management attention.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    session_id = req.session_id or (f"user_{user_email}" if user_email else None)

    return _ai_service.generate_ai_insights(
        request=req,
        session_id=session_id
    )


@api_router.get("/assistant/insights", response_model=AiInsightsResult)
def get_enterprise_ai_insights(
    focus_area: Optional[str] = "all",
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieves complete enterprise strategic AI Insights report.
    """
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    resolved_session_id = session_id or (f"user_{user_email}" if user_email else None)
    req = AiInsightsRequest(
        focus_area=focus_area,
        session_id=resolved_session_id
    )

    return _ai_service.generate_ai_insights(
        request=req,
        session_id=resolved_session_id
    )


@api_router.get("/assistant/preferences")
def get_assistant_preferences(
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """Returns learned contextual preferences and persona for the active session."""
    memory_store = get_memory_store()
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass
    prefs = memory_store.get_preferences(session_id=session_id, user_email=user_email)
    return {
        "session_id": session_id,
        "user_email": user_email,
        "preferences": prefs
    }


@api_router.get("/assistant/history")
def get_assistant_history(
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """Returns persistent conversation history for the session or authenticated user."""
    memory_store = get_memory_store()
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    history = memory_store.get_history(session_id=session_id, user_email=user_email)
    return {
        "session_id": session_id,
        "user_email": user_email,
        "total_messages": len(history),
        "messages": history
    }


@api_router.delete("/assistant/history")
def clear_assistant_history(
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    """Clears conversation memory for the session or authenticated user."""
    memory_store = get_memory_store()
    user_email = None
    if authorization:
        try:
            from backend.api.auth import _auth_store
            token = authorization.replace("Bearer ", "").strip()
            profile = _auth_store.get_user_by_token(token)
            if profile:
                user_email = profile.email
        except Exception:
            pass

    count = memory_store.clear_history(session_id=session_id, user_email=user_email)
    return {
        "message": "Conversation history cleared successfully.",
        "cleared_count": count
    }


@api_router.post("/assistant/nlp/retrain")
def retrain_nlp_model_endpoint(
    req: Optional[NlpRetrainRequest] = None,
    authorization: Optional[str] = Header(None)
):
    """Retrains the AI Neural Intent Classifier across 100 backpropagation epochs with 20x fine-tuned dataset."""
    _verify_admin_access(authorization)
    epochs = req.epochs if req and req.epochs else 100
    telemetry = _ai_service.retrain_nlp_model(epochs=epochs)
    return {
        "status": "success",
        "message": f"Successfully retrained AI NLP model for {epochs} epochs with 20x fine-tuning multiplier.",
        "telemetry": telemetry
    }


@api_router.get("/assistant/nlp/model-info")
def get_nlp_model_info_endpoint(
    authorization: Optional[str] = Header(None)
):
    """Returns AI NLP model architecture, 20x dataset statistics, and 100-epoch convergence status."""
    return _ai_service.get_nlp_model_info()


# ================= DATA IMPORT & EXPORT PIPELINE =================

class ImportDataRequest(BaseModel):
    format: str = "json"  # "json" or "csv"
    content: Optional[str] = None
    data: Optional[Any] = None
    dataset_name: Optional[str] = None      # e.g. "State Bank of XYZ", "Apex Healthcare"
    name: Optional[str] = None              # Alias for dataset_name
    organization: Optional[str] = None      # e.g. "State Bank of XYZ"
    sector: Optional[str] = None            # e.g. "Banking & Financial Services"
    overwrite: Optional[bool] = False       # Set to true to overwrite existing dataset if duplicate or collision


@api_router.get("/data/active-dataset")
def get_active_dataset_metadata():
    """Returns currently loaded dataset, target enterprise organization, and sector metadata."""
    return _telemetry_service.get_active_metadata()


@api_router.get("/data/export")
def export_data(
    format: str = Query("json", description="'json' or 'csv'"),
    type: str = Query("full", description="'full' (all risk quantification dossier) or 'assets' (only asset inventory)"),
    token: Optional[str] = Query(None, description="Optional bearer token for authenticated download"),
    authorization: Optional[str] = Header(None)
):
    """
    Exports enterprise assets or full Open FAIR™ risk quantification analysis dossier.
    Formats: JSON or CSV. Supports Bearer authorization header or token query parameter.
    """
    _verify_admin_access(authorization=authorization, token_query=token)
    if format.lower() == "csv":
        csv_text = _telemetry_service.export_assets_csv()
        filename = f"risklens_enterprise_assets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    # JSON export
    if type.lower() == "assets":
        return {
            "export_type": "assets",
            "count": len(_telemetry_service.get_all_assets()),
            "assets": _telemetry_service.export_assets_dict()
        }

    # Full dossier
    risk_summary = _risk_engine.run_enterprise_simulation()
    opt_result = _optimizer.optimize_security_investment(10000000.0)
    frameworks = _compliance_engine.get_all_framework_scores()
    active_meta = _telemetry_service.get_active_metadata()

    return {
        "export_type": "full_risk_dossier",
        "platform": "RiskLens Cyber Risk Quantification & Optimization",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "target_organization": active_meta.get("organization") or active_meta.get("name", "Enterprise Organization"),
        "sector": active_meta.get("sector", "Banking & Financial Services"),
        "is_custom_dataset": active_meta.get("is_custom", False),
        "currency_base": "INR",
        "usd_inr_rate": USD_INR_RATE,
        "quantified_risk": risk_summary.model_dump(),
        "investment_optimization": opt_result.model_dump(),
        "compliance_posture": [f.model_dump() for f in frameworks],
        "asset_inventory": _telemetry_service.export_assets_dict(),
        "initiatives_catalog": [i.model_dump() for i in _telemetry_service.get_all_initiatives()]
    }


def _verify_admin_access(authorization: Optional[str] = None, token_query: Optional[str] = None):
    """
    Validates authorization token for administrative operations (/data/import, /data/reset, /datasets/{id}/load).
    When RISKLENS_REQUIRE_AUTH is explicitly set to true/1/yes, a valid Bearer token is strictly required.
    If a Bearer token or token query parameter is provided in any mode, it is validated against the SQLite credential vault.
    """
    import os
    from backend.api.auth import _auth_store

    req_auth_env = os.environ.get("RISKLENS_REQUIRE_AUTH", "").lower().strip()
    if req_auth_env in ("true", "1", "yes"):
        require_auth = True
    elif req_auth_env in ("false", "0", "no"):
        require_auth = False
    else:
        # Default: authentication requirement is disabled unless explicitly activated
        require_auth = False

    token = None
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
    elif token_query:
        token = token_query.strip()

    if token:
        user = _auth_store.get_user_by_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired authorization token.")
        return user

    if require_auth:
        raise HTTPException(
            status_code=401,
            detail="Authentication required for administrative data operations. Please provide Authorization: Bearer <token>."
        )

    return None


@api_router.post("/data/import")
def import_data(req: ImportDataRequest, authorization: Optional[str] = Header(None)):
    """
    Imports real enterprise asset telemetry and vulnerabilities in JSON or CSV format.
    Strictly prevents duplicate data ingestion (identifies identical data even under different names)
    and persists the imported dataset and its assets into the SQLite backend database.
    """
    admin_user = _verify_admin_access(authorization)
    fmt = req.format.lower().strip()
    warnings = []

    try:
        if fmt == "csv":
            if not req.content or not req.content.strip():
                raise HTTPException(status_code=400, detail="CSV content string is required.")
            assets, warnings = _telemetry_service.import_from_csv(req.content)
        elif fmt == "json":
            raw = req.data
            if raw is None and req.content:
                raw = json.loads(req.content)
            if raw is None:
                raise HTTPException(status_code=400, detail="JSON payload or content string is required.")
            assets, warnings = _telemetry_service.import_from_json(raw)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format '{fmt}'. Choose 'json' or 'csv'.")

        if not assets:
            raise HTTPException(status_code=400, detail="No valid enterprise assets found in import payload.")

        entity_name = (req.dataset_name or req.name or req.organization or "").strip() or "Custom Enterprise Data"
        sector_name = (req.sector or "").strip() or "Banking & Financial Services"
        clean_id_suffix = re.sub(r'[^A-Za-z0-9]', '-', entity_name).upper()[:24].strip('-') or "DATA"
        dataset_id = f"CUSTOM-{clean_id_suffix}"

        # === DEDUPLICATION & CONFLICT DETECTION ===
        fingerprint = compute_asset_fingerprint(assets)
        ds_store = get_dataset_store()

        duplicate_conflict = ds_store.check_duplicate(fingerprint=fingerprint, name=entity_name)
        if duplicate_conflict:
            conflict_type = duplicate_conflict.get("conflict_type")
            existing_name = duplicate_conflict.get("existing_name")

            if conflict_type == "content":
                # Telemetry data is identical to an existing dataset
                if not req.overwrite:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"Duplicate dataset rejected: Identical asset inventory and vulnerability telemetry "
                            f"was already imported under '{existing_name}' "
                            f"({duplicate_conflict.get('asset_count', 0)} assets, {duplicate_conflict.get('total_cves', 0)} CVEs). "
                            f"Repeated imports of identical telemetry are prevented. "
                            f"If you intentionally want to update or re-record under '{entity_name}', check 'Overwrite Existing Dataset'."
                        )
                    )
            elif conflict_type == "name":
                # Dataset name already exists but content is different
                if not req.overwrite:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"Dataset name collision: A dataset named '{existing_name}' already exists in the database. "
                            f"Please provide a distinct dataset name (e.g. '{entity_name} v2') or check 'Overwrite Existing Dataset' to replace it."
                        )
                    )

        meta = {
            "id": dataset_id,
            "name": entity_name,
            "organization": entity_name,
            "sector": sector_name,
            "is_custom": True,
            "asset_count": len(assets),
            "imported_at": datetime.now().isoformat()
        }

        with _mutation_lock:
            # Save to persistent storage and active memory with custom entity metadata
            _telemetry_service.save_assets(assets, metadata=meta, persist=True)

            # Invalidate all simulation caches
            _risk_engine.invalidate_cache()
            _optimizer.invalidate_cache()
            _ai_service.invalidate_cache()
            _compliance_engine.invalidate_cache()

            # Re-compute new baseline risk immediately
            new_summary = _risk_engine.run_enterprise_simulation()
            _optimizer.compute_initiative_effectiveness()
            _optimizer.generate_efficient_frontier()
            _compliance_engine.get_all_framework_scores()

        # Persist dataset and its individual assets into backend SQLite database
        raw_payload = req.content if req.content else (json.dumps(req.data) if req.data else "")
        imported_by_user = admin_user.email if admin_user else "admin"
        ds_record = ds_store.save_imported_dataset(
            dataset_id=dataset_id,
            name=entity_name,
            sector=sector_name,
            format_type=fmt,
            assets=assets,
            fingerprint=fingerprint,
            raw_content=raw_payload,
            recalculated_eal=new_summary.expected_annual_loss_inr,
            risk_score=new_summary.enterprise_risk_score,
            imported_by=imported_by_user,
            overwrite=bool(req.overwrite)
        )

        total_cves = sum(len(a.vulnerabilities or []) for a in assets)

        return {
            "status": "success",
            "message": f"Successfully ingested and persisted {len(assets)} enterprise assets for '{entity_name}' in backend database.",
            "dataset_id": ds_record["dataset_id"],
            "dataset_name": entity_name,
            "organization": entity_name,
            "sector": sector_name,
            "imported_assets_count": len(assets),
            "total_cves_count": total_cves,
            "fingerprint": fingerprint,
            "stored_in_database": True,
            "warnings": warnings,
            "recalculated_risk": {
                "eal_inr": new_summary.expected_annual_loss_inr,
                "eal_usd": new_summary.expected_annual_loss_usd,
                "var_95_inr": new_summary.var_95_inr,
                "var_95_usd": new_summary.var_95_usd,
                "risk_score": new_summary.enterprise_risk_score
            }
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail=f"Data Import Error: {str(e)}")


@api_router.get("/data/imports")
def list_saved_datasets(authorization: Optional[str] = Header(None)):
    """
    Returns all enterprise datasets stored in the SQLite database.
    """
    _verify_admin_access(authorization)
    ds_store = get_dataset_store()
    return ds_store.list_imported_datasets()


@api_router.post("/data/imports/{dataset_id}/activate")
def activate_saved_dataset(dataset_id: str, authorization: Optional[str] = Header(None)):
    """
    Activates a previously imported dataset from the backend database into active memory.
    """
    _verify_admin_access(authorization)
    ds_store = get_dataset_store()
    loaded = ds_store.get_dataset(dataset_id)
    if not loaded:
        raise HTTPException(status_code=404, detail=f"Imported dataset '{dataset_id}' not found in database.")

    meta_row, assets = loaded
    meta = {
        "id": meta_row["dataset_id"],
        "name": meta_row["name"],
        "organization": meta_row["name"],
        "sector": meta_row["sector"],
        "is_custom": True,
        "asset_count": len(assets),
        "imported_at": meta_row["created_at"]
    }

    with _mutation_lock:
        _telemetry_service.save_assets(assets, metadata=meta, persist=True)
        _risk_engine.invalidate_cache()
        _optimizer.invalidate_cache()
        _ai_service.invalidate_cache()
        _compliance_engine.invalidate_cache()

        new_summary = _risk_engine.run_enterprise_simulation()
        _optimizer.compute_initiative_effectiveness()
        _optimizer.generate_efficient_frontier()
        _compliance_engine.get_all_framework_scores()

    return {
        "status": "success",
        "message": f"Dataset '{meta_row['name']}' activated from backend database.",
        "dataset_id": meta_row["dataset_id"],
        "dataset_name": meta_row["name"],
        "sector": meta_row["sector"],
        "asset_count": len(assets),
        "recalculated_risk": {
            "eal_inr": new_summary.expected_annual_loss_inr,
            "eal_usd": new_summary.expected_annual_loss_usd,
            "var_95_inr": new_summary.var_95_inr,
            "var_95_usd": new_summary.var_95_usd,
            "risk_score": new_summary.enterprise_risk_score
        }
    }


@api_router.delete("/data/imports/{dataset_id}")
def delete_saved_dataset(dataset_id: str, authorization: Optional[str] = Header(None)):
    """
    Deletes an imported dataset and its telemetry from the persistent database.
    """
    _verify_admin_access(authorization)
    ds_store = get_dataset_store()
    deleted = ds_store.delete_dataset(dataset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Imported dataset '{dataset_id}' not found in database.")
    return {
        "status": "success",
        "message": f"Dataset '{dataset_id}' successfully removed from database."
    }


@api_router.post("/data/reset")
def reset_data(authorization: Optional[str] = Header(None)):
    """
    Resets active asset inventory and telemetry back to the default banking benchmark dataset.
    """
    _verify_admin_access(authorization)
    with _mutation_lock:
        _telemetry_service.reset_to_default()
        _risk_engine.invalidate_cache()
        _optimizer.invalidate_cache()
        _ai_service.invalidate_cache()
        _compliance_engine.invalidate_cache()

        new_summary = _risk_engine.run_enterprise_simulation()
        _optimizer.compute_initiative_effectiveness()
        _optimizer.generate_efficient_frontier()
        _compliance_engine.get_all_framework_scores()

    return {
        "status": "success",
        "message": "Asset inventory and telemetry successfully reset to default benchmark dataset.",
        "assets_count": len(_telemetry_service.get_all_assets()),
        "recalculated_risk": {
            "eal_inr": new_summary.expected_annual_loss_inr,
            "risk_score": new_summary.enterprise_risk_score
        }
    }


@api_router.get("/data/template")
def get_data_template(format: str = Query("csv", description="'csv' or 'json'")):
    """
    Returns pre-formatted sample templates with column definitions for importing real company data.
    """
    if format.lower() == "csv":
        csv_text = _telemetry_service.get_csv_template()
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=risklens_asset_import_template.csv"}
        )
    return _telemetry_service.get_json_template()


# ================= 20 PRE-CONFIGURED INDUSTRY DATASETS =================

@api_router.get("/datasets")
def list_industry_datasets(include_custom: bool = Query(False, description="Optionally include custom stored datasets")):
    """Returns metadata for all 20 pre-configured enterprise industry datasets, optionally appending custom stored datasets."""
    presets = get_all_industry_datasets_metadata()
    if not include_custom:
        return presets

    try:
        ds_store = get_dataset_store()
        custom_list = ds_store.list_imported_datasets()
        custom_entries = []
        for c in custom_list:
            custom_entries.append({
                "id": f"CUSTOM:{c['dataset_id']}",
                "name": c["name"],
                "sector": c["sector"],
                "description": f"Custom imported enterprise dataset ({c['asset_count']} assets, {c['total_cves']} CVEs). Stored in SQLite.",
                "asset_count": c["asset_count"],
                "risk_profile": f"Custom Enterprise Telemetry • EAL: ₹{round(c['recalculated_eal_inr'], 2):,}",
                "regulatory_focus": ["Custom Assessment", "Enterprise FAIR"],
                "is_custom": True,
                "created_at": c["created_at"]
            })
        preset_dicts = [p if isinstance(p, dict) else p.model_dump() for p in presets]
        return custom_entries + preset_dicts
    except Exception:
        return presets


@api_router.get("/datasets/{dataset_id}")
def get_industry_dataset_details(dataset_id: str):
    """Returns metadata and asset inventory for a specific dataset ID or custom stored dataset."""
    clean_id = dataset_id.replace("CUSTOM:", "") if dataset_id.startswith("CUSTOM:") else dataset_id
    entry = get_industry_dataset_by_id(clean_id)
    if not entry:
        try:
            ds_store = get_dataset_store()
            loaded = ds_store.get_dataset(clean_id)
            if loaded:
                meta_row, assets = loaded
                return {
                    "metadata": {
                        "id": f"CUSTOM:{meta_row['dataset_id']}",
                        "name": meta_row["name"],
                        "sector": meta_row["sector"],
                        "description": f"Custom imported enterprise dataset with {len(assets)} assets.",
                        "asset_count": len(assets),
                        "total_cves": meta_row["total_cves"],
                        "risk_profile": f"Custom Enterprise Telemetry • EAL: ₹{round(meta_row['recalculated_eal_inr'], 2):,}",
                        "regulatory_focus": ["Custom Assessment", "Enterprise FAIR"],
                        "is_custom": True
                    },
                    "assets": [a.model_dump() for a in assets]
                }
        except Exception:
            pass
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")
    meta, assets = entry
    return {
        "metadata": meta.model_dump(),
        "assets": [a.model_dump() for a in assets]
    }


@api_router.post("/datasets/{dataset_id}/load")
def load_industry_dataset(dataset_id: str, authorization: Optional[str] = Header(None)):
    """
    Loads one of the 20 industry datasets or a custom imported dataset into active memory & disk,
    invalidates simulation caches, and recalculates enterprise FAIR risk metrics.
    """
    _verify_admin_access(authorization)
    clean_id = dataset_id.replace("CUSTOM:", "") if dataset_id.startswith("CUSTOM:") else dataset_id
    entry = get_industry_dataset_by_id(clean_id)
    if not entry:
        # Check if it's a stored custom dataset in SQLite
        ds_store = get_dataset_store()
        loaded = ds_store.get_dataset(clean_id)
        if loaded:
            return activate_saved_dataset(clean_id, authorization=authorization)
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")
    meta, assets = entry

    with _mutation_lock:
        meta_dict = {
            "id": meta.id,
            "name": meta.name,
            "organization": meta.name,
            "sector": meta.sector,
            "is_custom": False,
            "asset_count": len(assets)
        }
        # Save to persistent storage and active memory with preset metadata
        _telemetry_service.save_assets(assets, metadata=meta_dict, persist=True)

        # Invalidate all simulation caches
        _risk_engine.invalidate_cache()
        _optimizer.invalidate_cache()
        _ai_service.invalidate_cache()
        _compliance_engine.invalidate_cache()

        # Re-compute new baseline risk immediately
        new_summary = _risk_engine.run_enterprise_simulation()
        _optimizer.compute_initiative_effectiveness()
        _optimizer.generate_efficient_frontier()
        _compliance_engine.get_all_framework_scores()

    total_cves = sum(len(a.vulnerabilities) for a in assets)

    return {
        "status": "success",
        "message": f"Successfully loaded industry dataset: {meta.name} ({len(assets)} assets).",
        "loaded_dataset_id": meta.id,
        "name": meta.name,
        "sector": meta.sector,
        "risk_profile": meta.risk_profile,
        "asset_count": len(assets),
        "total_cves_count": total_cves,
        "recalculated_risk": {
            "eal_inr": new_summary.expected_annual_loss_inr,
            "eal_usd": new_summary.expected_annual_loss_usd,
            "var_95_inr": new_summary.var_95_inr,
            "var_95_usd": new_summary.var_95_usd,
            "risk_score": new_summary.enterprise_risk_score
        }
    }
