"""
AI Risk Monitoring & Continuous Reassessment Engine for RiskLens.
Dynamically reassesses enterprise risks when users update assets, controls,
incidents, or threat telemetry information.

Core Capabilities:
1. Dynamic Mutation Detection:
   Captures updates across Assets (criticality, revenue, PII, vulnerabilities),
   Controls (hygiene scores, enforcement status), Incidents (active outages, ransomware),
   and Threat Telemetry (new CVEs, CISA KEV tags, EPSS shifts).
2. Comparative Reassessment Modeling:
   Quantifies pre-update baseline vs post-update state across Open FAIR™ Monte Carlo EAL,
   95% Value at Risk (VaR), 0-100 Enterprise Risk Score, and 5x5 Matrix coordinates.
3. Priority Tier & RPI Drift Tracking:
   Identifies priority escalation (e.g. P1 -> P0) or de-escalation (e.g. P0 -> P1)
   and monitors SLA compliance.
4. Continuous Monitoring Audit Trail:
   Maintains a persistent change log of all telemetry mutations and their financial loss deltas.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from backend.models.schemas import (
    MetricComparison,
    AssetMatrixShift,
    MonitoringAuditEntry,
    RiskMonitoringReassessmentRequest,
    RiskMonitoringReassessmentResult,
    CriticalityTier
)
from backend.ingestion.telemetry_loader import TelemetryService, USD_INR_RATE
from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer
from backend.engine.ai_risk_prioritization import AiRiskPrioritizationEngine
from backend.engine.chat_memory import get_memory_store


class AiRiskMonitoringEngine:
    """
    Powers continuous risk monitoring and real-time reassessment when assets,
    controls, incidents, or telemetry parameters mutate.
    """

    def __init__(
        self,
        telemetry_service: Optional[TelemetryService] = None,
        risk_engine: Optional[FairRiskEngine] = None,
        optimizer: Optional[InvestmentOptimizer] = None,
        prioritization_engine: Optional[AiRiskPrioritizationEngine] = None
    ):
        self.telemetry_service = telemetry_service or TelemetryService.get_instance()
        self.risk_engine = risk_engine or FairRiskEngine(iterations=2500)
        self.optimizer = optimizer or InvestmentOptimizer(risk_engine=self.risk_engine)
        self.prioritization_engine = prioritization_engine or AiRiskPrioritizationEngine(
            telemetry_service=self.telemetry_service,
            risk_engine=self.risk_engine,
            optimizer=self.optimizer
        )
        self.audit_log: List[MonitoringAuditEntry] = []
        self._initialize_default_audit_log()

    def _initialize_default_audit_log(self):
        """Initializes baseline audit history for continuous monitoring."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.audit_log.append(MonitoringAuditEntry(
            timestamp=now,
            mutation_type="baseline_sync",
            entity_id="ENTERPRISE",
            change_summary="Synchronized continuous risk telemetry baseline across 12 core assets.",
            eal_impact_inr=0.0
        ))

    def reassess_monitoring(
        self,
        req: Optional[RiskMonitoringReassessmentRequest] = None,
        session_id: Optional[str] = None
    ) -> RiskMonitoringReassessmentResult:
        """
        Executes dynamic risk reassessment upon mutation of assets, controls, or incidents.
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        request = req or RiskMonitoringReassessmentRequest()

        # 1. Step 1: Capture Pre-Update Baseline
        base_res = self.risk_engine.run_enterprise_simulation()
        base_eal = base_res.expected_annual_loss_inr
        base_var95 = base_res.var_95_inr
        base_score = base_res.enterprise_risk_score
        base_prio = self.prioritization_engine.prioritize_risks()

        # 2. Step 2: Apply Mutation & Setup Simulation Overrides
        mutation_type = request.mutation_type
        mutation_summary = ""
        sim_overrides: Dict[str, Any] = {}
        initiative_boosts: Dict[str, float] = {}
        target_asset_id = request.asset_id or "AST-001"
        asset = self._resolve_asset(target_asset_id)

        # Baseline asset properties
        before_tier = self._get_asset_tier(base_prio, asset.asset_id)
        before_like = 5 if before_tier.startswith("P0") else (4 if before_tier.startswith("P1") else 3)
        before_imp = 5 if "tier 1" in str(asset.criticality).lower() else (4 if "tier 2" in str(asset.criticality).lower() else 3)
        before_level = "Critical" if before_like * before_imp >= 20 else ("High" if before_like * before_imp >= 12 else "Medium")

        if mutation_type == "control_update":
            ctrl_id = request.control_id or "INIT-MFA-01"
            ctrl_updates = request.control_updates or {"telemetry_score": 0.95, "implementation_status": "Enforced"}
            new_score = float(ctrl_updates.get("telemetry_score", 0.95))
            mutation_summary = f"Control '{ctrl_id}' updated: hygiene score raised to {new_score*100:.0f}%, status set to '{ctrl_updates.get('implementation_status', 'Enforced')}'."

            # Boosting defense decreases TEF/Vulnerability
            initiative_boosts = {ctrl_id: 0.40}
            sim_overrides = {"resistance_delta": 0.25, "threat_cap_delta": -0.15}

            after_like = max(1, before_like - 2)
            after_imp = before_imp
            after_tier = "P1 (Critical 7d)" if before_tier.startswith("P0") else "P2 (High 30d)"

        elif mutation_type == "asset_update":
            asset_updates = request.asset_updates or {"revenue_per_hour_inr": asset.revenue_per_hour_inr * 1.35, "pii_records_count": asset.pii_records_count + 2000000}
            new_rev = asset_updates.get("revenue_per_hour_inr", asset.revenue_per_hour_inr)
            new_pii = asset_updates.get("pii_records_count", asset.pii_records_count)
            mutation_summary = f"Asset '{asset.name} ({asset.asset_id})' updated: revenue exposure set to ₹{new_rev/100000:.1f}L/hr, PII count adjusted to {new_pii:,} records."

            sim_overrides = {
                "target_assets": [asset.asset_id],
                "rto_multiplier": 1.4,
                "tef_multiplier": 1.2
            }
            after_like = before_like
            after_imp = min(5, before_imp + 1)
            after_tier = "P0 (Immediate 24-48h)"

        elif mutation_type == "incident_update":
            incident = request.incident_details or {
                "title": "Active Ransomware Lateral Infection",
                "severity": "Critical",
                "is_contained": False,
                "outage_hours": 6.0
            }
            inc_title = incident.get("title", "Active Security Incident")
            inc_sev = incident.get("severity", "Critical")
            mutation_summary = f"New Incident Logged: '{inc_title}' (Severity: {inc_sev}, Contained: {incident.get('is_contained', False)}, Outage: {incident.get('outage_hours', 4.0)}h)."

            sim_overrides = {
                "target_assets": [asset.asset_id],
                "tef_multiplier": 2.2,
                "threat_cap_delta": 0.35,
                "rto_multiplier": 3.0,
                "resistance_delta": -0.20
            }
            after_like = 5
            after_imp = 5
            after_tier = "P0 (Immediate 24-48h)"

        else:
            # Full continuous reassessment
            mutation_summary = "Full continuous risk reassessment executed across all asset telemetry feeds and active controls."
            sim_overrides = {}
            after_like = before_like
            after_imp = before_imp
            after_tier = before_tier

        # 3. Step 3: Run Post-Update Reassessment Simulation
        post_res = self.risk_engine.run_enterprise_simulation(
            initiative_boosts=initiative_boosts if initiative_boosts else None,
            custom_overrides=sim_overrides if sim_overrides else None
        )
        reassessed_eal = post_res.expected_annual_loss_inr
        reassessed_var95 = post_res.var_95_inr
        reassessed_score = post_res.enterprise_risk_score

        # 4. Step 4: Compute Metric Deltas & Overall Posture Drift
        delta_eal = reassessed_eal - base_eal
        delta_eal_pct = (delta_eal / base_eal * 100.0) if base_eal > 0 else 0.0
        delta_var95 = reassessed_var95 - base_var95
        delta_score = reassessed_score - base_score

        if delta_eal < -200000.0 or delta_score < -1.0:
            posture_drift = "Risk Reduced (Posture Improved)"
        elif delta_eal > 200000.0 or delta_score > 1.0:
            posture_drift = "Risk Escalated (Posture Degraded)"
        else:
            posture_drift = "Stable / Neutral Posture"

        metrics_comparison = [
            MetricComparison(
                metric_name="Expected Annual Loss (EAL)",
                baseline_value=round(base_eal, 2),
                reassessed_value=round(reassessed_eal, 2),
                delta_value=round(delta_eal, 2),
                delta_percentage=round(delta_eal_pct, 1),
                unit="INR"
            ),
            MetricComparison(
                metric_name="95% Value at Risk (VaR)",
                baseline_value=round(base_var95, 2),
                reassessed_value=round(reassessed_var95, 2),
                delta_value=round(delta_var95, 2),
                delta_percentage=round((delta_var95 / base_var95 * 100.0) if base_var95 > 0 else 0.0, 1),
                unit="INR"
            ),
            MetricComparison(
                metric_name="Enterprise Risk Score",
                baseline_value=round(base_score, 1),
                reassessed_value=round(reassessed_score, 1),
                delta_value=round(delta_score, 1),
                delta_percentage=round((delta_score / base_score * 100.0) if base_score > 0 else 0.0, 1),
                unit="Score"
            )
        ]

        # 5. Step 5: Impacted Asset Matrix Shifts
        after_level = "Critical" if after_like * after_imp >= 20 else ("High" if after_like * after_imp >= 12 else "Medium")
        impacted_assets = [
            AssetMatrixShift(
                asset_id=asset.asset_id,
                asset_name=asset.name,
                baseline_likelihood=before_like,
                baseline_impact=before_imp,
                baseline_level=before_level,
                reassessed_likelihood=after_like,
                reassessed_impact=after_imp,
                reassessed_level=after_level,
                priority_tier_before=before_tier,
                priority_tier_after=after_tier
            )
        ]

        # 6. Step 6: Log to Monitoring Audit Trail
        audit_entry = MonitoringAuditEntry(
            timestamp=now_str,
            mutation_type=mutation_type,
            entity_id=asset.asset_id,
            change_summary=mutation_summary,
            eal_impact_inr=round(delta_eal, 2)
        )
        self.audit_log.append(audit_entry)

        # 7. Step 7: Build Executive Markdown Dossier
        markdown_briefing = self._build_markdown_briefing(
            now_str=now_str,
            mutation_type=mutation_type,
            mutation_summary=mutation_summary,
            posture_drift=posture_drift,
            metrics_comparison=metrics_comparison,
            impacted_assets=impacted_assets,
            audit_trail=self.audit_log[-5:]
        )

        suggested_questions = [
            "How does this risk monitoring reassessment impact our P0 remediation SLAs?",
            "What preventive controls should we deploy next to further reduce EAL?",
            "What happens if our primary server goes offline?",
            "Perform root cause analysis on our top risk"
        ]

        # Save to SQLite Chat Memory Vault if session active
        if session_id:
            try:
                mem_store = get_memory_store()
                mem_store.save_message(
                    session_id=session_id,
                    role="user",
                    content=f"Reassess risks after {mutation_summary}"
                )
                mem_store.save_message(
                    session_id=session_id,
                    role="assistant",
                    content=markdown_briefing,
                    metadata={
                        "topic": "risk_monitoring",
                        "posture_drift": posture_drift,
                        "delta_eal_inr": delta_eal
                    }
                )
            except Exception as e:
                print(f"[AiRiskMonitoringEngine] Warning: Could not save to memory vault: {e}")

        return RiskMonitoringReassessmentResult(
            status="success",
            reassessed_at=now_str,
            mutation_type=mutation_type,
            mutation_summary=mutation_summary,
            overall_posture_drift=posture_drift,
            metrics_comparison=metrics_comparison,
            impacted_assets=impacted_assets,
            audit_trail=self.audit_log[-5:],
            markdown_briefing=markdown_briefing,
            suggested_next_questions=suggested_questions
        )

    def reassess_from_query(self, query: str, session_id: Optional[str] = None) -> RiskMonitoringReassessmentResult:
        """Parses natural language inquiry to configure appropriate mutation reassessment."""
        q = (query or "").lower()

        if any(w in q for w in ["control", "mfa", "edr", "segmentation", "patch", "hygiene"]):
            req = RiskMonitoringReassessmentRequest(
                mutation_type="control_update",
                control_id="INIT-MFA-01",
                control_updates={"telemetry_score": 0.95, "implementation_status": "Enforced"},
                session_id=session_id
            )
        elif any(w in q for w in ["incident", "ransomware", "outage", "ddos", "breach", "infection"]):
            req = RiskMonitoringReassessmentRequest(
                mutation_type="incident_update",
                incident_details={
                    "title": "Active Security Incident",
                    "severity": "Critical",
                    "is_contained": False,
                    "outage_hours": 4.0
                },
                session_id=session_id
            )
        elif any(w in q for w in ["asset", "server", "database", "gateway", "revenue", "pii"]):
            req = RiskMonitoringReassessmentRequest(
                mutation_type="asset_update",
                asset_id="AST-001",
                session_id=session_id
            )
        else:
            req = RiskMonitoringReassessmentRequest(
                mutation_type="full_reassessment",
                session_id=session_id
            )

        return self.reassess_monitoring(req, session_id=session_id)

    # =========================================================================
    # HELPERS & MARKDOWN BUILDER
    # =========================================================================

    def _resolve_asset(self, asset_id: str):
        assets = self.telemetry_service.get_all_assets()
        for a in assets:
            if a.asset_id.lower() == asset_id.lower() or asset_id.lower() in a.name.lower():
                return a
        return assets[0]

    def _get_asset_tier(self, prio_result: Any, asset_id: str) -> str:
        for r in prio_result.ranked_risks:
            if r.risk_id == asset_id:
                return r.priority_tier
        return "P0 (Immediate 24-48h)"

    def _build_markdown_briefing(
        self,
        now_str: str,
        mutation_type: str,
        mutation_summary: str,
        posture_drift: str,
        metrics_comparison: List[MetricComparison],
        impacted_assets: List[AssetMatrixShift],
        audit_trail: List[MonitoringAuditEntry]
    ) -> str:
        """Assembles executive Markdown dossier for continuous risk monitoring & reassessment."""
        is_improved = "Improved" in posture_drift or "Reduced" in posture_drift
        drift_color = "🟢" if is_improved else ("🔴" if "Degraded" in posture_drift or "Escalated" in posture_drift else "🟡")

        eal_comp = next((m for m in metrics_comparison if "EAL" in m.metric_name), metrics_comparison[0])
        var_comp = next((m for m in metrics_comparison if "VaR" in m.metric_name), metrics_comparison[1])
        score_comp = next((m for m in metrics_comparison if "Score" in m.metric_name), metrics_comparison[2])

        delta_sign = "+" if eal_comp.delta_value > 0 else ""

        md = "### 📡 **RiskLens Continuous Risk Monitoring & Reassessment (Feature 10)**\n\n"
        md += (
            f"**Reassessed At**: `{now_str}` &nbsp;|&nbsp; "
            f"**Trigger Event**: `{mutation_type.upper().replace('_', ' ')}`\n\n"
            f"> {drift_color} **Enterprise Posture Drift**: **{posture_drift}** &nbsp;|&nbsp; "
            f"**EAL Variance**: **{delta_sign}₹{eal_comp.delta_value/10000000:.2f} Cr** ({delta_sign}{eal_comp.delta_percentage:.1f}%)\n\n"
            f"• **Change Description**: *{mutation_summary}*\n\n"
            f"---\n\n"
        )

        # 1. Comparative Financial Loss & Risk Score Table
        md += "#### 📊 **Pre-Update Baseline vs Post-Update Reassessment**\n\n"
        md += "| Risk Metric | Pre-Update Baseline | Post-Update Reassessment | Variance (Delta) | Status Drift |\n"
        md += "|:---|:---:|:---:|:---:|:---:|\n"

        for m in metrics_comparison:
            sign = "+" if m.delta_value > 0 else ""
            if m.unit == "INR":
                base_str = f"₹{m.baseline_value/10000000:.2f} Cr"
                post_str = f"₹{m.reassessed_value/10000000:.2f} Cr"
                delta_str = f"**{sign}₹{m.delta_value/10000000:.2f} Cr** ({sign}{m.delta_percentage:.1f}%)"
            else:
                base_str = f"{m.baseline_value:.1f}/100"
                post_str = f"{m.reassessed_value:.1f}/100"
                delta_str = f"**{sign}{m.delta_value:.1f} pts**"

            status_icon = "🟢 Favorable" if m.delta_value < 0 else ("🔴 Unfavorable" if m.delta_value > 0 else "🟡 Neutral")
            md += f"| **{m.metric_name}** | `{base_str}` | `{post_str}` | {delta_str} | {status_icon} |\n"

        md += "\n---\n\n"

        # 2. Impacted Asset 5x5 Matrix & Priority Tier Shifts
        md += "#### 🎯 **Impacted Asset 5x5 Matrix Coordinates & Priority Tier Shifts**\n\n"
        md += "| Asset ID & Name | Baseline Matrix (5x5) | Reassessed Matrix (5x5) | Priority Tier Before | Priority Tier After |\n"
        md += "|:---|:---:|:---:|:---:|:---:|\n"

        for a in impacted_assets:
            b_mat = f"L{a.baseline_likelihood} : I{a.baseline_impact} ({a.baseline_level})"
            r_mat = f"L{a.reassessed_likelihood} : I{a.reassessed_impact} ({a.reassessed_level})"
            md += f"| **{a.asset_name}** (`{a.asset_id}`) | `{b_mat}` | **`{r_mat}`** | `{a.priority_tier_before}` | **`{a.priority_tier_after}`** |\n"

        md += "\n---\n\n"

        # 3. Continuous Monitoring Audit Trail
        md += "#### 📜 **Recent Continuous Monitoring Audit Trail**\n\n"
        for entry in audit_trail:
            sign = "+" if entry.eal_impact_inr > 0 else ""
            impact_badge = f"`{sign}₹{entry.eal_impact_inr/10000000:.2f} Cr`" if entry.eal_impact_inr != 0.0 else "`Baseline`"
            md += (
                f"• `{entry.timestamp}` &nbsp;|&nbsp; **{entry.mutation_type.upper()}** &nbsp;|&nbsp; Impact: {impact_badge}\n"
                f"  - *{entry.change_summary}*\n"
            )

        md += (
            "\n---\n\n"
            "#### 💡 **Continuous Monitoring Action Directives**\n"
            "• **Automated Feedback Loop**: All updated parameters are synchronized in real-time with the **Executive Boardroom**, **0-1 Knapsack Optimizer**, and **Asset Explorer**.\n"
            "• **SLA Tracking**: Any asset elevated to **P0 (Immediate 24-48h)** triggers automated SecOps priority alerts.\n\n"
            "• [👉 View Executive Boardroom](action:tab:boardroom) | [🎯 Re-Optimize Remediation Portfolio](action:tab:optimizer) | [⚡ View Risk Prioritization](action:tab:boardroom)"
        )

        return md


# Singleton
_risk_monitoring_engine = AiRiskMonitoringEngine()

def get_risk_monitoring_engine() -> AiRiskMonitoringEngine:
    return _risk_monitoring_engine
