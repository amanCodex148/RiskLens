"""
AI Risk Identification Engine for RiskLens.
Enables users to describe a project, system, business process, or security incident,
and automatically analyzes and identifies:
1. Identified Potential Risks (Confidentiality, Integrity, Availability, Compliance, Financial).
2. Root Causes & Threat Attack Vectors.
3. Affected Crown Jewel Assets & Workloads (grounded in live telemetry).
4. Possible Consequences (Downtime financial loss, DPDP Act 2023 penalties, RBI/SEBI fines, customer churn).
5. Defensible Recommended Mitigations & 1-Click Actionable Controls.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

from backend.models.schemas import (
    RiskIdentificationRequest,
    RiskIdentificationResult,
    IdentifiedRiskItem,
    ConsequenceItem,
    RiskScoreProfile,
    OverallRiskScoring,
    MitigationRecommendation,
    CriticalityTier
)
from backend.ingestion.telemetry_loader import TelemetryService, USD_INR_RATE
from backend.engine.risk_engine import FairRiskEngine
from backend.engine.optimizer import InvestmentOptimizer

logger = logging.getLogger(__name__)


class AiRiskIdentifier:
    """
    Automated AI Risk Identification Engine.
    Maps free-form text descriptions of systems, projects, processes, or incidents
    to formal cybersecurity risk taxonomies, affected assets, and statutory consequences.
    """

    def __init__(
        self,
        telemetry_service: Optional[TelemetryService] = None,
        risk_engine: Optional[FairRiskEngine] = None,
        optimizer: Optional[InvestmentOptimizer] = None
    ):
        self.telemetry_service = telemetry_service or TelemetryService.get_instance()
        self.risk_engine = risk_engine or FairRiskEngine(iterations=1000)
        self.optimizer = optimizer or InvestmentOptimizer(risk_engine=self.risk_engine)

    def compute_risk_score(self, likelihood: int, impact: int) -> RiskScoreProfile:
        """
        Assesses risk using likelihood (1-5) and impact (1-5).
        Classifies risk as Critical (>=20), High (12-19), Medium (6-11), or Low (1-5).
        """
        l = max(1, min(5, int(likelihood)))
        i = max(1, min(5, int(impact)))
        score = l * i
        score_100 = round((score / 25.0) * 100.0, 1)

        l_labels = {
            1: "Rare (<10%)",
            2: "Unlikely (10-30%)",
            3: "Moderate (30-60%)",
            4: "Likely (60-85%)",
            5: "Almost Certain (>85%)"
        }
        i_labels = {
            1: "Negligible (<₹10L)",
            2: "Minor (₹10L-50L)",
            3: "Moderate (₹50L-2.5Cr)",
            4: "Major (₹2.5Cr-15Cr)",
            5: "Catastrophic (>₹15Cr / DPDP ₹250Cr)"
        }

        if score >= 20:
            classification = "Critical"
            badge = "🔴 Critical"
        elif score >= 12:
            classification = "High"
            badge = "🟠 High"
        elif score >= 6:
            classification = "Medium"
            badge = "🟡 Medium"
        else:
            classification = "Low"
            badge = "🟢 Low"

        return RiskScoreProfile(
            likelihood=l,
            likelihood_label=l_labels.get(l, f"Level {l}"),
            impact=i,
            impact_label=i_labels.get(i, f"Level {i}"),
            score=score,
            score_100=score_100,
            classification=classification,
            matrix_position={"likelihood": l, "impact": i, "row": l, "col": i},
            matrix_coord=f"L{l}:I{i}",
            badge=badge
        )

    def generate_5x5_markdown_matrix(
        self,
        inherent_l: int,
        inherent_i: int,
        residual_l: int,
        residual_i: int
    ) -> str:
        """
        Renders a 5x5 Enterprise Risk Matrix table in GitHub-flavored Markdown.
        Rows = Likelihood (5 down to 1), Columns = Impact (1 to 5).
        Highlights Inherent position and Residual position with badges.
        """
        lines = [
            "| Likelihood \\ Impact | 1 - Negligible | 2 - Minor | 3 - Moderate | 4 - Major | 5 - Catastrophic |",
            "|:---|:---:|:---:|:---:|:---:|:---:|"
        ]

        row_labels = {
            5: "5 - Almost Certain",
            4: "4 - Likely",
            3: "3 - Moderate",
            2: "2 - Unlikely",
            1: "1 - Rare"
        }

        for row_l in [5, 4, 3, 2, 1]:
            cells = [f"**{row_labels[row_l]}**"]
            for col_i in range(1, 6):
                score = row_l * col_i
                is_inh = (row_l == inherent_l and col_i == inherent_i)
                is_res = (row_l == residual_l and col_i == residual_i)

                if score >= 20:
                    tier_short = "🔴 Crit"
                elif score >= 12:
                    tier_short = "🟠 High"
                elif score >= 6:
                    tier_short = "🟡 Med"
                else:
                    tier_short = "🟢 Low"

                if is_inh and is_res:
                    cell_content = f"🔴 **CRIT ({score})**<br/>`[⚠️ INHERENT & 🛡️ RESIDUAL]`"
                elif is_inh:
                    cell_content = f"🔴 **{tier_short.split()[1].upper()} ({score})**<br/>`[⚠️ INHERENT]`"
                elif is_res:
                    cell_content = f"🟢 **{tier_short.split()[1].upper()} ({score})**<br/>`[🛡️ RESIDUAL]`"
                else:
                    cell_content = f"{tier_short} ({score})"

                cells.append(cell_content)
            lines.append("| " + " | ".join(cells) + " |")

        return "\n".join(lines)

    def generate_5x5_ascii_matrix(
        self,
        inherent_l: int,
        inherent_i: int,
        residual_l: int,
        residual_i: int
    ) -> str:
        """Renders a text-based ASCII 5x5 Risk Matrix representation."""
        lines = [
            "  Likelihood (1-5)",
            "     ▲",
        ]
        for row_l in [5, 4, 3, 2, 1]:
            row_str = f"  {row_l}  |"
            for col_i in range(1, 6):
                score = row_l * col_i
                is_inh = (row_l == inherent_l and col_i == inherent_i)
                is_res = (row_l == residual_l and col_i == residual_i)

                if is_inh and is_res:
                    cell_repr = f" [INH/RES:{score}]"
                elif is_inh:
                    cell_repr = f" [INH:{score}]⚠️"
                elif is_res:
                    cell_repr = f" [RES:{score}]🛡️"
                else:
                    tier = "C" if score >= 20 else ("H" if score >= 12 else ("M" if score >= 6 else "L"))
                    cell_repr = f"  {tier}({score:2d})  "
                row_str += cell_repr
            lines.append(row_str)
        lines.append("     +-------------------------------------------------------------►")
        lines.append("           1            2            3            4            5      Impact (1-5)")
        return "\n".join(lines)

    def identify_risks(
        self,
        description: str,
        session_id: Optional[str] = None,
        industry_sector: Optional[str] = None
    ) -> RiskIdentificationResult:
        """
        Analyzes user-provided description and returns structured risk identification.
        """
        text = description.strip()
        lower = text.lower()

        # Step 1: Classify scenario type
        scenario_type = self._classify_scenario_type(lower)

        # Step 2: Match affected assets from enterprise telemetry
        matched_assets = self._match_affected_assets(lower)

        # Step 3: Determine identified risks with inherent and residual scoring
        identified_risks, overall_severity = self._determine_risks(lower, scenario_type, matched_assets)

        # Step 4: Calculate overall inherent vs. residual scoring and 5x5 matrix
        if identified_risks:
            max_inh_l = max(r.inherent_risk.likelihood for r in identified_risks if r.inherent_risk)
            max_inh_i = max(r.inherent_risk.impact for r in identified_risks if r.inherent_risk)
            overall_inh = self.compute_risk_score(max_inh_l, max_inh_i)

            max_res_l = max(r.residual_risk.likelihood for r in identified_risks if r.residual_risk)
            max_res_i = max(r.residual_risk.impact for r in identified_risks if r.residual_risk)
            overall_res = self.compute_risk_score(max_res_l, max_res_i)
        else:
            overall_inh = self.compute_risk_score(5 if overall_severity == "CRITICAL" else 4, 5 if overall_severity == "CRITICAL" else 4)
            overall_res = self.compute_risk_score(2, 2)

        reduction_pct = round(((overall_inh.score - overall_res.score) / overall_inh.score) * 100.0, 1) if overall_inh.score > 0 else 0.0
        shift_summary = f"L{overall_inh.likelihood}:I{overall_inh.impact} (Score: {overall_inh.score} - {overall_inh.classification}) ➔ L{overall_res.likelihood}:I{overall_res.impact} (Score: {overall_res.score} - {overall_res.classification}) [-{reduction_pct:.1f}% Risk Reduction]"
        tolerance_status = "Within Enterprise Risk Appetite Post-Mitigation (Score ≤ 6)" if overall_res.score <= 6 else "Requires Residual Risk Acceptance / Exception"

        overall_scoring = OverallRiskScoring(
            inherent_risk=overall_inh,
            residual_risk=overall_res,
            risk_reduction_pct=reduction_pct,
            matrix_shift_summary=shift_summary,
            tolerance_status=tolerance_status
        )

        matrix_table_md = self.generate_5x5_markdown_matrix(
            overall_inh.likelihood, overall_inh.impact,
            overall_res.likelihood, overall_res.impact
        )
        matrix_ascii = self.generate_5x5_ascii_matrix(
            overall_inh.likelihood, overall_inh.impact,
            overall_res.likelihood, overall_res.impact
        )

        # Step 5: Extract root causes
        root_causes = self._determine_root_causes(lower, scenario_type)

        # Step 6: Compute possible consequences
        consequences, statutory_penalties = self._determine_consequences(lower, matched_assets, overall_severity)

        # Step 7: Formulate recommended mitigations ordered by priority
        mitigations = self._determine_mitigations(lower, scenario_type, matched_assets, identified_risks)

        # Attach per-risk mitigation recommendations
        for r in identified_risks:
            r.recommended_mitigations = [
                m for m in mitigations if (
                    m.target_risk.lower() in r.risk_title.lower() or
                    r.risk_title.lower() in m.target_risk.lower() or
                    (r.category == "Confidentiality" and "microseg" in m.initiative_id.lower()) or
                    (r.category == "Integrity" and ("mfa" in m.initiative_id.lower() or "vendor" in m.initiative_id.lower())) or
                    (r.category == "Compliance" and "patch" in m.initiative_id.lower()) or
                    (r.category == "Availability" and "backup" in m.initiative_id.lower())
                )
            ]
            if not r.recommended_mitigations and mitigations:
                r.recommended_mitigations = [mitigations[0]]

        # Step 8: Formulate executive summary
        summary = self._generate_executive_summary(
            description=text,
            scenario_type=scenario_type,
            risks=identified_risks,
            assets=matched_assets,
            severity=overall_severity
        )

        # Step 9: Build suggested actions
        actions = self._build_suggested_actions(scenario_type, matched_assets, mitigations)

        # Step 10: Render structured markdown report
        markdown_report = self._render_markdown_report(
            description=text,
            scenario_type=scenario_type,
            summary=summary,
            risks=identified_risks,
            root_causes=root_causes,
            assets=matched_assets,
            consequences=consequences,
            statutory_penalties=statutory_penalties,
            mitigations=mitigations,
            severity=overall_severity,
            actions=actions,
            overall_scoring=overall_scoring,
            matrix_grid_md=matrix_table_md
        )

        return RiskIdentificationResult(
            description=text,
            scenario_type=scenario_type,
            executive_summary=summary,
            identified_risks=identified_risks,
            root_causes=root_causes,
            affected_assets=matched_assets,
            consequences=consequences,
            statutory_penalties=statutory_penalties,
            recommended_mitigations=mitigations,
            overall_risk_severity=overall_severity,
            suggested_actions=actions,
            markdown_report=markdown_report,
            overall_scoring=overall_scoring,
            matrix_view=matrix_ascii,
            matrix_grid_markdown=matrix_table_md
        )

    def _classify_scenario_type(self, lower: str) -> str:
        """Classifies the input into a standard scenario domain."""
        if any(term in lower for term in ["publicly accessible", "open port", "exposed", "public internet", "no firewall", "unrestricted", "0.0.0.0", "misconfigured", "unencrypted"]):
            return "System Misconfiguration & Exposure"
        elif any(term in lower for term in ["phish", "clicked", "malware", "ransomware", "encrypt", "stolen", "leak", "compromised", "breached", "ddos", "incident"]):
            return "Active Security Incident & Breach"
        elif any(term in lower for term in ["migrat", "cloud", "aws", "azure", "gcp", "kubernetes", "k8s", "project", "deploying", "new system", "upgrad"]):
            return "Cloud Architecture & Transformation Project"
        elif any(term in lower for term in ["vendor", "third party", "supplier", "upload", "csv", "ftp", "process", "workflow", "contractor", "invoice"]):
            return "Business Process & Supply Chain Exposure"
        elif any(term in lower for term in ["password", "mfa", "credential", "shared account", "admin access", "privilege", "active directory", "iam"]):
            return "Identity & Access Management (IAM) Gap"
        elif any(term in lower for term in ["unpatched", "cve", "vulnerability", "legacy", "outdated", "end of life", "eol"]):
            return "Vulnerability & Patch Backlog"
        else:
            return "Enterprise Cyber Risk Assessment"

    def _match_affected_assets(self, lower: str) -> List[Dict[str, Any]]:
        """Matches enterprise assets based on semantic keywords."""
        all_assets = self.telemetry_service.get_all_assets()
        matched = []

        # Keyword mapping
        keywords_map = {
            "database": ["db", "database", "oracle", "sql", "postgres", "mongo", "mysql", "customer", "pii", "kyc", "vault"],
            "payment": ["payment", "switch", "transaction", "gateway", "swift", "upi", "checkout", "card"],
            "web": ["web", "api", "portal", "internet", "endpoint", "frontend", "public", "ingress"],
            "cloud": ["cloud", "s3", "bucket", "k8s", "kubernetes", "pod", "cluster", "aws", "azure", "container"],
            "identity": ["active directory", "ad", "domain", "ldap", "iam", "sso", "identity", "credential", "mfa", "admin"]
        }

        for asset in all_assets:
            aname = asset.name.lower()
            aid = asset.asset_id.lower()
            abu = (asset.business_unit.value if hasattr(asset.business_unit, 'value') else str(asset.business_unit)).lower()

            hit = False
            for cat, words in keywords_map.items():
                if any(w in lower for w in words):
                    if any(w in aname or w in aid or w in abu for w in words):
                        hit = True
                        break

            if hit:
                matched.append({
                    "asset_id": asset.asset_id,
                    "asset_name": asset.name,
                    "business_unit": asset.business_unit.value if hasattr(asset.business_unit, 'value') else str(asset.business_unit),
                    "criticality": asset.criticality.value if hasattr(asset.criticality, 'value') else str(asset.criticality),
                    "hourly_downtime_inr": asset.revenue_per_hour_inr,
                    "hourly_downtime_usd": round(asset.revenue_per_hour_inr / USD_INR_RATE, 2),
                    "pii_records_count": asset.pii_records_count,
                    "open_cves_count": len(asset.vulnerabilities),
                    "top_cve": asset.vulnerabilities[0].cve_id if asset.vulnerabilities else "None",
                    "cisa_kev_active": any(v.is_cisa_kev for v in asset.vulnerabilities)
                })

        # Fallback to highest criticality asset if no explicit keyword hit
        if not matched:
            top = all_assets[0] if all_assets else None
            if top:
                matched.append({
                    "asset_id": top.asset_id,
                    "asset_name": top.name,
                    "business_unit": top.business_unit.value if hasattr(top.business_unit, 'value') else str(top.business_unit),
                    "criticality": top.criticality.value if hasattr(top.criticality, 'value') else str(top.criticality),
                    "hourly_downtime_inr": top.revenue_per_hour_inr,
                    "hourly_downtime_usd": round(top.revenue_per_hour_inr / USD_INR_RATE, 2),
                    "pii_records_count": top.pii_records_count,
                    "open_cves_count": len(top.vulnerabilities),
                    "top_cve": top.vulnerabilities[0].cve_id if top.vulnerabilities else "None",
                    "cisa_kev_active": any(v.is_cisa_kev for v in top.vulnerabilities)
                })

        return matched

    def _determine_risks(
        self,
        lower: str,
        scenario_type: str,
        assets: List[Dict[str, Any]]
    ) -> Tuple[List[IdentifiedRiskItem], str]:
        """
        Identifies specific risk categories, assigns inherent risk (before controls)
        and residual risk (after controls), calculating likelihood, impact, score, and classification.
        """
        risks: List[IdentifiedRiskItem] = []
        is_critical = False

        # 1. Data Exposure / Exfiltration Risk
        if any(term in lower for term in ["publicly accessible", "database", "pii", "exposed", "leak", "unencrypted", "s3", "upload"]):
            inh = self.compute_risk_score(5, 5)
            res = self.compute_risk_score(1, 2)
            red = round(((inh.score - res.score) / inh.score) * 100.0, 1)
            risks.append(IdentifiedRiskItem(
                risk_title="Massive Data Exposure & Sensitive PII Exfiltration",
                category="Confidentiality",
                severity="CRITICAL",
                description="Unauthenticated threat actors, automated web scrapers, and botnets (e.g., Shodan, Shadowserver) can discover and exfiltrate raw database records without authentication barriers.",
                inherent_risk=inh,
                residual_risk=res,
                risk_reduction_pct=red
            ))
            is_critical = True

        # 2. Unauthorized Access & Credential Harvesting
        if any(term in lower for term in ["access", "publicly", "password", "mfa", "credential", "phish", "admin", "privilege"]):
            inh_l = 5 if is_critical else 4
            inh = self.compute_risk_score(inh_l, 4)
            res = self.compute_risk_score(2, 2)
            red = round(((inh.score - res.score) / inh.score) * 100.0, 1)
            risks.append(IdentifiedRiskItem(
                risk_title="Unauthorized System Ingress & Privilege Escalation",
                category="Integrity",
                severity="HIGH" if not is_critical else "CRITICAL",
                description="Direct network exposure allows brute-forcing, SQL injection, API abuse, and remote administrative command execution bypassing perimeter defenses.",
                inherent_risk=inh,
                residual_risk=res,
                risk_reduction_pct=red
            ))

        # 3. Regulatory & Statutory Non-Compliance Risk
        inh = self.compute_risk_score(4, 5)
        res = self.compute_risk_score(1, 2)
        red = round(((inh.score - res.score) / inh.score) * 100.0, 1)
        risks.append(IdentifiedRiskItem(
            risk_title="Statutory Regulatory Non-Compliance & Severe Sanctions",
            category="Compliance",
            severity="CRITICAL",
            description="Violates India's DPDP Act 2023 Section 8(5) (mandating reasonable security safeguards), RBI Cyber Security Framework Section 4 (DMZ architecture), and SEBI CSCRF controls.",
            inherent_risk=inh,
            residual_risk=res,
            risk_reduction_pct=red
        ))

        # 4. Ransomware & Data Destruction Risk
        if any(term in lower for term in ["database", "ransomware", "encrypt", "malware", "incident", "publicly", "unrestricted"]):
            inh = self.compute_risk_score(4, 4)
            res = self.compute_risk_score(1, 2)
            red = round(((inh.score - res.score) / inh.score) * 100.0, 1)
            risks.append(IdentifiedRiskItem(
                risk_title="Ransomware Extortion & Malicious Database Dropping",
                category="Availability",
                severity="HIGH",
                description="Automated extortion bots frequently drop publicly exposed databases, overwrite table partitions, and demand cryptocurrency ransom payments.",
                inherent_risk=inh,
                residual_risk=res,
                risk_reduction_pct=red
            ))

        # 5. Third-Party / Supply Chain Integrity Risk
        if any(term in lower for term in ["vendor", "third party", "upload", "csv", "supplier", "contractor"]):
            inh = self.compute_risk_score(4, 3)
            res = self.compute_risk_score(2, 2)
            red = round(((inh.score - res.score) / inh.score) * 100.0, 1)
            risks.append(IdentifiedRiskItem(
                risk_title="Untrusted Supply Chain Ingestion & Malicious Payload Delivery",
                category="Integrity",
                severity="HIGH",
                description="Allowing external uninspected file ingestion introduces malicious macros, reverse shells, and deserialization vulnerabilities into core processing workloads.",
                inherent_risk=inh,
                residual_risk=res,
                risk_reduction_pct=red
            ))

        # 6. Reputational & Customer Trust Risk
        inh = self.compute_risk_score(4, 4)
        res = self.compute_risk_score(1, 2)
        red = round(((inh.score - res.score) / inh.score) * 100.0, 1)
        risks.append(IdentifiedRiskItem(
            risk_title="Severe Reputational Damage & Customer Churn Liability",
            category="Reputational",
            severity="HIGH",
            description="Public disclosure or press coverage of an exposed customer repository leads to institutional brand erosion, customer litigation, and stock price discount.",
            inherent_risk=inh,
            residual_risk=res,
            risk_reduction_pct=red
        ))

        overall_severity = "CRITICAL" if is_critical or scenario_type in ["System Misconfiguration & Exposure", "Active Security Incident & Breach"] else "HIGH"
        return risks, overall_severity

    def _determine_root_causes(self, lower: str, scenario_type: str) -> List[str]:
        """Pinpoints root causes and threat vector origins."""
        causes = []

        if "publicly accessible" in lower or "exposed" in lower or "0.0.0.0" in lower:
            causes.append("Permissive Security Group / Firewall Rules: Ingress rule configured with `0.0.0.0/0` across database listening ports (e.g. 1521, 5432, 3306).")
            causes.append("Flawed Subnet Routing: Production database hosted on a public subnet with an assigned Public IP and direct Internet Gateway (IGW) route.")
            causes.append("Lack of Zero-Trust Segmentation: Missing software-defined enclaves isolating data persistence layers from external network ingress.")

        if "phish" in lower or "credential" in lower or "password" in lower:
            causes.append("Absence of Hardware-Backed FIDO2 MFA: Reliance on easily phished SMS, email OTP, or legacy password-only authentication.")
            causes.append("Lack of Domain Controller Hardening: Domain admin accounts lack workstation restrictions and tiered administrative separation.")

        if "vendor" in lower or "third party" in lower or "upload" in lower:
            causes.append("Unvetted Ingestion Architecture: Ingestion pipelines accept external files directly into production storage without automated sandboxing or antivirus scanning.")
            causes.append("Excessive Persistent Permissions: Third-party service accounts granted broad read/write permissions rather than scoped, short-lived STS tokens.")

        if "cloud" in lower or "migrat" in lower:
            causes.append("CI/CD Configuration Drift: Infrastructure-as-Code (Terraform/CloudFormation) lacked pre-deployment automated security linting (e.g. Checkov/Tfsec).")
            causes.append("Default Cloud IAM Privileges: Cloud IAM roles configured with wildcard `*` permissions across cloud storage and managed databases.")

        # Default standard causes
        if len(causes) < 2:
            causes.append("Inadequate Network Segmentation: Flat enterprise network topology lacking microsegmented DMZ boundaries.")
            causes.append("Missing Automated Posture Auditing: CSPM / continuous security scanning failed to alert on configuration anomalies.")

        return causes

    def _determine_consequences(
        self,
        lower: str,
        assets: List[Dict[str, Any]],
        severity: str
    ) -> Tuple[List[ConsequenceItem], List[str]]:
        """Quantifies financial, regulatory, and operational consequences."""
        consequences: List[ConsequenceItem] = []
        statutory_penalties: List[str] = []

        total_pii = sum(a.get("pii_records_count", 0) for a in assets) or 4500000
        max_hourly_downtime = max((a.get("hourly_downtime_inr", 0) for a in assets), default=3500000.0)

        # 1. Statutory Penalties
        statutory_penalties.append(
            "DPDP Act 2023 Section 33 Schedule: Statutory penalty of up to ₹250 Crore ($29.9M USD) for failure to implement reasonable security safeguards preventing a personal data breach."
        )
        statutory_penalties.append(
            "DPDP Act 2023 Section 8(6): Penalty of up to ₹200 Crore for failure to promptly notify the Data Protection Board of India and affected data principals."
        )
        statutory_penalties.append(
            "SEBI CSCRF Mandate: Mandatory reporting to CERT-In and SEBI within 6 hours of incident detection; regulatory audit inquiry and license suspension exposure."
        )
        statutory_penalties.append(
            "RBI Cyber Security Framework: Direct show-cause notices and supervisory enforcement actions under Banking Regulation Act Section 35A."
        )

        consequences.append(ConsequenceItem(
            impact_type="Statutory & Regulatory Liabilities",
            details=f"Severe financial penalty exposure under Section 33 of India's DPDP Act 2023 (up to ₹250 Cr) due to {total_pii:,} exposed customer PII records.",
            estimated_cost_inr=2500000000.0,
            estimated_cost_usd=round(2500000000.0 / USD_INR_RATE, 2)
        ))

        # 2. Operational Downtime
        est_downtime_hours = 24.0 if severity == "CRITICAL" else 8.0
        downtime_cost_inr = max_hourly_downtime * est_downtime_hours
        consequences.append(ConsequenceItem(
            impact_type="Operational Downtime & Business Interruption",
            details=f"Emergency containment, database isolation, forensic imaging, and system recovery estimated at {est_downtime_hours:.0f} hours of service outage (@ ₹{max_hourly_downtime:,.0f}/hr).",
            estimated_cost_inr=downtime_cost_inr,
            estimated_cost_usd=round(downtime_cost_inr / USD_INR_RATE, 2)
        ))

        # 3. Direct Incident Response & Forensics
        ir_cost_inr = 3500000.0
        consequences.append(ConsequenceItem(
            impact_type="Digital Forensics & Incident Response (DFIR)",
            details="Retaining specialized external third-party forensic investigators, forensic host analysis, compromised credential revocation, and log parsing.",
            estimated_cost_inr=ir_cost_inr,
            estimated_cost_usd=round(ir_cost_inr / USD_INR_RATE, 2)
        ))

        # 4. Customer Notification & Churn
        churn_cost_inr = 18000000.0
        consequences.append(ConsequenceItem(
            impact_type="Customer Notification & Attrition",
            details="Executing mandatory written breach communications to impacted customers, credit monitoring support, and customer attrition churn.",
            estimated_cost_inr=churn_cost_inr,
            estimated_cost_usd=round(churn_cost_inr / USD_INR_RATE, 2)
        ))

        return consequences, statutory_penalties

    def _determine_mitigations(
        self,
        lower: str,
        scenario_type: str,
        assets: List[Dict[str, Any]],
        identified_risks: Optional[List[IdentifiedRiskItem]] = None
    ) -> List[MitigationRecommendation]:
        """
        Recommends practical controls for each risk, strictly ordered by priority.
        Includes implementation steps, expected risk reduction, effort, and responsible team.
        """
        ctrl_microseg = MitigationRecommendation(
            priority=1,
            priority_label="P0 - Immediate Remediation",
            initiative_id="INIT-MICRO-05",
            title="Zero-Trust Network Microsegmentation & Ingress Enclave",
            target_risk="Massive Data Exposure & Sensitive PII Exfiltration",
            action_type="Immediate Technical Remediation",
            cost_inr=2500000.0,
            cost_usd=round(2500000.0 / USD_INR_RATE, 2),
            expected_risk_reduction_pct=82.0,
            expected_loss_reduction_inr=28300000.0,
            expected_loss_reduction_usd=round(28300000.0 / USD_INR_RATE, 2),
            rosi_pct=540.0,
            effort="Low (2-4 hours for ingress containment; 2 days for VPC enclave)",
            effort_level="Low",
            responsible_team="Cloud Infrastructure & Network SecOps",
            secondary_teams=["Database Administration (DBA)", "Site Reliability Engineering (SRE)"],
            implementation_steps=[
                "Immediate Ingress Containment: Revoke all `0.0.0.0/0` inbound security group rules on database ports (1521 Oracle, 5432 Postgres, 3306 MySQL).",
                "Subnet Realignment: Migrate database cluster to isolated private VPC subnets with routes pointing exclusively to NAT/Transit Gateways (no Internet Gateway).",
                "Mutual TLS Bastion Enclave: Deploy Envoy mTLS sidecars and require administrative sessions to transit a hardened bastion jump-host with session recording.",
                "PrivateLink / Internal Peering: Reconfigure microservices and API gateways to access the database strictly via AWS PrivateLink or internal VPC peering.",
                "External Ingress Validation: Execute external Nmap, Shodan, and Nessus scans to confirm zero external exposure on exposed IP addresses."
            ],
            verification_metric="External TCP SYN scan returns 'Filtered' or 'Closed' across all database listening ports; CSPM alerts clear to 0 open SG findings.",
            description="Block all direct internet ingress (`0.0.0.0/0`) to database subnets; place database inside private isolated VPC subnet accessible only via API Gateway and bastion jump-box with mTLS.",
            action_link="action:set_budget:2500000"
        )

        ctrl_mfa = MitigationRecommendation(
            priority=2,
            priority_label="P1 - High Priority",
            initiative_id="INIT-MFA-01",
            title="Universal Phishing-Resistant FIDO2 MFA Rollout",
            target_risk="Unauthorized System Ingress & Privilege Escalation",
            action_type="Identity Hardening",
            cost_inr=1500000.0,
            cost_usd=round(1500000.0 / USD_INR_RATE, 2),
            expected_risk_reduction_pct=74.0,
            expected_loss_reduction_inr=25500000.0,
            expected_loss_reduction_usd=round(25500000.0 / USD_INR_RATE, 2),
            rosi_pct=680.0,
            effort="Medium (1-2 weeks for organization-wide hardware token provisioning)",
            effort_level="Medium",
            responsible_team="Identity & Access Management (IAM) Team",
            secondary_teams=["IT Operations", "SecOps"],
            implementation_steps=[
                "Privileged Account Inventory: Enumerate 100% of DBA, cloud root, IAM administrator, and DevOps accounts with access to data stores.",
                "Enforce Hardware FIDO2 WebAuthn: Mandate physical hardware keys (YubiKey 5 Series / Google Titan) in Okta/Azure AD for privileged tiers.",
                "Deprecate Insecure Fallbacks: Disable SMS OTP, email verification codes, and push-notification approvals that are susceptible to AiTM phishing.",
                "Implement Just-In-Time (JIT) Privileges: Integrate HashiCorp Vault or AWS IAM Identity Center to issue time-limited (max 2-hour) database credentials.",
                "Continuous Identity Monitoring: Forward authentication telemetry to SIEM (Splunk/Sentinel) with alerts for abnormal login locations or multiple failed MFA challenges."
            ],
            verification_metric="100% of privileged administrator sessions authenticated via FIDO2 WebAuthn; 0 active legacy static passwords.",
            description="Mandate hardware security keys (YubiKey/FIDO2) across 100% of Database DBAs, Cloud IAM Admins, and DevOps engineers, neutralizing credential stuffing.",
            action_link="action:set_budget:1500000"
        )

        ctrl_patch = MitigationRecommendation(
            priority=3,
            priority_label="P1 - High Priority",
            initiative_id="INIT-PATCH-04",
            title="Automated Continuous Posture Auditing & DPDP Compliance Guardrails",
            target_risk="Statutory Regulatory Non-Compliance & Severe Sanctions",
            action_type="Continuous Configuration Management",
            cost_inr=1800000.0,
            cost_usd=round(1800000.0 / USD_INR_RATE, 2),
            expected_risk_reduction_pct=68.0,
            expected_loss_reduction_inr=23500000.0,
            expected_loss_reduction_usd=round(23500000.0 / USD_INR_RATE, 2),
            rosi_pct=490.0,
            effort="Medium (1-2 weeks for rule authoring and CI/CD policy gates)",
            effort_level="Medium",
            responsible_team="Governance, Risk & Compliance (GRC) & Cloud Security",
            secondary_teams=["DevSecOps", "Cloud Engineering"],
            implementation_steps=[
                "Deploy CSPM Guardrails: Activate AWS Config and Security Hub benchmark rules mapped to DPDP Act Section 8(5) and RBI CS Framework Section 4.",
                "Automated Ingress Remediation: Deploy Lambda auto-remediation playbooks to automatically quarantine any security group opening 0.0.0.0/0 within 60 seconds.",
                "PII Inventory & Column Encryption: Scan database tables using automated classification tools (e.g. AWS Macie); apply AES-256 client-side column encryption on PII fields.",
                "Audit Logging to WORM Storage: Stream CloudTrail, VPC Flow, and database audit logs to an encrypted, Write-Once-Read-Many (WORM) S3 bucket with 1-year retention.",
                "Regulatory Incident Playbook: Establish 6-hour CERT-In and Data Protection Board notification playbooks with pre-drafted notification templates."
            ],
            verification_metric="CSPM compliance posture score >= 95%; zero drift on security group rules over continuous 30-day monitoring.",
            description="Deploy automated CSPM posture guardrails that detect public S3 buckets, open security groups, and unpatched CVEs, auto-remediating violations within 5 minutes.",
            action_link="action:set_budget:1800000"
        )

        ctrl_backup = MitigationRecommendation(
            priority=4,
            priority_label="P2 - Medium Priority",
            initiative_id="INIT-BACKUP-03",
            title="Immutable Air-Gapped Database Backups",
            target_risk="Ransomware Extortion & Malicious Database Dropping",
            action_type="Resilience & Disaster Recovery",
            cost_inr=1200000.0,
            cost_usd=round(1200000.0 / USD_INR_RATE, 2),
            expected_risk_reduction_pct=62.0,
            expected_loss_reduction_inr=21400000.0,
            expected_loss_reduction_usd=round(21400000.0 / USD_INR_RATE, 2),
            rosi_pct=420.0,
            effort="Low (3-5 business days for vault lock and replica pairing)",
            effort_level="Low",
            responsible_team="Database Administration (DBA) & Site Reliability Engineering (SRE)",
            secondary_teams=["Backup Operations", "Disaster Recovery Team"],
            implementation_steps=[
                "Configure Immutable Backup Vault: Enable AWS Backup Vault Lock in Compliance Mode, prohibiting snapshot deletion even by root account users.",
                "Cross-Account Air-Gap Replication: Replicate daily encrypted database snapshots to an isolated secondary AWS account with separate IAM trust boundaries.",
                "Automated Recovery Testing: Execute scheduled weekly automated database restore drills to verify Recovery Time Objective (RTO < 2 hrs) and Point Objective (RPO < 15 min).",
                "Air-Gap Network Isolation: Restrict backup account ingress exclusively to private backup control endpoints without public internet connectivity."
            ],
            verification_metric="Successful non-destructive automated database recovery test completed in <90 minutes with zero data corruption.",
            description="Establish WORM (Write Once, Read Many) air-gapped snapshots to ensure instant recovery if database tables are dropped or encrypted by malicious actors.",
            action_link="action:set_budget:1200000"
        )

        ctrl_vendor = MitigationRecommendation(
            priority=1,
            priority_label="P0 - Immediate Remediation",
            initiative_id="INIT-VENDOR-02",
            title="Sandboxed External Ingestion Gateway & Scoped STS Token Broker",
            target_risk="Untrusted Supply Chain Ingestion & Malicious Payload Delivery",
            action_type="Supply Chain Isolation",
            cost_inr=1600000.0,
            cost_usd=round(1600000.0 / USD_INR_RATE, 2),
            expected_risk_reduction_pct=78.0,
            expected_loss_reduction_inr=26900000.0,
            expected_loss_reduction_usd=round(26900000.0 / USD_INR_RATE, 2),
            rosi_pct=510.0,
            effort="Medium (1 week for pipeline isolation and sandboxing)",
            effort_level="Medium",
            responsible_team="Application Security & Cloud Architecture",
            secondary_teams=["Vendor Management", "Data Engineering"],
            implementation_steps=[
                "Isolate Ingestion S3 Bucket: Establish a dedicated external file ingestion bucket in an isolated DMZ account disconnected from core production databases.",
                "Automated Antivirus & Sandboxing: Trigger event-driven file scanning (ClamAV / AWS GuardDuty Malware Protection) upon s3:ObjectCreated before downstream consumption.",
                "Short-Lived Temporary STS Credentials: Terminate permanent vendor API keys; issue short-lived (max 15-minute) STS tokens scoped to specific customer file prefixes.",
                "Schema & Payload Validation: Run automated CSV schema validation and deep content inspection to block malicious embedded formulas, macros, or binary exploits."
            ],
            verification_metric="100% of vendor uploads inspected in sandbox before ingestion; 0 static long-lived credentials assigned to external vendors.",
            description="Isolate external vendor file uploads into an unprivileged DMZ S3 bucket with automated antivirus sandboxing and short-lived STS tokens.",
            action_link="action:set_budget:1600000"
        )

        ctrl_iac = MitigationRecommendation(
            priority=1,
            priority_label="P0 - Immediate Remediation",
            initiative_id="INIT-IAC-01",
            title="Pre-Deployment Infrastructure-as-Code (IaC) Security Gate",
            target_risk="Cloud Architecture & Transformation Project",
            action_type="Automated Pipeline Security",
            cost_inr=1400000.0,
            cost_usd=round(1400000.0 / USD_INR_RATE, 2),
            expected_risk_reduction_pct=80.0,
            expected_loss_reduction_inr=27600000.0,
            expected_loss_reduction_usd=round(27600000.0 / USD_INR_RATE, 2),
            rosi_pct=560.0,
            effort="Medium (1 week for CI/CD linting integration and baseline scan)",
            effort_level="Medium",
            responsible_team="DevSecOps & Platform Engineering",
            secondary_teams=["Cloud Architecture", "SecOps"],
            implementation_steps=[
                "CI/CD Pipeline Linting: Integrate Checkov and Tfsec scanning into GitHub Actions/GitLab CI pipelines to fail builds containing open 0.0.0.0/0 rules or public IPs.",
                "Least-Privilege Cloud IAM: Generate least-privilege IAM policies using AWS IAM Access Analyzer instead of wildcard * permissions.",
                "EKS Pod Security Admission: Enforce Kubernetes Pod Security Standards (restricted mode) and Calico network policies isolating microservices.",
                "Automated Terraform Drift Detection: Run scheduled daily Terraform drift detection to alert on manual AWS console changes."
            ],
            verification_metric="100% of PRs scanned with 0 blocking high/critical misconfigurations; zero unmanaged cloud resource drift.",
            description="Enforce pre-merge automated security policy gates across Terraform and Kubernetes manifests to prevent cloud misconfigurations.",
            action_link="action:set_budget:1400000"
        )

        # Context-dependent priority ordering
        if scenario_type == "Business Process & Supply Chain Exposure" or "vendor" in lower or "third party" in lower or "upload" in lower:
            ctrl_vendor.priority = 1
            ctrl_vendor.priority_label = "P0 - Immediate Remediation"
            ctrl_mfa.priority = 2
            ctrl_mfa.priority_label = "P1 - High Priority"
            ctrl_patch.priority = 3
            ctrl_patch.priority_label = "P1 - High Priority"
            ctrl_backup.priority = 4
            ctrl_backup.priority_label = "P2 - Medium Priority"
            mitigations = [ctrl_vendor, ctrl_mfa, ctrl_patch, ctrl_backup]

        elif scenario_type == "Cloud Architecture & Transformation Project" or "migrat" in lower or "aws" in lower or "cloud" in lower:
            ctrl_iac.priority = 1
            ctrl_iac.priority_label = "P0 - Immediate Remediation"
            ctrl_microseg.priority = 2
            ctrl_microseg.priority_label = "P0 - Immediate Remediation"
            ctrl_patch.priority = 3
            ctrl_patch.priority_label = "P1 - High Priority"
            ctrl_mfa.priority = 4
            ctrl_mfa.priority_label = "P1 - High Priority"
            mitigations = [ctrl_iac, ctrl_microseg, ctrl_patch, ctrl_mfa]

        elif scenario_type == "Active Security Incident & Breach" or "phish" in lower or "credential" in lower:
            ctrl_mfa.priority = 1
            ctrl_mfa.priority_label = "P0 - Immediate Containment"
            ctrl_microseg.priority = 2
            ctrl_microseg.priority_label = "P0 - Immediate Containment"
            ctrl_patch.priority = 3
            ctrl_patch.priority_label = "P1 - High Priority"
            ctrl_backup.priority = 4
            ctrl_backup.priority_label = "P2 - Medium Priority"
            mitigations = [ctrl_mfa, ctrl_microseg, ctrl_patch, ctrl_backup]

        else:
            # Default / System Misconfiguration & Exposure
            ctrl_microseg.priority = 1
            ctrl_microseg.priority_label = "P0 - Immediate Remediation"
            ctrl_mfa.priority = 2
            ctrl_mfa.priority_label = "P1 - High Priority"
            ctrl_patch.priority = 3
            ctrl_patch.priority_label = "P1 - High Priority"
            ctrl_backup.priority = 4
            ctrl_backup.priority_label = "P2 - Medium Priority"
            mitigations = [ctrl_microseg, ctrl_mfa, ctrl_patch, ctrl_backup]

        mitigations.sort(key=lambda m: m.priority)
        return mitigations

    def _generate_executive_summary(
        self,
        description: str,
        scenario_type: str,
        risks: List[IdentifiedRiskItem],
        assets: List[Dict[str, Any]],
        severity: str
    ) -> str:
        """Synthesizes high-level executive decision brief."""
        asset_names = ", ".join(a["asset_name"] for a in assets[:2]) or "Enterprise Infrastructure"
        risk_titles = ", ".join(r.risk_title for r in risks[:3])

        return (
            f"The analyzed scenario ('{description}') represents a **{severity}** security exposure classified under "
            f"**{scenario_type}**. The primary threat surface threatens **{asset_names}**, creating critical exposure to "
            f"{risk_titles}. Without immediate defensive intervention, this condition exposes the enterprise to catastrophic "
            f"statutory penalties under India's DPDP Act 2023 (up to ₹250 Crore) and direct operational downtime exceeding "
            f"₹{assets[0].get('hourly_downtime_inr', 3500000):,.0f} per hour."
        )

    def _build_suggested_actions(
        self,
        scenario_type: str,
        assets: List[Dict[str, Any]],
        mitigations: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Builds interactive UI actions for fast 1-click execution."""
        actions = []
        if mitigations:
            best = mitigations[0]
            actions.append({
                "label": f"Deploy {best['title'][:32]}...",
                "action": f"action:set_budget:{int(best['cost_inr'])}"
            })
        actions.append({
            "label": "Simulate Ransomware Exposure",
            "action": "action:run_scenario:SCEN-RANSOM-CORE"
        })
        actions.append({
            "label": "View Compliance Gaps",
            "action": "action:tab:compliance"
        })
        actions.append({
            "label": "Inspect Crown Jewel Assets",
            "action": "action:tab:assets"
        })
        return actions

    def _render_markdown_report(
        self,
        description: str,
        scenario_type: str,
        summary: str,
        risks: List[IdentifiedRiskItem],
        root_causes: List[str],
        assets: List[Dict[str, Any]],
        consequences: List[ConsequenceItem],
        statutory_penalties: List[str],
        mitigations: List[Dict[str, Any]],
        severity: str,
        actions: List[Dict[str, str]],
        overall_scoring: Optional[OverallRiskScoring] = None,
        matrix_grid_md: Optional[str] = None
    ) -> str:
        """Renders comprehensive, cited executive report in GitHub-flavored Markdown."""
        sev_badge = "🔴 **CRITICAL SEVERITY**" if severity == "CRITICAL" else "🟠 **HIGH SEVERITY**"

        # Format risks table
        risks_md = []
        for idx, r in enumerate(risks, 1):
            badge = "`CRITICAL`" if r.severity == "CRITICAL" else "`HIGH`"
            inh_str = f"Inherent: {r.inherent_risk.badge} (`{r.inherent_risk.matrix_coord}`)" if r.inherent_risk else ""
            res_str = f"Residual: {r.residual_risk.badge} (`{r.residual_risk.matrix_coord}`)" if r.residual_risk else ""
            score_inline = f" | {inh_str} ➔ {res_str}" if (inh_str and res_str) else ""
            risks_md.append(f"{idx}. **{r.risk_title}** [{badge} - *{r.category}*{score_inline}]\n   • {r.description}")
        risks_text = "\n\n".join(risks_md)

        # Format Risk Scoring & Classification Table (Before vs. After Controls)
        scoring_table_rows = []
        for idx, r in enumerate(risks, 1):
            inh = r.inherent_risk or self.compute_risk_score(5, 5)
            res = r.residual_risk or self.compute_risk_score(2, 2)
            red = r.risk_reduction_pct if r.risk_reduction_pct is not None else round(((inh.score - res.score) / inh.score) * 100.0, 1)
            scoring_table_rows.append(
                f"| {idx} | **{r.risk_title}** | *{r.category}* | `L{inh.likelihood}×I{inh.impact}` | **{inh.score}/25** | {inh.badge} | `L{res.likelihood}×I{res.impact}` | **{res.score}/25** | {res.badge} | **-{red:.1f}%** |"
            )
        scoring_table_md = (
            "| # | Identified Potential Risk | Domain | Inherent (L×I) | Inherent Score | Inherent Tier | Residual (L×I) | Residual Score | Residual Tier | Net Reduction |\n"
            "|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|\n"
            + "\n".join(scoring_table_rows)
        )

        matrix_section = ""
        if overall_scoring and matrix_grid_md:
            matrix_section = (
                f"#### **Enterprise 5x5 Risk Matrix & Control Shift**\n\n"
                f"• **Matrix Shift**: `{overall_scoring.matrix_shift_summary}`\n"
                f"• **Portfolio Risk Reduction**: **-{overall_scoring.risk_reduction_pct:.1f}%** (from {overall_scoring.inherent_risk.badge} to {overall_scoring.residual_risk.badge})\n"
                f"• **Risk Tolerance Status**: *{overall_scoring.tolerance_status}*\n\n"
                f"{matrix_grid_md}\n\n"
                f"---\n\n"
                f"#### **Risk Scoring & Classification (Before & After Controls)**\n\n"
                f"{scoring_table_md}\n\n"
                f"---\n\n"
            )

        # Format causes
        causes_text = "\n".join([f"• **{c.split(':')[0]}**: {c.split(':')[1] if ':' in c else ''}" for c in root_causes])

        # Format assets
        assets_md = []
        for a in assets:
            assets_md.append(
                f"• **{a['asset_name']}** (`{a['asset_id']}`)\n"
                f"  - *Business Unit*: {a['business_unit']} | *Tier*: {a['criticality']}\n"
                f"  - *PII Records*: **{a['pii_records_count']:,} records** exposed\n"
                f"  - *Hourly Outage Cost*: **₹{a['hourly_downtime_inr']:,.0f} / hr** (${a['hourly_downtime_usd']:,.0f} USD/hr)\n"
                f"  - *Active Vulnerability*: `{a['top_cve']}`"
            )
        assets_text = "\n\n".join(assets_md)

        # Format consequences
        conseq_md = []
        for c in consequences:
            cost_str = f" — *Estimated Impact*: **₹{c.estimated_cost_inr:,.0f}** (${c.estimated_cost_usd:,.0f} USD)" if c.estimated_cost_inr else ""
            conseq_md.append(f"• **{c.impact_type}**{cost_str}\n  {c.details}")
        conseq_text = "\n\n".join(conseq_md)

        # Format statutory penalties
        penalties_text = "\n".join([f"• {p}" for p in statutory_penalties])

        # Format mitigations roadmap table
        mitig_table_rows = []
        for m in mitigations:
            p_badge = "🔴 **P0**" if m.priority == 1 else ("🟠 **P1**" if m.priority <= 3 else "🟡 **P2**")
            mitig_table_rows.append(
                f"| {p_badge} | **{m.title}** | `{m.initiative_id}` | *{m.target_risk}* | **{m.expected_risk_reduction_pct:.0f}%** | {m.effort} | `{m.responsible_team}` | **{m.rosi_pct:.0f}%** |"
            )
        mitig_table_md = (
            "| Priority | Recommended Practical Control | Initiative ID | Target Risk | Expected Risk Reduction | Effort | Responsible Team | ROSI |\n"
            "|:---:|:---|:---:|:---|:---:|:---|:---|:---:|\n"
            + "\n".join(mitig_table_rows)
        )

        # Format detailed actionable mitigation cards
        mitig_cards = []
        for m in mitigations:
            p_badge = "🔴 **P0 - Immediate Remediation**" if m.priority == 1 else ("🟠 **P1 - High Priority**" if m.priority <= 3 else "🟡 **P2 - Medium Priority**")
            sec_teams = f" *(Supporting: {', '.join(m.secondary_teams)})*" if m.secondary_teams else ""
            loss_red_str = f" (~₹{m.expected_loss_reduction_inr/100000:.1f} Lakhs loss reduction)" if m.expected_loss_reduction_inr else ""
            steps_md = "\n".join([f"    {i+1}. {step}" for i, step in enumerate(m.implementation_steps)])
            verif_str = f"\n  - *Verification Metric*: `{m.verification_metric}`" if m.verification_metric else ""

            mitig_cards.append(
                f"• **{m['title']}** (`{m['initiative_id']}`)\n"
                f"  - *Priority Order*: **Priority {m.priority}** ({p_badge}) | *Target Risk*: **{m.target_risk}**\n"
                f"  - *Cost*: **₹{m['cost_inr']/100000:.1f} Lakhs** (${m['cost_usd']:,.0f} USD) | *Expected Risk Reduction*: **{m['expected_risk_reduction_pct']:.0f}%**{loss_red_str} | *ROSI*: **{m['rosi_pct']:.0f}%**\n"
                f"  - *Implementation Effort*: **{m.effort}** | *Effort Level*: `{m.effort_level}`\n"
                f"  - *Responsible Team*: **{m.responsible_team}**{sec_teams}\n"
                f"  - *Remediation*: {m['description']}{verif_str}\n"
                f"  - *Actionable Implementation Steps*:\n{steps_md}"
            )
        mitig_cards_text = "\n\n".join(mitig_cards)
        mitig_text = f"{mitig_table_md}\n\n---\n\n{mitig_cards_text}"

        # Action links
        action_buttons = " | ".join([f"[{a['label']}]({a['action']})" for a in actions])

        return (
            f"### 🎯 **AI Cyber Risk Identification Report & 5x5 Risk Matrix**\n\n"
            f"**Scenario Analyzed**: *\"{description}\"*\n"
            f"**Classification**: `{scenario_type}` | {sev_badge}\n\n"
            f"#### **Executive Summary**\n"
            f"{summary}\n\n"
            f"---\n\n"
            f"{matrix_section}"
            f"#### **1. ⚠️ Identified Potential Risks**\n"
            f"{risks_text}\n\n"
            f"#### **2. 🔍 Root Causes & Threat Vectors**\n"
            f"{causes_text}\n\n"
            f"#### **3. 🎯 Affected Crown Jewel Assets & Workloads**\n"
            f"{assets_text}\n\n"
            f"#### **4. 💥 Possible Consequences & Financial Impact**\n"
            f"{conseq_text}\n\n"
            f"#### **5. ⚖️ Statutory & Regulatory Penalties**\n"
            f"{penalties_text}\n\n"
            f"#### **6. 🛡️ Recommended Mitigations & Remediation**\n"
            f"{mitig_text}\n\n"
            f"---\n\n"
            f"**1-Click Copilot Actions:**\n"
            f"{action_buttons}"
        )
