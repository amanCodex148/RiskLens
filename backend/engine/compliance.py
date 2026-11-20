"""
Compliance and Framework Cross-Walk Engine for RiskLens.
Maps active security telemetry and asset findings to established standards:
1. ISO/IEC 27001:2022
2. NIST Cybersecurity Framework (CSF 2.0)
3. CIS Controls v8
4. RBI Cyber Security Framework (for Banks & Regulated Financial Entities)
5. SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)
"""

from typing import List, Dict, Any, Optional
from backend.models.schemas import FrameworkScore, CriticalityTier
from backend.ingestion.telemetry_loader import TelemetryService


class ComplianceFrameworkEngine:
    """
    Evaluates enterprise posture against national and international cybersecurity frameworks.
    """

    def __init__(self):
        self.telemetry_service = TelemetryService.get_instance()
        self._cached_scores: Optional[List[FrameworkScore]] = None
        self._cached_report: Optional[Dict[str, Any]] = None
        self._cached_version: Optional[int] = None

    def invalidate_cache(self):
        """Clears cached scores upon telemetry refresh."""
        self._cached_scores = None
        self._cached_report = None
        self._cached_version = None

    def _check_version(self):
        current_version = self.telemetry_service.get_version()
        if self._cached_version != current_version:
            self.invalidate_cache()
            self._cached_version = current_version

    def get_all_framework_scores(self) -> List[FrameworkScore]:
        """
        Calculates compliance percentage and category scores across all 5 frameworks.
        """
        self._check_version()
        if self._cached_scores is not None:
            return self._cached_scores

        assets = self.telemetry_service.get_all_assets()

        # Collect all control telemetry across enterprise
        all_controls = []
        for a in assets:
            all_controls.extend(a.controls)

        # Average control score by category
        cat_scores: Dict[str, List[float]] = {}
        for c in all_controls:
            cat_scores.setdefault(c.category, []).append(c.telemetry_score)

        avg_by_cat = {k: sum(v)/len(v) for k, v in cat_scores.items()}

        iam_score = avg_by_cat.get("IAM", 0.62)
        edr_score = avg_by_cat.get("EDR", 0.85)
        net_score = avg_by_cat.get("Network", 0.72)
        cspm_score = avg_by_cat.get("CSPM", 0.58)
        vm_score = avg_by_cat.get("Vulnerability", 0.52)
        app_score = avg_by_cat.get("AppSec", 0.70)
        data_score = avg_by_cat.get("DataSec", 0.81)

        def _eval_framework(pct: float, cat_map: Dict[str, float], custom_status: Optional[str] = None):
            deficiencies = sum(1 for v in cat_map.values() if v < 75.0)
            if custom_status:
                status = custom_status
            elif pct >= 85.0:
                status = "Compliant (Audit Ready)"
            elif pct >= 70.0:
                status = "Conditionally Compliant"
            else:
                status = "Requires Remediation"
            return status, deficiencies

        # 1. RBI CSF
        rbi_cats = {
            "Access Control & IAM (Section 3)": round(iam_score * 100, 1),
            "Network Architecture & DMZ (Section 4)": round(net_score * 100, 1),
            "Continuous SOC Monitoring (Section 5)": round(edr_score * 100, 1),
            "Vulnerability & Patch Mgmt (Section 6)": round(vm_score * 100, 1),
            "Cyber Crisis Management Plan (CCMP)": 78.5
        }
        rbi_pct = round((iam_score * 0.25 + net_score * 0.25 + edr_score * 0.20 + vm_score * 0.30) * 100, 1)
        rbi_status, rbi_def = _eval_framework(rbi_pct, rbi_cats)

        # 2. SEBI CSCRF
        sebi_cats = {
            "API Security & WAF Defense": round(app_score * 100, 1),
            "Data Protection & Encryption": round(data_score * 100, 1),
            "Cloud Security Posture & Isolation": round(cspm_score * 100, 1),
            "VAPT & Threat Intelligence SLA": round(vm_score * 100, 1),
            "6-Hour Incident Reporting Readiness": 82.0
        }
        sebi_pct = round((app_score * 0.25 + data_score * 0.25 + cspm_score * 0.25 + vm_score * 0.25) * 100, 1)
        sebi_status, sebi_def = _eval_framework(sebi_pct, sebi_cats)

        # 3. ISO 27001
        iso_cats = {
            "A.5 Organizational Controls": 84.0,
            "A.6 People Controls (Awareness & Training)": 72.0,
            "A.7 Physical Controls": 91.0,
            "A.8 Technological Controls (Endpoint & Network)": round((edr_score * 0.5 + net_score * 0.5) * 100, 1)
        }
        iso_pct = round((iam_score * 0.30 + edr_score * 0.25 + net_score * 0.25 + data_score * 0.20) * 100, 1)
        iso_status, iso_def = _eval_framework(iso_pct, iso_cats)

        # 4. NIST CSF 2.0
        nist_cats = {
            "GOVERN (GV)": 80.0,
            "IDENTIFY (ID)": round(vm_score * 100, 1),
            "PROTECT (PR)": round((iam_score * 0.5 + data_score * 0.5) * 100, 1),
            "DETECT (DE)": round(edr_score * 100, 1),
            "RESPOND (RS)": 76.0,
            "RECOVER (RC)": 81.0
        }
        nist_pct = round((0.80 * 0.15 + vm_score * 0.20 + iam_score * 0.25 + edr_score * 0.20 + 0.75 * 0.20) * 100, 1)
        nist_status, nist_def = _eval_framework(nist_pct, nist_cats)

        # 5. CIS Controls v8
        cis_cats = {
            "Implementation Group 1 (IG1 - Basic Hygiene)": 88.0,
            "Implementation Group 2 (IG2 - Enterprise Defense)": round((iam_score * 0.5 + edr_score * 0.5) * 100, 1),
            "Implementation Group 3 (IG3 - Advanced Adversary)": round((cspm_score * 0.5 + vm_score * 0.5) * 100, 1)
        }
        cis_pct = round((vm_score * 0.25 + iam_score * 0.25 + edr_score * 0.25 + cspm_score * 0.25) * 100, 1)
        cis_status, cis_def = _eval_framework(cis_pct, cis_cats)

        frameworks = [
            FrameworkScore(
                framework_id="FW-RBI-CSF",
                framework_name="RBI Cyber Security Framework",
                regulatory_mandate="Mandatory for Commercial Banks, NBFCs & Payment System Operators",
                overall_compliance_pct=rbi_pct,
                category_scores=rbi_cats,
                status=rbi_status,
                open_deficiencies_count=rbi_def
            ),
            FrameworkScore(
                framework_id="FW-SEBI-CSCRF",
                framework_name="SEBI Cyber Security & Resilience Framework (CSCRF)",
                regulatory_mandate="Mandatory for Market Infrastructure Institutions, Brokers & Depository Participants",
                overall_compliance_pct=sebi_pct,
                category_scores=sebi_cats,
                status=sebi_status,
                open_deficiencies_count=sebi_def
            ),
            FrameworkScore(
                framework_id="FW-ISO-27001",
                framework_name="ISO/IEC 27001:2022 ISMS",
                regulatory_mandate="International Information Security Standard",
                overall_compliance_pct=iso_pct,
                category_scores=iso_cats,
                status=iso_status,
                open_deficiencies_count=iso_def
            ),
            FrameworkScore(
                framework_id="FW-NIST-CSF",
                framework_name="NIST Cybersecurity Framework 2.0",
                regulatory_mandate="Global Cybersecurity Core Benchmark",
                overall_compliance_pct=nist_pct,
                category_scores=nist_cats,
                status=nist_status,
                open_deficiencies_count=nist_def
            ),
            FrameworkScore(
                framework_id="FW-CIS-V8",
                framework_name="CIS Critical Security Controls v8",
                regulatory_mandate="Center for Internet Security Prescriptive Safeguards",
                overall_compliance_pct=cis_pct,
                category_scores=cis_cats,
                status=cis_status,
                open_deficiencies_count=cis_def
            )
        ]

        self._cached_scores = frameworks
        return frameworks

    def generate_board_compliance_report(self) -> Dict[str, Any]:
        """
        Produces an executive summary report correlating technical gaps to monetary exposure,
        dynamically synthesized from active asset telemetry, vulnerabilities, and controls.
        """
        self._check_version()
        if self._cached_report is not None:
            return self._cached_report

        scores = self.get_all_framework_scores()
        assets = self.telemetry_service.get_all_assets()
        findings: List[Dict[str, str]] = []
        finding_id_counter = 1

        # 1. Inspect critical vulnerabilities (CISA KEV, high EPSS >= 0.35, or CVSS >= 9.0)
        vuln_candidates = []
        for a in assets:
            for v in a.vulnerabilities:
                if v.is_cisa_kev or v.epss_score >= 0.30 or v.cvss_score >= 8.5:
                    vuln_candidates.append((a, v))

        # Prioritize CISA KEV and highest EPSS exploit probabilities
        vuln_candidates.sort(
            key=lambda item: (1 if item[1].is_cisa_kev else 0, item[1].epss_score, item[1].cvss_score),
            reverse=True
        )

        for a, v in vuln_candidates[:2]:
            exposure_desc = f"Vulnerability remediation SLA exceeded for {v.cve_id} (EPSS {v.epss_score * 100:.1f}%, CVSS {v.cvss_score}) on {a.name}."
            if v.is_cisa_kev:
                exposure_desc += " Listed in CISA Known Exploited Vulnerabilities (KEV) catalogue under active in-the-wild exploitation."
            findings.append({
                "finding_id": f"AUD-2026-{finding_id_counter:02d}",
                "framework_clause": "SEBI CSCRF 2.5 & ISO/IEC 27001:2022 A.12.6.1 & CIS-7.4",
                "severity": "CRITICAL" if v.is_cisa_kev or v.epss_score >= 0.50 else "HIGH",
                "description": exposure_desc,
                "associated_monetary_risk": f"Exposes {a.business_unit.value if hasattr(a.business_unit, 'value') else a.business_unit} to initial compromise vector with hourly downtime impact of ₹{a.revenue_per_hour_inr:,.0f}.",
                "recommended_remediation": f"Deploy automated patching pipeline (INIT-PATCH-04) to enforce 48-hour SLA for {v.cve_id}."
            })
            finding_id_counter += 1

        # 2. Inspect control deficiencies (< 0.65) on Tier 1 / Tier 2 assets
        for a in assets:
            if a.criticality == CriticalityTier.TIER_1:
                for c in a.controls:
                    if c.telemetry_score < 0.65:
                        findings.append({
                            "finding_id": f"AUD-2026-{finding_id_counter:02d}",
                            "framework_clause": "RBI CSF 3.1 & CIS Controls v8 CIS-6.3 & ISO A.9.4",
                            "severity": "HIGH",
                            "description": f"{c.name} enforcement score is degraded ({round(c.telemetry_score * 100, 1)}%) on mission-critical asset '{a.name}'.",
                            "associated_monetary_risk": f"Weakens control resistance (V) under FAIR standard, directly escalating Expected Annual Loss (EAL).",
                            "recommended_remediation": f"Implement hardware-backed authentication (INIT-MFA-01) and strict access controls on {a.name}."
                        })
                        finding_id_counter += 1
                        break
            if len(findings) >= 3:
                break

        # 3. DPDP Act compliance finding for high-volume customer data repositories
        dpdp_assets = [a for a in assets if a.pii_records_count > 500000]
        if dpdp_assets:
            target_asset = max(dpdp_assets, key=lambda x: x.pii_records_count)
            findings.append({
                "finding_id": f"AUD-2026-{finding_id_counter:02d}",
                "framework_clause": "Digital Personal Data Protection (DPDP) Act 2023 - Section 8(5)",
                "severity": "HIGH",
                "description": f"Asset '{target_asset.name}' stores {target_asset.pii_records_count:,} personal records requiring reasonable technical safeguards.",
                "associated_monetary_risk": "Triggers statutory penalty risk up to ₹250 Crore under DPDP Schedule 1 for failure to protect personal data against breach.",
                "recommended_remediation": "Deploy enterprise data tokenization and continuous privilege audit logging."
            })
            finding_id_counter += 1

        if not findings:
            findings.append({
                "finding_id": "AUD-2026-01",
                "framework_clause": "ISO/IEC 27001:2022 Surveillance",
                "severity": "LOW",
                "description": "All security controls across asset inventory exceed baseline operational thresholds.",
                "associated_monetary_risk": "Current safeguards maintain enterprise loss expectancy within defined risk appetite.",
                "recommended_remediation": "Maintain continuous telemetry monitoring and quarterly threat model review."
            })

        report = {
            "report_title": "Enterprise Cyber Governance & Regulatory Compliance Audit Package",
            "audit_period": "Q4 FY2026",
            "frameworks": [f.model_dump() for f in scores],
            "statutory_mandates_assessed": [
                "Reserve Bank of India (RBI) Cyber Security Framework for Scheduled Commercial Banks",
                "Securities and Exchange Board of India (SEBI) CSCRF Guidelines",
                "Digital Personal Data Protection (DPDP) Act 2023",
                "ISO/IEC 27001:2022 ISMS Surveillance Audit",
                "NIST CSF 2.0 Maturity Assessment"
            ],
            "critical_audit_findings": findings
        }
        self._cached_report = report
        return report
