"""
Telemetry Ingestion & Asset Inventory loader for RiskLens.
Simulates normalized ingestion from Vulnerability Scanners, SIEM, IAM, EDR, CSPM, and Threat Intel feeds.
"""

import os
import json
import csv
import io
import threading
from typing import List, Dict, Tuple, Optional, Any
from backend.models.schemas import (
    Asset, VulnerabilityFinding, ControlTelemetry,
    CriticalityTier, BusinessUnit, SecurityInitiative
)

USD_INR_RATE = 84.0  # 1 USD = 84 INR


def get_default_security_initiatives() -> List[SecurityInitiative]:
    """
    Standard candidate security investment initiatives with cost,
    targeted assets/controls, and estimated risk mitigation capability.
    """
    initiatives = [
        SecurityInitiative(
            initiative_id="INIT-MFA-01",
            title="Enterprise Phishing-Resistant FIDO2/MFA Rollout",
            category="Identity & Access Management (IAM)",
            cost_inr=2800000.0,  # ₹28 Lakhs
            cost_usd=round(2800000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-IAM-MFA", "CTRL-IAM-PAM"],
            target_asset_tiers=[CriticalityTier.TIER_1, CriticalityTier.TIER_2],
            target_assets=["AST-001", "AST-003", "AST-005"],
            resistance_boost=0.38,
            implementation_weeks=3,
            description="Enforces mandatory hardware/FIDO2 MFA for all domain admins, privileged database operators, and cloud root accounts, eradicating credential stuffing and session hijacking."
        ),
        SecurityInitiative(
            initiative_id="INIT-EDR-02",
            title="Full-Fleet Next-Gen EDR & 24/7 Managed MDR",
            category="Endpoint Detection & Response (EDR)",
            cost_inr=4200000.0,  # ₹42 Lakhs
            cost_usd=round(4200000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-EDR-COV", "CTRL-SIEM-VEL"],
            target_asset_tiers=[CriticalityTier.TIER_1, CriticalityTier.TIER_2, CriticalityTier.TIER_3],
            target_assets=["AST-001", "AST-002", "AST-004", "AST-005", "AST-008"],
            resistance_boost=0.32,
            implementation_weeks=4,
            description="Closes the 28% endpoint blindspot on legacy servers and deploys automated containment playbooks with a 15-minute SLA on active ransomware beaconing."
        ),
        SecurityInitiative(
            initiative_id="INIT-CSPM-03",
            title="Automated CSPM & Kubernetes Runtime Drift Remediation",
            category="Cloud Security Posture Management (CSPM)",
            cost_inr=3100000.0,  # ₹31 Lakhs
            cost_usd=round(3100000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-CSPM-AUD", "CTRL-NET-SEG"],
            target_asset_tiers=[CriticalityTier.TIER_1],
            target_assets=["AST-004", "AST-002", "AST-007"],
            resistance_boost=0.35,
            implementation_weeks=3,
            description="Continuous policy enforcement that auto-quarantines publicly exposed S3 buckets, blocks unauthorized ingress security groups, and enforces IMDSv2 across AWS & Azure."
        ),
        SecurityInitiative(
            initiative_id="INIT-PATCH-04",
            title="Automated Risk-Based Vulnerability Patching Pipeline",
            category="Vulnerability Management",
            cost_inr=2400000.0,  # ₹24 Lakhs
            cost_usd=round(2400000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-VM-SLA"],
            target_asset_tiers=[CriticalityTier.TIER_1, CriticalityTier.TIER_2],
            target_assets=["AST-001", "AST-002", "AST-003", "AST-007"],
            resistance_boost=0.29,
            implementation_weeks=2,
            description="Prioritizes and patches high-EPSS and CISA KEV vulnerabilities within 48 hours via automated CI/CD staging tests, slashing the average exploit exposure window from 47 days to 4 days."
        ),
        SecurityInitiative(
            initiative_id="INIT-MICRO-05",
            title="Zero-Trust Microsegmentation for Core Banking & Data",
            category="Network Security",
            cost_inr=5800000.0,  # ₹58 Lakhs
            cost_usd=round(5800000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-NET-SEG", "CTRL-DATA-ENC"],
            target_asset_tiers=[CriticalityTier.TIER_1],
            target_assets=["AST-001", "AST-003", "AST-006"],
            resistance_boost=0.42,
            implementation_weeks=6,
            description="Isolates the Core Banking transaction switch and Customer PII vault from general workstation VLANs, neutralizing lateral movement during ransomware attacks."
        ),
        SecurityInitiative(
            initiative_id="INIT-BACKUP-06",
            title="Immutable Air-Gapped Cloud & Tape Backup Architecture",
            category="Cyber Resilience & Business Continuity",
            cost_inr=3600000.0,  # ₹36 Lakhs
            cost_usd=round(3600000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-BCP-IMM", "CTRL-DATA-ENC"],
            target_asset_tiers=[CriticalityTier.TIER_1, CriticalityTier.TIER_2],
            target_assets=["AST-001", "AST-003", "AST-006", "AST-010"],
            resistance_boost=0.30,
            implementation_weeks=4,
            description="Deploys WORM (Write Once Read Many) immutable cloud object storage with separate encryption keys and physical air-gap isolation, guaranteeing rapid recovery without paying ransoms."
        ),
        SecurityInitiative(
            initiative_id="INIT-DLP-07",
            title="AI-Powered Sensitive Data Discovery & Tokenization (DPDP/SEBI)",
            category="Data Privacy & Compliance",
            cost_inr=2900000.0,  # ₹29 Lakhs
            cost_usd=round(2900000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-DATA-ENC", "CTRL-DLP-SEN"],
            target_asset_tiers=[CriticalityTier.TIER_1, CriticalityTier.TIER_2],
            target_assets=["AST-003", "AST-002", "AST-011"],
            resistance_boost=0.27,
            implementation_weeks=5,
            description="Scans on-prem and cloud datastores for cleartext Aadhaar, PAN, and cardholder data, substituting with cryptographic tokens to eliminate data breach penalty exposure under DPDP Act 2023."
        ),
        SecurityInitiative(
            initiative_id="INIT-WAF-08",
            title="Next-Gen API Security Shield & Distributed WAF",
            category="Application Security",
            cost_inr=1900000.0,  # ₹19 Lakhs
            cost_usd=round(1900000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-WAF-API"],
            target_asset_tiers=[CriticalityTier.TIER_1, CriticalityTier.TIER_2],
            target_assets=["AST-002", "AST-007"],
            resistance_boost=0.24,
            implementation_weeks=2,
            description="Deploys behavioral API anomaly detection and rate-limiting to protect Payment Gateway and Mobile Banking APIs against BOLA (Broken Object Level Auth) and bot scrapers."
        ),
        SecurityInitiative(
            initiative_id="INIT-PAM-09",
            title="Privileged Access Management (PAM) Just-In-Time Vaulting",
            category="Identity & Access Management (IAM)",
            cost_inr=3400000.0,  # ₹34 Lakhs
            cost_usd=round(3400000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-IAM-PAM"],
            target_asset_tiers=[CriticalityTier.TIER_1],
            target_assets=["AST-001", "AST-004", "AST-005", "AST-006"],
            resistance_boost=0.33,
            implementation_weeks=4,
            description="Eliminates static root/admin passwords across domain controllers, databases, and Linux bastions by requiring ephemeral, biometric-approved just-in-time checkouts."
        ),
        SecurityInitiative(
            initiative_id="INIT-TRAIN-10",
            title="Continuous Phishing Simulation & Human Risk Engineering",
            category="Security Awareness",
            cost_inr=1200000.0,  # ₹12 Lakhs
            cost_usd=round(1200000.0 / USD_INR_RATE, 2),
            target_controls=["CTRL-HUMAN-RISK"],
            target_asset_tiers=[CriticalityTier.TIER_2, CriticalityTier.TIER_3],
            target_assets=["AST-008", "AST-010", "AST-011"],
            resistance_boost=0.18,
            implementation_weeks=2,
            description="Conducts AI-personalized spear-phishing drills targeting finance and operations personnel to cut initial access click rates from 19.4% down to under 2.5%."
        )
    ]
    return initiatives


def get_default_enterprise_assets() -> List[Asset]:
    """
    Returns 12 realistic enterprise banking & fintech assets with real-world CVEs,
    criticality tiers, financial downtime costs, and live control telemetry.
    """
    assets = [
        # 1. Core Banking Switch (Tier 1 Crown Jewel)
        Asset(
            asset_id="AST-001",
            name="Core Banking Transaction Switch (Finacle)",
            business_unit=BusinessUnit.RETAIL_BANKING,
            criticality=CriticalityTier.TIER_1,
            revenue_per_hour_inr=3500000.0,  # ₹35 Lakhs / hr downtime
            pii_records_count=8500000,
            data_classification="Highly Restricted / PCI-DSS",
            rto_hours=1.0,
            rpo_hours=0.25,
            ip_or_endpoint="10.200.10.15",
            cloud_provider="Hybrid On-Prem / AWS DirectConnect",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-IAM-MFA",
                    name="Privileged Multi-Factor Authentication",
                    category="IAM",
                    framework_mappings={
                        "ISO_27001": ["A.9.4.2"], "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
                        "CIS_V8": ["CIS-6.3", "CIS-6.4"], "RBI": ["RBI-3.1", "RBI-3.2"], "SEBI": ["CSCRF-1.4"]
                    },
                    telemetry_score=0.62,
                    implementation_status="Partially Enforced",
                    description="MFA enforced for remote VPN, but bypassed on internal bastion jumps."
                ),
                ControlTelemetry(
                    control_id="CTRL-EDR-COV",
                    name="Endpoint Detection & Response (EDR)",
                    category="EDR",
                    framework_mappings={
                        "ISO_27001": ["A.12.2.1"], "NIST_CSF": ["DE.CM-1"],
                        "CIS_V8": ["CIS-10.1"], "RBI": ["RBI-5.1"], "SEBI": ["CSCRF-3.2"]
                    },
                    telemetry_score=0.88,
                    implementation_status="Enforced"
                ),
                ControlTelemetry(
                    control_id="CTRL-NET-SEG",
                    name="Network Microsegmentation",
                    category="Network",
                    framework_mappings={
                        "ISO_27001": ["A.13.1.3"], "NIST_CSF": ["PR.AC-5"],
                        "CIS_V8": ["CIS-12.2"], "RBI": ["RBI-4.2"], "SEBI": ["CSCRF-2.1"]
                    },
                    telemetry_score=0.55,
                    implementation_status="Degraded"
                ),
                ControlTelemetry(
                    control_id="CTRL-VM-SLA",
                    name="Risk-Based Vulnerability Remediation SLA",
                    category="Vulnerability",
                    framework_mappings={
                        "ISO_27001": ["A.12.6.1"], "NIST_CSF": ["ID.RA-1"],
                        "CIS_V8": ["CIS-7.1"], "RBI": ["RBI-6.1"], "SEBI": ["CSCRF-2.5"]
                    },
                    telemetry_score=0.48,
                    implementation_status="Overdue Backlog"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-4966",
                    asset_id="AST-001",
                    title="Citrix Bleed - NetScaler ADC Sensitive Information Disclosure",
                    cvss_score=9.4,
                    epss_score=0.942,
                    is_cisa_kev=True,
                    days_open=42,
                    attack_vector="Network"
                ),
                VulnerabilityFinding(
                    cve_id="CVE-2024-21887",
                    asset_id="AST-001",
                    title="Ivanti Connect Secure Command Injection Vulnerability",
                    cvss_score=9.1,
                    epss_score=0.895,
                    is_cisa_kev=True,
                    days_open=28,
                    attack_vector="Network"
                )
            ]
        ),

        # 2. Payment Gateway API (Tier 1 Crown Jewel)
        Asset(
            asset_id="AST-002",
            name="UPI & Card Payment Gateway API",
            business_unit=BusinessUnit.RETAIL_BANKING,
            criticality=CriticalityTier.TIER_1,
            revenue_per_hour_inr=2800000.0,
            pii_records_count=12000000,
            data_classification="PCI-DSS / Critical",
            rto_hours=0.5,
            rpo_hours=0.1,
            ip_or_endpoint="api.pay.bank.internal",
            cloud_provider="AWS",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-WAF-API",
                    name="WAF & API Threat Defense",
                    category="AppSec",
                    framework_mappings={"ISO_27001": ["A.14.2.5"], "NIST_CSF": ["PR.PT-4"], "RBI": ["RBI-4.3"], "SEBI": ["CSCRF-2.3"]},
                    telemetry_score=0.72,
                    implementation_status="Enforced"
                ),
                ControlTelemetry(
                    control_id="CTRL-CSPM-AUD",
                    name="Cloud Posture & IAM Least Privilege",
                    category="CSPM",
                    framework_mappings={"ISO_27001": ["A.9.2.3"], "NIST_CSF": ["PR.AC-4"], "CIS_V8": ["CIS-5.1"], "SEBI": ["CSCRF-2.2"]},
                    telemetry_score=0.60,
                    implementation_status="Warning - Ingress Open"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-34362",
                    asset_id="AST-002",
                    title="MOVEit Transfer SQL Injection Remote Code Execution",
                    cvss_score=9.8,
                    epss_score=0.971,
                    is_cisa_kev=True,
                    days_open=35,
                    attack_vector="Network"
                )
            ]
        ),

        # 3. Customer PII & Accounts Master Database (Tier 1 Crown Jewel)
        Asset(
            asset_id="AST-003",
            name="Customer Master PII & KYC Vault (Oracle Exadata)",
            business_unit=BusinessUnit.RETAIL_BANKING,
            criticality=CriticalityTier.TIER_1,
            revenue_per_hour_inr=1800000.0,
            pii_records_count=14500000,
            data_classification="DPDP Highly Sensitive PII",
            rto_hours=2.0,
            rpo_hours=0.5,
            ip_or_endpoint="10.200.20.50",
            cloud_provider="On-Premises Datacenter",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-DATA-ENC",
                    name="Transparent Data Encryption (TDE) & Key Management",
                    category="DataSec",
                    framework_mappings={"ISO_27001": ["A.10.1.1"], "NIST_CSF": ["PR.DS-1"], "CIS_V8": ["CIS-3.11"], "RBI": ["RBI-3.4"], "SEBI": ["CSCRF-2.4"]},
                    telemetry_score=0.85,
                    implementation_status="Enforced"
                ),
                ControlTelemetry(
                    control_id="CTRL-IAM-PAM",
                    name="Privileged Access Management (PAM) Vaulting",
                    category="IAM",
                    framework_mappings={"ISO_27001": ["A.9.4.4"], "NIST_CSF": ["PR.AC-6"], "CIS_V8": ["CIS-5.4"], "RBI": ["RBI-3.3"], "SEBI": ["CSCRF-1.5"]},
                    telemetry_score=0.58,
                    implementation_status="Shared DBA Creds Detected"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2021-44228",
                    asset_id="AST-003",
                    title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                    cvss_score=10.0,
                    epss_score=0.975,
                    is_cisa_kev=True,
                    days_open=65,
                    attack_vector="Network"
                )
            ]
        ),

        # 4. Production Kubernetes Cluster (Tier 1 Crown Jewel)
        Asset(
            asset_id="AST-004",
            name="Production EKS Cloud Microservices Cluster",
            business_unit=BusinessUnit.CLOUD_INFRASTRUCTURE,
            criticality=CriticalityTier.TIER_1,
            revenue_per_hour_inr=2200000.0,
            pii_records_count=3500000,
            data_classification="Confidential",
            rto_hours=1.5,
            rpo_hours=0.5,
            ip_or_endpoint="k8s.prod.cluster.aws",
            cloud_provider="AWS",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-CSPM-AUD",
                    name="Kubernetes Admission & CSPM Drift Control",
                    category="CSPM",
                    framework_mappings={"ISO_27001": ["A.12.1.2"], "NIST_CSF": ["PR.IP-1"], "CIS_V8": ["CIS-4.1"], "SEBI": ["CSCRF-2.2"]},
                    telemetry_score=0.52,
                    implementation_status="Privileged Pods Allowed"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-5043",
                    asset_id="AST-004",
                    title="Ingress-NGINX Incomplete Annotations Bypass RCE",
                    cvss_score=9.8,
                    epss_score=0.824,
                    is_cisa_kev=True,
                    days_open=19,
                    attack_vector="Network"
                )
            ]
        ),

        # 5. Active Directory Domain Controllers (Tier 1 Crown Jewel)
        Asset(
            asset_id="AST-005",
            name="Enterprise Active Directory Domain Controllers",
            business_unit=BusinessUnit.CLOUD_INFRASTRUCTURE,
            criticality=CriticalityTier.TIER_1,
            revenue_per_hour_inr=1500000.0,
            pii_records_count=45000,
            data_classification="Restricted System Identity",
            rto_hours=2.0,
            rpo_hours=1.0,
            ip_or_endpoint="10.100.1.10",
            cloud_provider="Hybrid (Azure AD / On-Prem)",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-IAM-MFA",
                    name="Domain Admin MFA & Tiered Admin Model",
                    category="IAM",
                    framework_mappings={"ISO_27001": ["A.9.2.1"], "NIST_CSF": ["PR.AC-1"], "CIS_V8": ["CIS-6.5"], "RBI": ["RBI-3.1"]},
                    telemetry_score=0.64,
                    implementation_status="Partial - Tiering Gap"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2024-1709",
                    asset_id="AST-005",
                    title="ScreenConnect / ConnectWise Auth Bypass & RCE",
                    cvss_score=10.0,
                    epss_score=0.963,
                    is_cisa_kev=True,
                    days_open=14,
                    attack_vector="Network"
                )
            ]
        ),

        # 6. SWIFT International Financial Gateway (Tier 1 Crown Jewel)
        Asset(
            asset_id="AST-006",
            name="SWIFT Alliance Gateway & CSP Compliant HSM",
            business_unit=BusinessUnit.CORPORATE_TREASURY,
            criticality=CriticalityTier.TIER_1,
            revenue_per_hour_inr=4000000.0,
            pii_records_count=500000,
            data_classification="High-Value Financial Messaging",
            rto_hours=1.0,
            rpo_hours=0.05,
            ip_or_endpoint="10.250.5.1",
            cloud_provider="Secure On-Premises HSM Vault",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-NET-SEG",
                    name="Air-Gap & Hardware Token Enclave",
                    category="Network",
                    framework_mappings={"ISO_27001": ["A.13.1.1"], "NIST_CSF": ["PR.AC-5"], "RBI": ["RBI-4.1"], "SEBI": ["CSCRF-1.1"]},
                    telemetry_score=0.88,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-22515",
                    asset_id="AST-006",
                    title="Confluence Server Broken Access Control Advisory",
                    cvss_score=8.1,
                    epss_score=0.312,
                    is_cisa_kev=False,
                    days_open=32,
                    attack_vector="Adjacent"
                )
            ]
        ),

        # 7. Mobile Banking Backend API (Tier 2 Operational)
        Asset(
            asset_id="AST-007",
            name="Mobile Banking Gateway & Push Engine",
            business_unit=BusinessUnit.RETAIL_BANKING,
            criticality=CriticalityTier.TIER_2,
            revenue_per_hour_inr=950000.0,
            pii_records_count=4200000,
            data_classification="Confidential",
            rto_hours=4.0,
            rpo_hours=1.0,
            ip_or_endpoint="mobile.bank.internal",
            cloud_provider="AWS",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-WAF-API",
                    name="API Rate Limiting & Bot Protection",
                    category="AppSec",
                    framework_mappings={"ISO_27001": ["A.14.2.1"], "NIST_CSF": ["PR.PT-4"], "SEBI": ["CSCRF-2.3"]},
                    telemetry_score=0.68,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2024-27198",
                    asset_id="AST-007",
                    title="JetBrains TeamCity Auth Bypass in Staging Pipeline",
                    cvss_score=9.8,
                    epss_score=0.914,
                    is_cisa_kev=True,
                    days_open=21,
                    attack_vector="Network"
                )
            ]
        ),

        # 8. Corporate Email & Exchange (Tier 2 Operational)
        Asset(
            asset_id="AST-008",
            name="Microsoft 365 Hybrid Exchange & Tenant",
            business_unit=BusinessUnit.ENTERPRISE_OPS,
            criticality=CriticalityTier.TIER_2,
            revenue_per_hour_inr=450000.0,
            pii_records_count=250000,
            data_classification="Internal Business",
            rto_hours=6.0,
            rpo_hours=2.0,
            ip_or_endpoint="outlook.office365.com",
            cloud_provider="Microsoft Cloud",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-HUMAN-RISK",
                    name="Anti-Phishing & Safe Links Filtering",
                    category="EmailSec",
                    framework_mappings={"ISO_27001": ["A.7.2.2"], "NIST_CSF": ["PR.AT-1"], "CIS_V8": ["CIS-14.1"], "RBI": ["RBI-7.1"]},
                    telemetry_score=0.74,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-23397",
                    asset_id="AST-008",
                    title="Microsoft Outlook NTLM Credential Theft Zero-Click",
                    cvss_score=9.8,
                    epss_score=0.887,
                    is_cisa_kev=True,
                    days_open=11,
                    attack_vector="Network"
                )
            ]
        ),

        # 9. Wealth Portfolio Management System (Tier 2 Operational)
        Asset(
            asset_id="AST-009",
            name="High-Net-Worth Wealth & Portfolio Engine",
            business_unit=BusinessUnit.CARDS_WEALTH,
            criticality=CriticalityTier.TIER_2,
            revenue_per_hour_inr=1100000.0,
            pii_records_count=320000,
            data_classification="Highly Confidential Financial",
            rto_hours=3.0,
            rpo_hours=0.5,
            ip_or_endpoint="wealth.bank.internal",
            cloud_provider="GCP",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-DATA-ENC",
                    name="Client Data Tokenization & KMS",
                    category="DataSec",
                    framework_mappings={"ISO_27001": ["A.10.1.2"], "NIST_CSF": ["PR.DS-2"], "SEBI": ["CSCRF-2.4"]},
                    telemetry_score=0.78,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-38606",
                    asset_id="AST-009",
                    title="Apple WebKit / Safari Remote Kernel Memory Corruption",
                    cvss_score=7.8,
                    epss_score=0.142,
                    is_cisa_kev=False,
                    days_open=38,
                    attack_vector="Adjacent"
                )
            ]
        ),

        # 10. Developer GitLab & CI/CD Pipeline (Tier 3 Supporting)
        Asset(
            asset_id="AST-010",
            name="Enterprise GitLab CI/CD & Artifact Registry",
            business_unit=BusinessUnit.CLOUD_INFRASTRUCTURE,
            criticality=CriticalityTier.TIER_3,
            revenue_per_hour_inr=250000.0,
            pii_records_count=10000,
            data_classification="Proprietary Source Code",
            rto_hours=12.0,
            rpo_hours=4.0,
            ip_or_endpoint="gitlab.bank.internal",
            cloud_provider="AWS",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-IAM-MFA",
                    name="Git Developer MFA & Branch Protection",
                    category="IAM",
                    framework_mappings={"ISO_27001": ["A.14.2.8"], "NIST_CSF": ["PR.IP-1"], "CIS_V8": ["CIS-16.1"]},
                    telemetry_score=0.70,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-7028",
                    asset_id="AST-010",
                    title="GitLab Community/Enterprise Password Reset Account Takeover",
                    cvss_score=10.0,
                    epss_score=0.865,
                    is_cisa_kev=True,
                    days_open=45,
                    attack_vector="Network"
                ),
                VulnerabilityFinding(
                    cve_id="CVE-2024-0402",
                    asset_id="AST-010",
                    title="GitLab Arbitrary File Read via Workspace Dependency Crawler",
                    cvss_score=6.5,
                    epss_score=0.745,
                    is_cisa_kev=False,
                    days_open=24,
                    attack_vector="Network"
                )
            ]
        ),

        # 11. HRMS & Employee Payroll System (Tier 3 Supporting)
        Asset(
            asset_id="AST-011",
            name="HRMS, Payroll & Employee PII Portal",
            business_unit=BusinessUnit.ENTERPRISE_OPS,
            criticality=CriticalityTier.TIER_3,
            revenue_per_hour_inr=150000.0,
            pii_records_count=28000,
            data_classification="Employee PII",
            rto_hours=24.0,
            rpo_hours=8.0,
            ip_or_endpoint="hrms.bank.internal",
            cloud_provider="SaaS Workday / Internal Proxy",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-DLP-SEN",
                    name="DLP & Identity Sync",
                    category="DLP",
                    framework_mappings={"ISO_27001": ["A.8.2.1"], "NIST_CSF": ["PR.DS-5"], "CIS_V8": ["CIS-13.1"]},
                    telemetry_score=0.65,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2023-46604",
                    asset_id="AST-011",
                    title="Apache ActiveMQ OpenWire Client Deserialization in HR Staging Broker",
                    cvss_score=5.8,
                    epss_score=0.182,
                    is_cisa_kev=False,
                    days_open=50,
                    attack_vector="Network"
                ),
                VulnerabilityFinding(
                    cve_id="CVE-2024-23897",
                    asset_id="AST-011",
                    title="Jenkins CLI Arbitrary File Read on Internal Automation Runner",
                    cvss_score=5.3,
                    epss_score=0.295,
                    is_cisa_kev=False,
                    days_open=60,
                    attack_vector="Network"
                )
            ]
        ),

        # 12. Corporate Edge Firewalls & SD-WAN (Tier 2 Operational)
        Asset(
            asset_id="AST-012",
            name="Perimeter Palo Alto Next-Gen Firewalls & SD-WAN",
            business_unit=BusinessUnit.CLOUD_INFRASTRUCTURE,
            criticality=CriticalityTier.TIER_2,
            revenue_per_hour_inr=800000.0,
            pii_records_count=0,
            data_classification="Network Routing & Logs",
            rto_hours=1.0,
            rpo_hours=0.1,
            ip_or_endpoint="192.168.1.1",
            cloud_provider="Palo Alto Networks Edge",
            controls=[
                ControlTelemetry(
                    control_id="CTRL-EDR-COV",
                    name="Firewall Firmware & Threat Prevention Profiles",
                    category="Network",
                    framework_mappings={"ISO_27001": ["A.13.1.1"], "NIST_CSF": ["PR.PT-1"], "CIS_V8": ["CIS-4.4"], "RBI": ["RBI-4.1"]},
                    telemetry_score=0.82,
                    implementation_status="Enforced"
                )
            ],
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2024-3400",
                    asset_id="AST-012",
                    title="PAN-OS GlobalProtect Command Injection Vulnerability",
                    cvss_score=10.0,
                    epss_score=0.928,
                    is_cisa_kev=True,
                    days_open=9,
                    attack_vector="Network"
                ),
                VulnerabilityFinding(
                    cve_id="CVE-2024-20353",
                    asset_id="AST-012",
                    title="Cisco ASA Web Services Denial of Service & Memory Corruption",
                    cvss_score=8.6,
                    epss_score=0.215,
                    is_cisa_kev=False,
                    days_open=27,
                    attack_vector="Network"
                ),
                VulnerabilityFinding(
                    cve_id="CVE-2023-3824",
                    asset_id="AST-012",
                    title="PHP Buffer Overflow in Internal Admin Panel Utilities",
                    cvss_score=6.2,
                    epss_score=0.612,
                    is_cisa_kev=False,
                    days_open=40,
                    attack_vector="Network"
                )
            ]
        )
    ]
    return assets


DATA_DIR = os.environ.get(
    "RISKLENS_DATA_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
)
CUSTOM_ASSETS_FILE = os.path.join(DATA_DIR, "custom_assets.json")
CUSTOM_METADATA_FILE = os.path.join(DATA_DIR, "custom_metadata.json")

DEFAULT_METADATA: Dict[str, Any] = {
    "id": "BENCHMARK-BANKING",
    "name": "Global Retail & Commercial Bank",
    "organization": "Global Retail & Commercial Bank",
    "sector": "Banking & Financial Services",
    "is_custom": False,
    "asset_count": 12
}


def normalize_criticality(val: Any) -> CriticalityTier:
    v = str(val).strip().lower()
    if "1" in v or "crown" in v:
        return CriticalityTier.TIER_1
    elif "2" in v or "operational" in v:
        return CriticalityTier.TIER_2
    else:
        return CriticalityTier.TIER_3


def normalize_business_unit(val: Any) -> BusinessUnit:
    v = str(val).strip().lower()
    if "retail" in v or "payment" in v:
        return BusinessUnit.RETAIL_BANKING
    elif "card" in v or "wealth" in v:
        return BusinessUnit.CARDS_WEALTH
    elif "treasury" in v or "corporate" in v:
        return BusinessUnit.CORPORATE_TREASURY
    elif "cloud" in v or "infra" in v:
        return BusinessUnit.CLOUD_INFRASTRUCTURE
    else:
        return BusinessUnit.ENTERPRISE_OPS


class TelemetryService:
    """
    Singleton service managing enterprise assets, active telemetry,
    security initiative catalogs, and real-data import/export pipelines.
    """
    _instance = None

    def __init__(self):
        self._lock = threading.RLock()
        self._last_mtime: float = 0.0
        self.metadata: Dict[str, Any] = self._load_initial_metadata()
        self.assets: List[Asset] = self._load_initial_assets()
        self.initiatives: List[SecurityInitiative] = get_default_security_initiatives()

    def _load_initial_metadata(self) -> Dict[str, Any]:
        try:
            from backend.db.connection import get_db_connection
            with get_db_connection() as conn:
                row = conn.execute("SELECT payload_json FROM active_telemetry_state WHERE key = %s", ("active_metadata",)).fetchone()
                if row and row.get("payload_json"):
                    return json.loads(row["payload_json"])
        except Exception:
            pass
        if os.path.exists(CUSTOM_METADATA_FILE):
            try:
                with open(CUSTOM_METADATA_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return dict(DEFAULT_METADATA)

    def _sync_custom_file_if_modified(self):
        try:
            if os.path.exists(CUSTOM_ASSETS_FILE):
                mtime = os.path.getmtime(CUSTOM_ASSETS_FILE)
                if self._last_mtime != mtime:
                    with open(CUSTOM_ASSETS_FILE, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                    self.assets = [Asset.model_validate(a) for a in raw]
                    self._last_mtime = mtime
                if os.path.exists(CUSTOM_METADATA_FILE):
                    try:
                        with open(CUSTOM_METADATA_FILE, "r", encoding="utf-8") as mf:
                            self.metadata = json.load(mf)
                    except Exception:
                        pass
            elif self._last_mtime > 0:
                self.assets = list(get_default_enterprise_assets())
                self.metadata = dict(DEFAULT_METADATA)
                self._last_mtime = 0.0
        except Exception:
            pass

    def _load_initial_assets(self) -> List[Asset]:
        try:
            from backend.db.connection import get_db_connection
            with get_db_connection() as conn:
                row = conn.execute("SELECT payload_json FROM active_telemetry_state WHERE key = %s", ("active_assets",)).fetchone()
                if row and row.get("payload_json"):
                    raw = json.loads(row["payload_json"])
                    return [Asset.model_validate(a) for a in raw]
        except Exception:
            pass
        if os.path.exists(CUSTOM_ASSETS_FILE):
            try:
                self._last_mtime = os.path.getmtime(CUSTOM_ASSETS_FILE)
                with open(CUSTOM_ASSETS_FILE, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    return [Asset.model_validate(a) for a in raw]
            except Exception:
                pass
        return get_default_enterprise_assets()

    @classmethod
    def get_instance(cls) -> "TelemetryService":
        if cls._instance is None:
            cls._instance = TelemetryService()
        return cls._instance

    def get_active_metadata(self) -> Dict[str, Any]:
        with self._lock:
            self._sync_custom_file_if_modified()
            meta = dict(self.metadata)
            meta["asset_count"] = len(self.assets)
            return meta

    def get_all_assets(self) -> List[Asset]:
        with self._lock:
            self._sync_custom_file_if_modified()
            return list(self.assets)

    def get_asset(self, asset_id: str) -> Asset:
        with self._lock:
            self._sync_custom_file_if_modified()
            for a in self.assets:
                if a.asset_id == asset_id:
                    return a
        raise KeyError(f"Asset {asset_id} not found")

    def get_all_initiatives(self) -> List[SecurityInitiative]:
        with self._lock:
            return list(self.initiatives)

    def save_assets(self, assets: List[Asset], metadata: Optional[Dict[str, Any]] = None, persist: bool = True):
        snapshot = list(assets)
        with self._lock:
            self.assets = snapshot
            if metadata:
                self.metadata = dict(metadata)
                self.metadata["asset_count"] = len(snapshot)
        if persist:
            # 1. Persist directly to PostgreSQL
            try:
                from datetime import datetime, timezone
                from backend.db.connection import get_db_connection
                now_iso = datetime.now(timezone.utc).isoformat()
                assets_json = json.dumps([a.model_dump() for a in snapshot])
                with get_db_connection() as conn:
                    conn.execute("""
                        INSERT INTO active_telemetry_state (key, payload_json, updated_at)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (key) DO UPDATE SET
                            payload_json = EXCLUDED.payload_json,
                            updated_at = EXCLUDED.updated_at;
                    """, ("active_assets", assets_json, now_iso))
                    if metadata:
                        meta_json = json.dumps(self.metadata)
                        conn.execute("""
                            INSERT INTO active_telemetry_state (key, payload_json, updated_at)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (key) DO UPDATE SET
                                payload_json = EXCLUDED.payload_json,
                                updated_at = EXCLUDED.updated_at;
                        """, ("active_metadata", meta_json, now_iso))
            except Exception as e:
                pass

            # 2. Maintain local cached snapshot
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                import tempfile
                with tempfile.NamedTemporaryFile("w", dir=DATA_DIR, delete=False, encoding="utf-8") as tf:
                    json.dump([a.model_dump() for a in snapshot], tf, indent=2)
                    temp_name = tf.name
                os.replace(temp_name, CUSTOM_ASSETS_FILE)

                if metadata:
                    with tempfile.NamedTemporaryFile("w", dir=DATA_DIR, delete=False, encoding="utf-8") as mtf:
                        json.dump(self.metadata, mtf, indent=2)
                        meta_temp_name = mtf.name
                    os.replace(meta_temp_name, CUSTOM_METADATA_FILE)

                with self._lock:
                    try:
                        self._last_mtime = os.path.getmtime(CUSTOM_ASSETS_FILE)
                    except OSError:
                        pass
            except Exception:
                pass

    def reset_to_default(self):
        try:
            from backend.db.connection import get_db_connection
            with get_db_connection() as conn:
                conn.execute("DELETE FROM active_telemetry_state WHERE key IN (%s, %s)", ("active_assets", "active_metadata"))
        except Exception:
            pass
        if os.path.exists(CUSTOM_ASSETS_FILE):
            try:
                os.remove(CUSTOM_ASSETS_FILE)
            except OSError:
                pass
        if os.path.exists(CUSTOM_METADATA_FILE):
            try:
                os.remove(CUSTOM_METADATA_FILE)
            except OSError:
                pass
        with self._lock:
            self._last_mtime = 0.0
            self.assets = list(get_default_enterprise_assets())
            self.metadata = dict(DEFAULT_METADATA)

    def export_assets_dict(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._sync_custom_file_if_modified()
            return [a.model_dump() for a in self.assets]

    def export_assets_csv(self) -> str:
        with self._lock:
            self._sync_custom_file_if_modified()
            current_assets = list(self.assets)
        output = io.StringIO()
        fieldnames = [
            "asset_id", "name", "business_unit", "criticality",
            "revenue_per_hour_inr", "pii_records_count", "data_classification",
            "rto_hours", "rpo_hours", "ip_or_endpoint", "cloud_provider",
            "cve_ids", "top_cvss", "top_epss", "avg_control_score"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for a in current_assets:
            cves = [v.cve_id for v in a.vulnerabilities]
            top_cvss = max((v.cvss_score for v in a.vulnerabilities), default=0.0)
            top_epss = max((v.epss_score for v in a.vulnerabilities), default=0.0)
            ctrl_scores = [c.telemetry_score for c in a.controls] if a.controls else [0.65]
            avg_score = round(sum(ctrl_scores) / len(ctrl_scores), 2)

            writer.writerow({
                "asset_id": a.asset_id,
                "name": a.name,
                "business_unit": a.business_unit.value if hasattr(a.business_unit, "value") else str(a.business_unit),
                "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
                "revenue_per_hour_inr": a.revenue_per_hour_inr,
                "pii_records_count": a.pii_records_count,
                "data_classification": a.data_classification,
                "rto_hours": a.rto_hours,
                "rpo_hours": a.rpo_hours,
                "ip_or_endpoint": a.ip_or_endpoint,
                "cloud_provider": a.cloud_provider,
                "cve_ids": ";".join(cves),
                "top_cvss": top_cvss,
                "top_epss": top_epss,
                "avg_control_score": avg_score
            })
        return output.getvalue()

    def import_from_json(self, raw_data: Any) -> Tuple[List[Asset], List[str]]:
        warnings = []
        if isinstance(raw_data, dict):
            if "assets" in raw_data and isinstance(raw_data["assets"], list):
                raw_list = raw_data["assets"]
            else:
                raw_list = [raw_data]
        elif isinstance(raw_data, list):
            raw_list = raw_data
        else:
            raise ValueError("Expected JSON array of assets or an object with an 'assets' list.")

        parsed_assets: List[Asset] = []
        for idx, item in enumerate(raw_list):
            if not isinstance(item, dict):
                warnings.append(f"Skipped item #{idx + 1}: item is not an object.")
                continue

            asset_id = str(item.get("asset_id") or item.get("id") or f"AST-{idx+1:03d}")
            name = str(item.get("name") or item.get("asset_name") or f"Enterprise Asset {asset_id}")
            bu = normalize_business_unit(item.get("business_unit") or item.get("bu") or "Enterprise Operations")
            crit = normalize_criticality(item.get("criticality") or item.get("tier") or "Tier 2")
            rev = float(item.get("revenue_per_hour_inr") or item.get("revenue_per_hour") or 100000.0)
            pii = int(item.get("pii_records_count") or item.get("pii_records") or 0)
            classification = str(item.get("data_classification") or ("Crown Jewel Confidential" if crit == CriticalityTier.TIER_1 else "Confidential"))
            rto = float(item.get("rto_hours") or 4.0)
            rpo = float(item.get("rpo_hours") or 1.0)
            endpoint = str(item.get("ip_or_endpoint") or item.get("endpoint") or "")
            cloud = str(item.get("cloud_provider") or "AWS")

            # Parse Controls
            controls: List[ControlTelemetry] = []
            if "controls" in item and isinstance(item["controls"], list):
                for c in item["controls"]:
                    if isinstance(c, dict):
                        controls.append(ControlTelemetry(
                            control_id=str(c.get("control_id") or "CTRL-GEN"),
                            name=str(c.get("name") or "Standard Control"),
                            category=str(c.get("category") or "General"),
                            framework_mappings=c.get("framework_mappings") or {},
                            telemetry_score=float(c.get("telemetry_score") or 0.65),
                            implementation_status=str(c.get("implementation_status") or "Enforced"),
                            description=str(c.get("description") or "")
                        ))
            if not controls:
                controls = self._generate_default_controls_for_asset(crit)

            # Parse Vulnerabilities
            vulnerabilities: List[VulnerabilityFinding] = []
            if "vulnerabilities" in item and isinstance(item["vulnerabilities"], list):
                for v in item["vulnerabilities"]:
                    if isinstance(v, dict):
                        vulnerabilities.append(VulnerabilityFinding(
                            cve_id=str(v.get("cve_id") or "CVE-2024-0001"),
                            asset_id=asset_id,
                            title=str(v.get("title") or "Identified Security Vulnerability"),
                            cvss_score=float(v.get("cvss_score") or 7.5),
                            epss_score=float(v.get("epss_score") or 0.15),
                            is_cisa_kev=bool(v.get("is_cisa_kev", False)),
                            patch_available=bool(v.get("patch_available", True)),
                            remediation_status=str(v.get("remediation_status") or "Open"),
                            days_open=int(v.get("days_open") or 14),
                            attack_vector=str(v.get("attack_vector") or "Network")
                        ))
                    elif isinstance(v, str):
                        vulnerabilities.append(VulnerabilityFinding(
                            cve_id=v.strip(),
                            asset_id=asset_id,
                            title=f"Vulnerability {v.strip()}",
                            cvss_score=7.8,
                            epss_score=0.25,
                            is_cisa_kev=False,
                            days_open=20
                        ))

            asset = Asset(
                asset_id=asset_id,
                name=name,
                business_unit=bu,
                criticality=crit,
                revenue_per_hour_inr=rev,
                pii_records_count=pii,
                data_classification=classification,
                rto_hours=rto,
                rpo_hours=rpo,
                controls=controls,
                vulnerabilities=vulnerabilities,
                ip_or_endpoint=endpoint,
                cloud_provider=cloud
            )
            parsed_assets.append(asset)

        if not parsed_assets:
            raise ValueError("No valid enterprise assets could be parsed from the provided JSON.")

        return parsed_assets, warnings

    def import_from_csv(self, csv_text: str) -> Tuple[List[Asset], List[str]]:
        warnings = []
        f = io.StringIO(csv_text.strip())
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("CSV is empty or missing headers.")

        parsed_assets: List[Asset] = []
        for idx, raw_row in enumerate(reader):
            row = {k.strip().lower(): (v.strip() if v else "") for k, v in raw_row.items() if k}
            if not any(row.values()):
                continue

            asset_id = row.get("asset_id") or row.get("id") or row.get("asset") or row.get("system_id") or f"AST-{idx+1:03d}"
            name = row.get("name") or row.get("asset_name") or row.get("system_name") or row.get("service") or row.get("application") or f"Asset {asset_id}"
            bu = normalize_business_unit(row.get("business_unit") or row.get("bu") or row.get("department") or row.get("division") or "Enterprise Operations")
            crit = normalize_criticality(row.get("criticality") or row.get("tier") or row.get("priority") or "Tier 2")

            try:
                rev_val = row.get("revenue_per_hour_inr") or row.get("revenue_per_hour") or row.get("hourly_revenue") or row.get("downtime_cost") or 150000.0
                rev = float(rev_val)
            except ValueError:
                rev = 150000.0

            try:
                pii_val = row.get("pii_records_count") or row.get("pii_records") or row.get("pii_count") or row.get("records") or 0
                pii = int(float(pii_val))
            except ValueError:
                pii = 0

            classification = row.get("data_classification") or ("Crown Jewel Confidential" if crit == CriticalityTier.TIER_1 else "Confidential")

            try:
                rto = float(row.get("rto_hours") or 4.0)
            except ValueError:
                rto = 4.0

            try:
                rpo = float(row.get("rpo_hours") or 1.0)
            except ValueError:
                rpo = 1.0

            endpoint = row.get("ip_or_endpoint") or row.get("endpoint") or row.get("ip") or row.get("host") or ""
            cloud = row.get("cloud_provider") or row.get("cloud") or row.get("environment") or "AWS"

            # Parse CVEs from CSV
            cves_str = row.get("cve_ids") or row.get("vulnerabilities_cve") or row.get("cve") or row.get("cves") or row.get("vulns") or ""
            top_cvss = 7.5
            top_epss = 0.20
            if "top_cvss" in row and row["top_cvss"]:
                try: top_cvss = float(row["top_cvss"])
                except ValueError: pass
            if "top_epss" in row and row["top_epss"]:
                try: top_epss = float(row["top_epss"])
                except ValueError: pass

            vulnerabilities = []
            if cves_str:
                parts = [p.strip() for p in cves_str.replace(",", ";").split(";") if p.strip()]
                for p_idx, cve_id in enumerate(parts):
                    vulnerabilities.append(VulnerabilityFinding(
                        cve_id=cve_id,
                        asset_id=asset_id,
                        title=f"Disclosed Vulnerability {cve_id}",
                        cvss_score=top_cvss if p_idx == 0 else max(5.0, top_cvss - 1.0),
                        epss_score=top_epss if p_idx == 0 else max(0.05, top_epss * 0.7),
                        is_cisa_kev=(top_epss > 0.6 or top_cvss >= 9.0),
                        days_open=21,
                        attack_vector="Network"
                    ))

            # Controls
            avg_score = 0.65
            if "avg_control_score" in row and row["avg_control_score"]:
                try: avg_score = max(0.1, min(0.99, float(row["avg_control_score"])))
                except ValueError: pass
            controls = self._generate_default_controls_for_asset(crit, base_score=avg_score)

            asset = Asset(
                asset_id=asset_id,
                name=name,
                business_unit=bu,
                criticality=crit,
                revenue_per_hour_inr=rev,
                pii_records_count=pii,
                data_classification=classification,
                rto_hours=rto,
                rpo_hours=rpo,
                controls=controls,
                vulnerabilities=vulnerabilities,
                ip_or_endpoint=endpoint,
                cloud_provider=cloud
            )
            parsed_assets.append(asset)

        if not parsed_assets:
            raise ValueError("No valid rows could be imported from the CSV.")

        return parsed_assets, warnings

    def _generate_default_controls_for_asset(self, crit: CriticalityTier, base_score: float = 0.65) -> List[ControlTelemetry]:
        boost = 0.1 if crit == CriticalityTier.TIER_1 else 0.0
        return [
            ControlTelemetry(
                control_id="CTRL-IAM-MFA",
                name="Privileged Multi-Factor Authentication",
                category="IAM",
                framework_mappings={"ISO_27001": ["A.9.4.2"], "NIST_CSF": ["PR.AC-1"], "RBI": ["RBI-3.1"], "SEBI": ["CSCRF-1.4"]},
                telemetry_score=max(0.01, min(0.95, base_score + boost)),
                implementation_status="Enforced"
            ),
            ControlTelemetry(
                control_id="CTRL-EDR-COV",
                name="Endpoint Detection & Response (EDR)",
                category="EDR",
                framework_mappings={"ISO_27001": ["A.12.2.1"], "NIST_CSF": ["DE.CM-1"], "CIS_V8": ["CIS-10.1"]},
                telemetry_score=max(0.01, min(0.95, base_score + 0.05)),
                implementation_status="Enforced"
            ),
            ControlTelemetry(
                control_id="CTRL-NET-SEG",
                name="Network Microsegmentation & Firewalls",
                category="Network",
                framework_mappings={"ISO_27001": ["A.13.1.3"], "NIST_CSF": ["PR.AC-5"], "RBI": ["RBI-4.2"]},
                telemetry_score=max(0.01, min(0.95, base_score - 0.05)),
                implementation_status="Partially Enforced"
            ),
            ControlTelemetry(
                control_id="CTRL-VM-SLA",
                name="Risk-Based Vulnerability Remediation",
                category="Vulnerability",
                framework_mappings={"ISO_27001": ["A.12.6.1"], "NIST_CSF": ["ID.RA-1"], "CIS_V8": ["CIS-7.1"]},
                telemetry_score=max(0.01, min(0.95, base_score - 0.1)),
                implementation_status="Remediation Active"
            )
        ]

    def get_csv_template(self) -> str:
        return (
            "asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count,data_classification,rto_hours,rpo_hours,ip_or_endpoint,cloud_provider,cve_ids,top_cvss,top_epss,avg_control_score\n"
            "AST-001,Core Banking Transaction Switch,Retail Banking & Payments,Tier 1 - Crown Jewel,4500000,25000000,Banking Confidential / PCI-DSS,1.0,0.25,10.200.10.15,AWS,\"CVE-2023-4966;CVE-2024-21887\",9.4,0.942,0.68\n"
            "AST-002,UPI Payment Gateway API,Retail Banking & Payments,Tier 1 - Crown Jewel,2800000,12000000,PCI-DSS / Critical,0.5,0.1,api.pay.bank.internal,AWS,\"CVE-2024-22243;CVE-2023-38606\",8.8,0.725,0.75\n"
            "AST-003,Customer Wealth Data Lake,Cards & Wealth Management,Tier 1 - Crown Jewel,1800000,8500000,PII Restricted,2.0,0.5,lake.prod.corp,Azure,\"CVE-2023-34362\",9.8,0.954,0.58\n"
            "AST-004,Corporate Liquidity Portal,Corporate & Treasury,Tier 2 - Business Operational,950000,350000,Internal Confidential,4.0,1.0,172.16.4.80,Hybrid On-Prem,\"CVE-2023-27997\",8.2,0.485,0.72\n"
            "AST-005,Enterprise Active Directory Bastion,Cloud & Core Infrastructure,Tier 1 - Crown Jewel,1200000,0,Domain Controller,1.0,0.25,dc01.corp.internal,Hybrid On-Prem,\"CVE-2024-21413\",9.8,0.885,0.52\n"
        )

    def get_json_template(self) -> Dict[str, Any]:
        return {
            "format_version": "1.0",
            "instructions": "Provide an array of assets under 'assets' or provide a root array of asset objects.",
            "assets": [
                {
                    "asset_id": "AST-001",
                    "name": "Production Payment Switch",
                    "business_unit": "Retail Banking & Payments",
                    "criticality": "Tier 1 - Crown Jewel",
                    "revenue_per_hour_inr": 4500000.0,
                    "pii_records_count": 25000000,
                    "data_classification": "PCI-DSS Tier 1",
                    "rto_hours": 1.0,
                    "rpo_hours": 0.25,
                    "ip_or_endpoint": "10.200.10.15",
                    "cloud_provider": "AWS",
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2023-4966",
                            "title": "Citrix Bleed Sensitive Info Leak",
                            "cvss_score": 9.4,
                            "epss_score": 0.942,
                            "is_cisa_kev": True
                        }
                    ],
                    "controls": [
                        {
                            "control_id": "CTRL-IAM-MFA",
                            "name": "Privileged MFA",
                            "category": "IAM",
                            "telemetry_score": 0.70
                        }
                    ]
                }
            ]
        }

    def compute_asset_resistance(self, asset: Asset, initiative_boosts: Dict[str, float] = None) -> float:
        """
        Computes the net control resistance strength (0.0 to 1.0) for an asset.
        Combines baseline telemetry scores with applicable targeted initiative boosts.
        """
        if not asset.controls:
            baseline = 0.35  # Minimal default hygiene
        else:
            scores = [c.telemetry_score for c in asset.controls]
            baseline = sum(scores) / len(scores)

        # Apply initiative boosts only if they target this asset, tier, or controls
        boost = 0.0
        if initiative_boosts:
            init_map = {i.initiative_id: i for i in self.initiatives}
            asset_ctrl_ids = {c.control_id for c in asset.controls}
            current_asset_ids = {a.asset_id for a in self.assets}

            for init_id, b_val in initiative_boosts.items():
                init = init_map.get(init_id)
                if init:
                    # If target_assets is explicitly defined AND at least one of target_assets is present in active inventory:
                    specific_match_possible = bool(init.target_assets and any(tid in current_asset_ids for tid in init.target_assets))
                    if specific_match_possible:
                        is_targeted = (asset.asset_id in init.target_assets)
                    else:
                        # Fallback for industry presets or custom imported data:
                        # Match on target_controls and/or target_asset_tiers
                        matches_ctrl = bool(asset_ctrl_ids.intersection(init.target_controls)) if init.target_controls else True
                        matches_tier = (asset.criticality in init.target_asset_tiers or (hasattr(asset.criticality, "value") and asset.criticality.value in init.target_asset_tiers)) if init.target_asset_tiers else True
                        is_targeted = matches_ctrl and matches_tier

                    if is_targeted:
                        boost += b_val
                else:
                    # Scenario or custom override boost
                    boost += b_val

        # Diminishing returns ceiling on resistance strength (max 0.96)
        effective_resistance = min(0.96, baseline + boost * (1.0 - baseline))
        return effective_resistance

    def compute_asset_threat_exposure(self, asset: Asset) -> Tuple[float, float]:
        """
        Calculates (Threat Event Frequency baseline, Threat Capability index).
        Derived from CVE severity, EPSS exploitation likelihood, and asset visibility.
        """
        # Baseline annual threat encounters
        base_tef = 2.0  # Enterprise assets undergo constant probe scans

        if asset.criticality == CriticalityTier.TIER_1:
            base_tef += 3.5  # Crown jewels are targeted by organized APTs
        elif asset.criticality == CriticalityTier.TIER_2:
            base_tef += 1.5

        if not asset.vulnerabilities:
            return base_tef, 0.40

        # Maximum EPSS and average CVSS
        max_epss = max(v.epss_score for v in asset.vulnerabilities)
        avg_cvss = sum(v.cvss_score for v in asset.vulnerabilities) / len(asset.vulnerabilities)
        kev_multiplier = 1.6 if any(v.is_cisa_kev for v in asset.vulnerabilities) else 1.0

        # High EPSS dramatically spikes active exploit attempts
        tef = (base_tef + (max_epss * 8.0)) * kev_multiplier
        # Threat capability index [0.3 to 0.98]
        threat_capability = min(0.98, 0.30 + (avg_cvss / 10.0) * 0.45 + (max_epss * 0.23))

        return tef, threat_capability
