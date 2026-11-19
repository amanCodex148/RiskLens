"""
20 Pre-Configured Enterprise Industry Datasets for RiskLens.
Covers real-world industry verticals with authentic asset taxonomies, financial outage costs,
PII record volumes, real CVE vulnerability exposures, and security control postures.
"""

from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel
from backend.models.schemas import (
    Asset, VulnerabilityFinding, ControlTelemetry,
    CriticalityTier, BusinessUnit
)


class IndustryDatasetMetadata(BaseModel):
    id: str
    name: str
    sector: str
    icon: str
    description: str
    risk_profile: str
    asset_count: int
    primary_threat: str
    regulatory_focus: List[str]


def _make_asset(
    asset_id: str,
    name: str,
    business_unit: BusinessUnit,
    criticality: CriticalityTier,
    revenue_per_hour_inr: float,
    pii_records_count: int,
    data_classification: str,
    ip_or_endpoint: str,
    cloud_provider: str,
    cves: List[Tuple[str, str, float, float, bool]],  # (cve_id, title, cvss, epss, is_kev)
    avg_control_score: float = 0.65
) -> Asset:
    vulnerabilities = [
        VulnerabilityFinding(
            cve_id=c[0],
            asset_id=asset_id,
            title=c[1],
            cvss_score=c[2],
            epss_score=c[3],
            is_cisa_kev=c[4],
            days_open=21,
            attack_vector="Network"
        )
        for c in cves
    ]
    boost = 0.10 if criticality == CriticalityTier.TIER_1 else 0.0
    controls = [
        ControlTelemetry(
            control_id="CTRL-IAM-MFA",
            name="Privileged Multi-Factor Authentication",
            category="IAM",
            framework_mappings={"ISO_27001": ["A.9.4.2"], "NIST_CSF": ["PR.AC-1"], "RBI": ["RBI-3.1"], "SEBI": ["CSCRF-1.4"]},
            telemetry_score=min(0.95, avg_control_score + boost),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-EDR-COV",
            name="Endpoint Detection & Response (EDR)",
            category="EDR",
            framework_mappings={"ISO_27001": ["A.12.2.1"], "NIST_CSF": ["DE.CM-1"], "CIS_V8": ["CIS-10.1"]},
            telemetry_score=min(0.95, avg_control_score + 0.05),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-NET-SEG",
            name="Network Microsegmentation & Firewalls",
            category="Network",
            framework_mappings={"ISO_27001": ["A.13.1.3"], "NIST_CSF": ["PR.AC-5"], "RBI": ["RBI-4.2"]},
            telemetry_score=min(0.95, avg_control_score - 0.05),
            implementation_status="Partially Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-VM-SLA",
            name="Risk-Based Vulnerability Remediation",
            category="Vulnerability",
            framework_mappings={"ISO_27001": ["A.12.6.1"], "NIST_CSF": ["ID.RA-1"], "CIS_V8": ["CIS-7.1"]},
            telemetry_score=min(0.95, avg_control_score - 0.1),
            implementation_status="Remediation Active"
        ),
        ControlTelemetry(
            control_id="CTRL-BCP-IMM",
            name="Immutable Air-Gapped Backups & Disaster Recovery",
            category="Resilience",
            framework_mappings={"ISO_27001": ["A.12.3.1"], "NIST_CSF": ["PR.IP-4"], "RBI": ["RBI-6.2"]},
            telemetry_score=min(0.95, avg_control_score - 0.08),
            implementation_status="Partially Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-DATA-ENC",
            name="Data Encryption & Tokenization Vault",
            category="Data Security",
            framework_mappings={"ISO_27001": ["A.10.1.1"], "NIST_CSF": ["PR.DS-1"], "SEBI": ["CSCRF-2.1"]},
            telemetry_score=min(0.95, avg_control_score + 0.02),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-DLP-SEN",
            name="Sensitive Data Discovery & DLP",
            category="Data Security",
            framework_mappings={"ISO_27001": ["A.8.2.3"], "NIST_CSF": ["PR.DS-5"], "DPDP": ["DPDP-Sec8"]},
            telemetry_score=min(0.95, avg_control_score - 0.12),
            implementation_status="Remediation Active"
        ),
        ControlTelemetry(
            control_id="CTRL-WAF-API",
            name="Web Application Firewall & API Shield",
            category="Application Security",
            framework_mappings={"ISO_27001": ["A.14.1.2"], "NIST_CSF": ["PR.PT-4"], "OWASP": ["API-Shield"]},
            telemetry_score=min(0.95, avg_control_score - 0.04),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-IAM-PAM",
            name="Privileged Access Management (PAM)",
            category="IAM",
            framework_mappings={"ISO_27001": ["A.9.2.3"], "NIST_CSF": ["PR.AC-4"], "RBI": ["RBI-3.4"]},
            telemetry_score=min(0.95, avg_control_score + 0.04),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-HUMAN-RISK",
            name="Security Awareness & Phishing Simulation",
            category="Human Risk",
            framework_mappings={"ISO_27001": ["A.7.2.2"], "NIST_CSF": ["PR.AT-1"]},
            telemetry_score=min(0.95, avg_control_score - 0.06),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-CSPM-AUD",
            name="Cloud Security Posture Management (CSPM)",
            category="Cloud Security",
            framework_mappings={"ISO_27001": ["A.12.6.2"], "NIST_CSF": ["DE.CM-7"]},
            telemetry_score=min(0.95, avg_control_score + 0.01),
            implementation_status="Enforced"
        ),
        ControlTelemetry(
            control_id="CTRL-SIEM-VEL",
            name="SIEM Log Analytics & Detection Velocity",
            category="SecOps",
            framework_mappings={"ISO_27001": ["A.12.4.1"], "NIST_CSF": ["DE.AE-2"]},
            telemetry_score=min(0.95, avg_control_score + 0.03),
            implementation_status="Enforced"
        )
    ]
    return Asset(
        asset_id=asset_id,
        name=name,
        business_unit=business_unit,
        criticality=criticality,
        revenue_per_hour_inr=revenue_per_hour_inr,
        pii_records_count=pii_records_count,
        data_classification=data_classification,
        rto_hours=0.5 if criticality == CriticalityTier.TIER_1 else 4.0,
        rpo_hours=0.1 if criticality == CriticalityTier.TIER_1 else 1.0,
        controls=controls,
        vulnerabilities=vulnerabilities,
        ip_or_endpoint=ip_or_endpoint,
        cloud_provider=cloud_provider
    )


def _build_dataset_catalog() -> Dict[str, Tuple[IndustryDatasetMetadata, List[Asset]]]:
    catalog: Dict[str, Tuple[IndustryDatasetMetadata, List[Asset]]] = {}

    # 1. Commercial Bank
    meta_1 = IndustryDatasetMetadata(
        id="DATASET-BANKING",
        name="Tier-1 Commercial & Retail Bank",
        sector="Banking & Financial Services",
        icon="landmark",
        description="Core banking switches, UPI/card payment rails, SWIFT messaging, and consumer loan portals.",
        risk_profile="Critical Financial Exposure & Regulatory Sanctions",
        asset_count=7,
        primary_threat="SWIFT Wire Fraud & Card Gateway Compromise",
        regulatory_focus=["RBI Master Directions", "SEBI CSCRF", "PCI-DSS", "DPDP Act"]
    )
    assets_1 = [
        _make_asset("BNK-001", "Core Banking Switch (Finacle)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 4800000.0, 28000000, "Banking Secret / PCI", "10.10.1.10", "Hybrid On-Prem", [("CVE-2023-4966", "Citrix Bleed Sensitive Info Leak", 9.4, 0.942, True), ("CVE-2024-21887", "Ivanti Connect Command Injection", 9.1, 0.895, True)], 0.65),
        _make_asset("BNK-002", "UPI & IMPS Fast Payment API", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 3200000.0, 15000000, "PCI-DSS Crown Jewel", "api.upi.bank.in", "AWS", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.72),
        _make_asset("BNK-003", "SWIFT International Alliance Gateway", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 5500000.0, 500000, "SWIFT CSP Restricted", "swift.gw.corp", "Physical Enclave", [("CVE-2023-38606", "Kernel Privilege Escalation", 7.8, 0.412, False)], 0.78),
        _make_asset("BNK-004", "Retail Internet Banking Web Farm", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1200000.0, 18000000, "Customer PII", "netbanking.bank.in", "AWS", [("CVE-2023-46604", "Apache ActiveMQ RCE", 9.8, 0.885, True)], 0.60),
        _make_asset("BNK-005", "Customer Master Data & Wealth DB", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_1, 2200000.0, 22000000, "PII / Financial KYC", "db.wealth.internal", "Azure", [("CVE-2023-34362", "MOVEit Transfer SQLi", 9.8, 0.954, True)], 0.58),
        _make_asset("BNK-006", "Enterprise Active Directory PDC", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 1500000.0, 0, "Identity Domain", "dc01.ad.bank.internal", "On-Prem", [("CVE-2024-21413", "Outlook Moniker RCE", 9.8, 0.885, True)], 0.52),
        _make_asset("BNK-007", "ATM Fleet Controller Switch", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 950000.0, 2000000, "Card PIN / Track2", "atm-switch.prod", "Private MPLS", [("CVE-2023-27997", "FortiOS Heap Overflow", 8.2, 0.485, False)], 0.62)
    ]
    catalog[meta_1.id] = (meta_1, assets_1)

    # 2. Fintech Unicorn
    meta_2 = IndustryDatasetMetadata(
        id="DATASET-FINTECH",
        name="Fintech Unicorn & Payment Gateway",
        sector="Payments & Digital Lending",
        icon="credit-card",
        description="High-velocity payment processing, merchant settlements, and AI-driven credit underwriting.",
        risk_profile="API Abuse, Synthetic Identity Fraud & Merchant Defalcation",
        asset_count=6,
        primary_threat="API Credential Stuffing & Gateway Key Exfiltration",
        regulatory_focus=["RBI PA/PG Guidelines", "PCI-DSS Level 1", "ISO 27001"]
    )
    assets_2 = [
        _make_asset("FNT-001", "Merchant Payment Gateway Core API", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 3800000.0, 16000000, "PCI-DSS / Tokenization", "api.checkout.fintech.io", "AWS", [("CVE-2023-4966", "Session Hijack in NetScaler", 9.4, 0.942, True)], 0.70),
        _make_asset("FNT-002", "Real-Time AI Fraud Detection Cluster", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 1900000.0, 24000000, "Transaction Graphs", "ml-fraud.internal", "GCP", [("CVE-2023-38606", "Linux Kernel Zero-Day", 7.8, 0.412, False)], 0.68),
        _make_asset("FNT-003", "Instant Personal Loan Disbursal Engine", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_2, 1400000.0, 8000000, "Credit Bureau Records", "loans.fintech.io", "AWS", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.62),
        _make_asset("FNT-004", "DigiLocker & Aadhaar KYC Verifier", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 2100000.0, 14000000, "Government PII / Biometrics", "kyc.fintech.io", "AWS", [("CVE-2023-34362", "MOVEit File Transfer SQLi", 9.8, 0.954, True)], 0.55),
        _make_asset("FNT-005", "Merchant Settlement Escrow Database", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 2900000.0, 4500000, "Financial Ledger", "escrow-db.fintech.internal", "AWS Aurora", [("CVE-2024-21887", "Ivanti Command Injection", 9.1, 0.895, True)], 0.74),
        _make_asset("FNT-006", "Webhooks Notification Dispatcher", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_3, 400000.0, 1000000, "Public Logs", "hooks.fintech.io", "Cloudflare / AWS", [("CVE-2023-27997", "Web Gateway Buffer Overflow", 8.2, 0.485, False)], 0.65)
    ]
    catalog[meta_2.id] = (meta_2, assets_2)

    # 3. Healthcare Hospital Network
    meta_3 = IndustryDatasetMetadata(
        id="DATASET-HEALTHCARE",
        name="Multi-Specialty Hospital Network",
        sector="Healthcare & Life Sciences",
        icon="heart-pulse",
        description="Electronic Health Records, PACS diagnostic imaging, ICU telemetry, and robotic pharmacies.",
        risk_profile="Life-Safety Disruption, Ransomware Lockout & Medical PII Leakage",
        asset_count=6,
        primary_threat="Double-Extortion Ransomware Encrypting Medical Records",
        regulatory_focus=["HIPAA Security Rule", "DPDP Act 2023", "National Health Authority (ABDM)"]
    )
    assets_3 = [
        _make_asset("MED-001", "Epic Electronic Health Records (EHR)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 3500000.0, 6500000, "PHI Protected Health Info", "ehr.hospital.net", "Hybrid Cloud", [("CVE-2023-34362", "MOVEit SQLi Patient Leak", 9.8, 0.954, True), ("CVE-2024-21887", "Ivanti SSL VPN Exploit", 9.1, 0.895, True)], 0.48),
        _make_asset("MED-002", "PACS Radiologic Medical Imaging Server", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 2100000.0, 4200000, "DICOM Diagnostic Scans", "pacs.hospital.net", "On-Premises SAN", [("CVE-2023-4966", "NetScaler Memory Dump", 9.4, 0.942, True)], 0.52),
        _make_asset("MED-003", "ICU Central Bedside Monitoring Hub", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 4200000.0, 500000, "Life-Critical Telemetry", "192.168.100.20", "Isolated Medical VLAN", [("CVE-2023-38606", "Embedded Linux Kernel Exploit", 7.8, 0.412, False)], 0.58),
        _make_asset("MED-004", "Pharmacy Automated Dispensing Robots", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1100000.0, 1200000, "Controlled Substance Log", "pharmacy-robot.internal", "On-Prem", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.50),
        _make_asset("MED-005", "Telemedicine Mobile Video Consult Hub", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_2, 750000.0, 2800000, "Audio/Video Doctor Notes", "telemed.hospital.net", "AWS", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.65),
        _make_asset("MED-006", "Pathology Lab Blood Analyzer Network", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_3, 450000.0, 1500000, "Lab Biometrics", "lab.hospital.internal", "VLAN 20", [("CVE-2023-27997", "Firewall Buffer Overflow", 8.2, 0.485, False)], 0.42)
    ]
    catalog[meta_3.id] = (meta_3, assets_3)

    # 4. E-Commerce Marketplace
    meta_4 = IndustryDatasetMetadata(
        id="DATASET-ECOMMERCE",
        name="Global E-Commerce Marketplace",
        sector="Retail & Consumer Internet",
        icon="shopping-bag",
        description="High-throughput cart checkout, flash-sale edge APIs, warehouse robotics, and logistics routing.",
        risk_profile="Massive Flash-Sale Outage Losses & Credit Card Skimming (Magecart)",
        asset_count=6,
        primary_threat="DDoS Volumetric Extortion & Payment Form Tampering",
        regulatory_focus=["PCI-DSS v4.0", "Consumer Protection E-Commerce Rules", "DPDP Act"]
    )
    assets_4 = [
        _make_asset("ECM-001", "Core Checkout & Order Placement Engine", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 5800000.0, 45000000, "Customer Credit Cards / Addresses", "checkout.shop.com", "AWS Multi-Region", [("CVE-2023-4966", "Citrix ADC Edge Leak", 9.4, 0.942, True)], 0.75),
        _make_asset("ECM-002", "Search & AI Recommendation Vector Cluster", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_2, 2200000.0, 0, "Behavioral Profiles", "search.shop.com", "GCP", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.70),
        _make_asset("ECM-003", "Warehouse Automation & Robotic Sorters", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 3100000.0, 0, "Robotics OT", "10.50.12.1", "Warehouse Edge", [("CVE-2023-46604", "ActiveMQ Broker RCE", 9.8, 0.885, True)], 0.50),
        _make_asset("ECM-004", "Payment Gateway Bridge & Card Vault", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 4100000.0, 32000000, "PCI Tokenized Records", "pay-bridge.shop.com", "AWS HSM", [("CVE-2024-21887", "Ivanti Gateway Exploit", 9.1, 0.895, True)], 0.82),
        _make_asset("ECM-005", "Last-Mile Delivery Dispatch Engine", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1400000.0, 15000000, "Driver GPS & Customer Phones", "dispatch.shop.com", "AWS", [("CVE-2023-38606", "Kernel Escalation", 7.8, 0.412, False)], 0.60),
        _make_asset("ECM-006", "Merchant Marketplace Seller Portal", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_3, 850000.0, 1200000, "Merchant Banking Details", "seller.shop.com", "AWS", [("CVE-2023-27997", "Fortinet Heap Corruption", 8.2, 0.485, False)], 0.64)
    ]
    catalog[meta_4.id] = (meta_4, assets_4)

    # 5. Energy & SCADA Grid
    meta_5 = IndustryDatasetMetadata(
        id="DATASET-ENERGY",
        name="National Power Grid & SCADA Utility",
        sector="Critical Infrastructure & Energy",
        icon="zap",
        description="Electrical transmission SCADA, substation RTUs, gas turbine telemetry, and smart meter head-ends.",
        risk_profile="Widespread Blackout, Cyber-Physical Equipment Destruction & Public Safety",
        asset_count=6,
        primary_threat="State-Sponsored APT Disrupting Industrial Control Systems (ICS)",
        regulatory_focus=["CEA Cyber Security Guidelines", "NCIIPC CII Protection", "NERC CIP"]
    )
    assets_5 = [
        _make_asset("ENG-001", "Master SCADA Transmission Control System", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 8500000.0, 0, "National Power Grid Telemetry", "10.240.1.5", "Air-Gapped SCADA LAN", [("CVE-2023-46604", "ActiveMQ ICS Command Injection", 9.8, 0.885, True), ("CVE-2024-21887", "Remote VPN Gateway Compromise", 9.1, 0.895, True)], 0.58),
        _make_asset("ENG-002", "Substation Automated RTU Controller Fleet", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 6200000.0, 0, "IEC 60870-5-104 Switches", "10.240.50.1", "Substation Field OT", [("CVE-2023-38606", "RTU Embedded Zero-Day", 7.8, 0.412, False)], 0.45),
        _make_asset("ENG-003", "Gas Turbine Vibration & Safety Governor", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 7100000.0, 0, "Turbine Safety Instrument (SIS)", "10.240.90.10", "Physical Generation Enclave", [("CVE-2023-27997", "OT Perimeter Firewall Exploit", 8.2, 0.485, False)], 0.62),
        _make_asset("ENG-004", "Smart Meter AMI Head-End Collector", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1800000.0, 8500000, "Consumer Power Consumption", "ami.powergrid.gov.in", "Hybrid Cloud", [("CVE-2023-4966", "Session Hijack in NetScaler", 9.4, 0.942, True)], 0.60),
        _make_asset("ENG-005", "Energy Trading & Wholesale Power Market Gateway", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 4500000.0, 200000, "Real-time Megawatt Bids", "px.powergrid.gov.in", "Dedicated Lease Line", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.75),
        _make_asset("ENG-006", "Enterprise Asset Management (Maximo)", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_3, 600000.0, 50000, "Grid Maintenance Schedules", "maximo.powergrid.internal", "On-Prem", [("CVE-2023-34362", "SQL Injection Flaw", 9.8, 0.954, True)], 0.54)
    ]
    catalog[meta_5.id] = (meta_5, assets_5)

    # 6. Commercial Airline
    meta_6 = IndustryDatasetMetadata(
        id="DATASET-AVIATION",
        name="Commercial Airline & Fleet Operations",
        sector="Aerospace & Transportation",
        icon="plane",
        description="Flight dispatch, passenger reservation (PSS), in-flight Wi-Fi telemetry, and aircraft maintenance.",
        risk_profile="Flight Cancellations, Airport Gridlock & Global Passenger PII Exfiltration",
        asset_count=5,
        primary_threat="Ransomware Knocking Out Passenger Check-In & Crew Rostering",
        regulatory_focus=["ICAO Aviation Cyber Security", "DGCA Directives", "EU GDPR"]
    )
    assets_6 = [
        _make_asset("AIR-001", "Flight Operations & Dispatch System (FODS)", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 6500000.0, 50000, "Active Flight Plans & Fuel Maps", "dispatch.airways.com", "Dedicated Tier-3 DC", [("CVE-2023-4966", "NetScaler Information Disclosure", 9.4, 0.942, True), ("CVE-2024-21887", "Ivanti Connect RCE", 9.1, 0.895, True)], 0.68),
        _make_asset("AIR-002", "Passenger Service & Booking Core (Amadeus PSS)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 5200000.0, 35000000, "Passport Details & Credit Cards", "res.airways.com", "AWS Multi-Region", [("CVE-2023-34362", "MOVEit Transfer SQLi", 9.8, 0.954, True)], 0.70),
        _make_asset("AIR-003", "Airport Baggage Handling PLC Network", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1900000.0, 0, "Baggage Conveyor Controllers", "10.40.1.8", "Airport Enclave", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.48),
        _make_asset("AIR-004", "Aircraft Maintenance Engineering Log (AMOS)", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 2800000.0, 0, "Jet Engine Telemetry & Airworthiness", "amos.airways.internal", "On-Prem", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.62),
        _make_asset("AIR-005", "Crew Rostering & Duty Period Engine", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1600000.0, 25000, "Pilot / Cabin Crew Rosters", "crew.airways.internal", "Azure", [("CVE-2023-38606", "Privilege Escalation", 7.8, 0.412, False)], 0.55)
    ]
    catalog[meta_6.id] = (meta_6, assets_6)

    # 7. Telecom 5G Carrier
    meta_7 = IndustryDatasetMetadata(
        id="DATASET-TELECOM",
        name="National Telecom & 5G Carrier",
        sector="Telecommunications & Media",
        icon="radio",
        description="5G standalone packet core, subscriber database (HSS/UDM), signaling gateways, and billing.",
        risk_profile="Mass Communication Outage, Lawful Interception Tampering & SIM Swap Fraud",
        asset_count=5,
        primary_threat="Signaling SS7/Diameter Spoofing & Nation-State Core Eavesdropping",
        regulatory_focus=["DoT Telecom Security Mandates", "TRAI Guidelines", "ISO 27001"]
    )
    assets_7 = [
        _make_asset("TEL-001", "5G Standalone Packet Core (UPF/AMF)", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 7200000.0, 120000000, "Live Packet Routing & Session Keys", "core.telco.net", "Telco NFV Cloud", [("CVE-2024-21887", "Ivanti Edge Bypass", 9.1, 0.895, True), ("CVE-2023-4966", "Citrix ADC Token Hijacking", 9.4, 0.942, True)], 0.72),
        _make_asset("TEL-002", "Home Subscriber Server & UDM (Unified Data)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 6100000.0, 95000000, "SIM Cryptographic Keys (Ki) & Location", "udm.telco.net", "Telco Private Enclave", [("CVE-2023-34362", "MOVEit Database Breach", 9.8, 0.954, True)], 0.65),
        _make_asset("TEL-003", "Call Detail Records (CDR) Big Data Lake", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_1, 2900000.0, 150000000, "Geo-Location & Call Logs", "cdr-lake.telco.internal", "Hadoop / AWS", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.58),
        _make_asset("TEL-004", "International Roaming Signaling Hub", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_2, 2400000.0, 15000000, "Diameter / SS7 Interconnect", "roam-gw.telco.net", "Equinix Edge", [("CVE-2023-27997", "Firewall Remote Overflow", 8.2, 0.485, False)], 0.60),
        _make_asset("TEL-005", "Customer Self-Care Billing & Recharge API", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1800000.0, 60000000, "Payment & Usage Logs", "api.telco.in", "AWS", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.68)
    ]
    catalog[meta_7.id] = (meta_7, assets_7)

    # 8. Connected EV Automotive
    meta_8 = IndustryDatasetMetadata(
        id="DATASET-AUTOMOTIVE",
        name="Connected EV OEM & Smart Mobility",
        sector="Automotive & Smart Mobility",
        icon="car",
        description="Over-The-Air (OTA) firmware signing, vehicle telematics, and robotic assembly plants.",
        risk_profile="Remote Vehicle Hijacking, Fleet-wide Recall & Industrial Robot Sabotage",
        asset_count=5,
        primary_threat="Compromised OTA Code Signing Keys Injecting Malicious Firmware",
        regulatory_focus=["UNECE WP.29 R155/R156", "ISO/SAE 21434", "DPDP Act"]
    )
    assets_8 = [
        _make_asset("AUTO-001", "OTA Firmware Code-Signing HSM Vault", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 7500000.0, 0, "Root Firmware Signing Keys", "ota-hsm.ev.corp", "Air-Gapped HSM Enclave", [("CVE-2024-21887", "Ivanti SSL Bypass", 9.1, 0.895, True)], 0.85),
        _make_asset("AUTO-002", "Vehicle Telematics Ingestion Cluster (MQTT)", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 3800000.0, 4500000, "Real-time Vehicle GPS & Battery Health", "telematics.ev.io", "AWS IoT Core", [("CVE-2023-4966", "Citrix NetScaler Token Leak", 9.4, 0.942, True)], 0.65),
        _make_asset("AUTO-003", "Autonomous Driving Vision ML Training Lake", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_2, 2200000.0, 0, "Proprietary Camera Video Models", "vision-ai.ev.corp", "GCP Vertex AI", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.68),
        _make_asset("AUTO-004", "Gigafactory Robotic Assembly Line SCADA", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 5900000.0, 0, "KUKA Robotic Arm Controllers", "10.80.20.1", "Plant Floor VLAN", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.50),
        _make_asset("AUTO-005", "Customer Companion Mobile App API", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1400000.0, 3200000, "Remote Door Unlock & Pre-Conditioning", "app-api.ev.io", "AWS", [("CVE-2023-38606", "Kernel Escalation", 7.8, 0.412, False)], 0.64)
    ]
    catalog[meta_8.id] = (meta_8, assets_8)

    # 9. Cloud SaaS Enterprise
    meta_9 = IndustryDatasetMetadata(
        id="DATASET-SAAS",
        name="Enterprise B2B Cloud SaaS Platform",
        sector="Cloud & Software Technology",
        icon="cloud",
        description="Multi-tenant Kubernetes clusters, HashiCorp Vault secrets, CI/CD runners, and billing gateways.",
        risk_profile="Cross-Tenant Data Exposure, Supply Chain CI/CD Tampering & Global Service Outage",
        asset_count=5,
        primary_threat="GitHub Actions Runner Breach & Multi-Tenant Database Exfiltration",
        regulatory_focus=["SOC 2 Type II", "ISO 27001", "FedRAMP", "EU GDPR"]
    )
    assets_9 = [
        _make_asset("SAS-001", "Production Multi-Tenant Kubernetes Cluster", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 4900000.0, 55000000, "Enterprise Customer Documents & DBs", "k8s-prod.saas.io", "AWS EKS", [("CVE-2023-4966", "Citrix ADC Token Hijacking", 9.4, 0.942, True), ("CVE-2024-21887", "Ivanti Gateway Exploit", 9.1, 0.895, True)], 0.76),
        _make_asset("SAS-002", "HashiCorp Vault Corporate Secrets Engine", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 6200000.0, 0, "Database Root Credentials & API Keys", "vault.saas.corp", "AWS KMS", [("CVE-2023-38606", "Linux Kernel Privilege Escalation", 7.8, 0.412, False)], 0.82),
        _make_asset("SAS-003", "CI/CD GitHub Actions Self-Hosted Runners", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 3100000.0, 0, "Build Environment & Production Keys", "runners.saas.internal", "AWS", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.54),
        _make_asset("SAS-004", "Customer Billing & Stripe Subscription Webhook", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_2, 1900000.0, 8500000, "Billing Records & Tax ID", "billing.saas.io", "AWS", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.70),
        _make_asset("SAS-005", "Public Enterprise Customer REST API Gateway", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 2800000.0, 20000000, "Customer CRM Integration", "api.saas.io", "Cloudflare / AWS", [("CVE-2023-27997", "Edge Buffer Overflow", 8.2, 0.485, False)], 0.72)
    ]
    catalog[meta_9.id] = (meta_9, assets_9)

    # 10. Government Digital Infrastructure
    meta_10 = IndustryDatasetMetadata(
        id="DATASET-GOVERNMENT",
        name="National Digital Identity & Citizen Services",
        sector="Public Sector & Governance",
        icon="building",
        description="National biometric identity vault, Direct Benefit Transfer (DBT), and civil registry portals.",
        risk_profile="Mass Citizen Identity Theft, Welfare Sabotage & Civil Trust Collapse",
        asset_count=5,
        primary_threat="Mass Identity Exfiltration & Subversion of Direct Welfare Transfers",
        regulatory_focus=["National Identity Cyber Regulations", "CERT-In Directives", "DPDP Act"]
    )
    assets_10 = [
        _make_asset("GOV-001", "National Biometric Identity Central DB", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 9500000.0, 180000000, "Biometrics, Iris & National ID Cards", "id-vault.gov.in", "Government Private Cloud", [("CVE-2023-34362", "MOVEit SQL Injection", 9.8, 0.954, True), ("CVE-2023-4966", "Citrix NetScaler Leak", 9.4, 0.942, True)], 0.70),
        _make_asset("GOV-002", "Direct Benefit Transfer (DBT) Welfare Switch", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 7800000.0, 95000000, "Welfare Bank Account Numbers", "dbt-switch.gov.in", "Gov Cloud Enclave", [("CVE-2024-21887", "Ivanti VPN Exploit", 9.1, 0.895, True)], 0.72),
        _make_asset("GOV-003", "National Tax Filing & Return Processing", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 5200000.0, 65000000, "Income Records & Bank Balances", "taxportal.gov.in", "Government DC", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.65),
        _make_asset("GOV-004", "Civil Registry & Passport Issuance Core", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 4100000.0, 48000000, "Birth Certificates & Passport Keys", "passport.gov.in", "Dedicated Govt DC", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.60),
        _make_asset("GOV-005", "Unified Public Citizen Mobile App (UMANG)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1900000.0, 75000000, "Citizen Account Logins", "api.services.gov.in", "Gov Cloud", [("CVE-2023-27997", "Gateway Buffer Overflow", 8.2, 0.485, False)], 0.64)
    ]
    catalog[meta_10.id] = (meta_10, assets_10)

    # 11. Pharmaceutical R&D
    meta_11 = IndustryDatasetMetadata(
        id="DATASET-PHARMA",
        name="Global Pharmaceutical R&D & Trials",
        sector="Pharmaceuticals & Biotech",
        icon="flask-conical",
        description="Patented drug formulas, Phase-III clinical trial data lakes, and Good Manufacturing Practice (GMP) lines.",
        risk_profile="Intellectual Property Espionage, Trial Data Falsification & Product Recall",
        asset_count=5,
        primary_threat="Nation-State APT Stealing Patented Vaccine & Oncology Formulations",
        regulatory_focus=["FDA 21 CFR Part 11", "GxP Compliance", "ISO 27001", "DPDP Act"]
    )
    assets_11 = [
        _make_asset("PHA-001", "Oncology Drug Formula & Molecular IP Vault", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 7200000.0, 0, "Billion-Dollar Patented Molecules", "ip-vault.pharma.corp", "Air-Gapped Enclave", [("CVE-2024-21887", "Ivanti SSL VPN RCE", 9.1, 0.895, True)], 0.80),
        _make_asset("PHA-002", "Phase-III Clinical Trial Electronic Data Capture", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 4800000.0, 1800000, "Patient Medical Trial Outcomes", "trials.pharma.corp", "AWS HealthLake", [("CVE-2023-34362", "MOVEit File Transfer SQLi", 9.8, 0.954, True)], 0.68),
        _make_asset("PHA-003", "Good Manufacturing Practice (GMP) Batch Release", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 5500000.0, 0, "Chemical Batch Dosing Calibration", "10.60.1.10", "Plant Floor OT", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.52),
        _make_asset("PHA-004", "High-Throughput Genomic Screening Cluster", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_2, 2100000.0, 0, "Genomic Sequencing Raw Data", "genomics.pharma.internal", "HPC Cluster", [("CVE-2023-38606", "Linux Kernel Zero-Day", 7.8, 0.412, False)], 0.62),
        _make_asset("PHA-005", "Global Adverse Drug Event Reporting System", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1800000.0, 3500000, "Statutory Side Effect Logs", "adverse.pharma.corp", "Azure", [("CVE-2023-4966", "NetScaler Sensitive Leak", 9.4, 0.942, True)], 0.66)
    ]
    catalog[meta_11.id] = (meta_11, assets_11)

    # 12. Defense Contractor
    meta_12 = IndustryDatasetMetadata(
        id="DATASET-DEFENSE",
        name="Defense Contractor & Aerospace Enclave",
        sector="Defense & Aerospace",
        icon="shield-alert",
        description="Fighter jet avionics CAD/CAM, secure drone telemetry, and encrypted military communications.",
        risk_profile="National Security Compromise, Weapon System Blueprints Theft & Enclave Breach",
        asset_count=5,
        primary_threat="Advanced Persistent Threat (APT) Infiltrating Defense Supply Chains",
        regulatory_focus=["CMMC Level 3", "NIST SP 800-171", "ITAR Regulations"]
    )
    assets_12 = [
        _make_asset("DEF-001", "Avionics CAD/CAM 3D Engineering Enclave", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 8800000.0, 0, "Top Secret Fighter Jet Schematics", "cad.defense.corp", "Air-Gapped SIPRNet Link", [("CVE-2024-21413", "Outlook Moniker Exploit", 9.8, 0.885, True)], 0.88),
        _make_asset("DEF-002", "UAV Tactical Drone Telemetry & Command Lab", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 6900000.0, 0, "Real-time Flight Control Code", "drone-lab.defense.corp", "Isolated RF Enclave", [("CVE-2024-21887", "Ivanti Command Injection", 9.1, 0.895, True)], 0.82),
        _make_asset("DEF-003", "Classified Defense Supply Chain ERP", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 4200000.0, 150000, "Missile Component Subcontractors", "erp.defense.corp", "GovCloud High", [("CVE-2023-34362", "MOVEit File Exfiltration", 9.8, 0.954, True)], 0.74),
        _make_asset("DEF-004", "Military Satellite Communications (SATCOM) Uplink", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 5600000.0, 0, "Telemetry Ground Station", "satcom.defense.internal", "Earth Station", [("CVE-2023-4966", "Citrix ADC Token Hijacking", 9.4, 0.942, True)], 0.78),
        _make_asset("DEF-005", "Personnel Security Clearance Vetting DB", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 2400000.0, 85000, "Polygraph & Background Dossiers", "clearance.defense.corp", "Private Cloud", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.70)
    ]
    catalog[meta_12.id] = (meta_12, assets_12)

    # 13. High-Frequency Trading
    meta_13 = IndustryDatasetMetadata(
        id="DATASET-TRADING",
        name="High-Frequency Trading & Stock Exchange",
        sector="Capital Markets & Trading",
        icon="trending-up",
        description="Sub-microsecond matching engines, Direct Market Access (DMA), and colocation FPGA clusters.",
        risk_profile="Catastrophic Flash-Crash Losses, Front-Running Exploit & Regulatory Penalties",
        asset_count=5,
        primary_threat="Direct Market Access (DMA) Algorithm Injection & Latency Sabotage",
        regulatory_focus=["SEBI CSCRF Framework", "MiFID II", "ISO 27001"]
    )
    assets_13 = [
        _make_asset("HFT-001", "Ultra-Low Latency Order Matching Engine", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 9200000.0, 8500000, "Live Bids & Equity Order Books", "coloc.engine.exchange.in", "Exchange Colocation", [("CVE-2023-38606", "Kernel Exploit on Bare-Metal", 7.8, 0.412, False)], 0.85),
        _make_asset("HFT-002", "Direct Market Access (DMA) Broker Gateway", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 6800000.0, 4200000, "High-Value Algo Routing", "dma.broker.in", "Direct Optical Line", [("CVE-2023-4966", "Citrix NetScaler Leak", 9.4, 0.942, True)], 0.80),
        _make_asset("HFT-003", "Real-Time Market Data Multicast Feed", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 4500000.0, 0, "Level-3 Tick-by-Tick Feed", "feed.exchange.in", "Low Latency Multicast", [("CVE-2023-27997", "Firewall Buffer Overflow", 8.2, 0.485, False)], 0.75),
        _make_asset("HFT-004", "Clearing & Margin Settlement Database", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 5100000.0, 3100000, "Collateral & Margin Balances", "margin.exchange.internal", "Oracle Exadata", [("CVE-2024-21887", "Ivanti Command Injection", 9.1, 0.895, True)], 0.78),
        _make_asset("HFT-005", "Algorithmic Risk Pre-Trade Guardrails (RMS)", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_1, 3900000.0, 0, "Fat-Finger & Limit Check Rules", "rms.exchange.internal", "FPGA Server", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.82)
    ]
    catalog[meta_13.id] = (meta_13, assets_13)

    # 14. Higher Education & University
    meta_14 = IndustryDatasetMetadata(
        id="DATASET-EDUCATION",
        name="Premier Research University Campus",
        sector="Higher Education & Research",
        icon="graduation-cap",
        description="Student information systems (SIS), supercomputing research clusters, and campus Wi-Fi infrastructure.",
        risk_profile="Ransomware Campus Lockout, Student PII Dumps & Patent Theft",
        asset_count=5,
        primary_threat="Widespread Phishing Hijacking Enterprise VPN & Research Servers",
        regulatory_focus=["FERPA", "UGC Cyber Security Directives", "DPDP Act"]
    )
    assets_14 = [
        _make_asset("EDU-001", "Student Academic Information System (SIS)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 1600000.0, 1850000, "Grades, Transcripts & Financial Aid", "sis.univ.edu", "Cloud Hosted", [("CVE-2023-34362", "MOVEit SQL Injection", 9.8, 0.954, True)], 0.52),
        _make_asset("EDU-002", "High-Performance Research Supercomputing (HPC)", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 2400000.0, 0, "Unpublished AI / Quantum Patents", "hpc.univ.edu", "Campus Data Center", [("CVE-2023-38606", "Linux Kernel Privilege Escalation", 7.8, 0.412, False)], 0.58),
        _make_asset("EDU-003", "Campus Core 802.1X Wireless & Network Bastion", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_2, 950000.0, 45000, "Student Network RADIUS Auth", "radius.univ.edu", "Campus Core", [("CVE-2023-4966", "NetScaler Sensitive Information", 9.4, 0.942, True)], 0.48),
        _make_asset("EDU-004", "Alumni Endowment & Donation Ledger", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_2, 1400000.0, 350000, "Billion-Dollar Endowment Gifts", "endowment.univ.edu", "Azure", [("CVE-2024-21887", "Ivanti SSL VPN Exploit", 9.1, 0.895, True)], 0.60),
        _make_asset("EDU-005", "Online Courseware & Examination LMS (Canvas)", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1100000.0, 650000, "Live Exam Question Papers", "lms.univ.edu", "AWS", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.55)
    ]
    catalog[meta_14.id] = (meta_14, assets_14)

    # 15. Container Shipping & Logistics
    meta_15 = IndustryDatasetMetadata(
        id="DATASET-LOGISTICS",
        name="Global Container Shipping & Ports",
        sector="Maritime & Logistics",
        icon="truck",
        description="Port Terminal Operating System (TOS), container crane automation, and customs manifests.",
        risk_profile="Global Supply Chain Blockade, Port Demurrage & Cargo Piracy",
        asset_count=5,
        primary_threat="NotPetya-style Ransomware Freezing Automated Port Gantry Cranes",
        regulatory_focus=["IMO Maritime Cyber Risk Guidelines", "SOLAS Mandates", "ISO 28000"]
    )
    assets_15 = [
        _make_asset("LOG-001", "Automated Port Terminal Operating System (TOS)", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 6800000.0, 1200000, "Container Stacking & Vessel Berth", "tos.port-terminal.com", "Port Data Center", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True), ("CVE-2024-21887", "Ivanti Gateway Exploit", 9.1, 0.895, True)], 0.54),
        _make_asset("LOG-002", "Quay Gantry Crane Automation PLC Network", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 5200000.0, 0, "Container Lifting Crane OT", "10.70.1.10", "Port Crane Enclave", [("CVE-2023-38606", "Embedded Linux Kernel Escalation", 7.8, 0.412, False)], 0.45),
        _make_asset("LOG-003", "Customs Clearance & Cargo Manifest Database", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 3900000.0, 4800000, "Cargo Bills of Lading / Customs", "manifest.shipping.corp", "Hybrid Cloud", [("CVE-2023-34362", "MOVEit Transfer SQLi", 9.8, 0.954, True)], 0.62),
        _make_asset("LOG-004", "Vessel GPS Fleet Telematics & AIS Gateway", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 2100000.0, 0, "Oceanic Ship Route Maps", "ais.fleet.corp", "Satellite Link / AWS", [("CVE-2023-4966", "NetScaler Information Disclosure", 9.4, 0.942, True)], 0.58),
        _make_asset("LOG-005", "Refrigerated Container IoT Temp Monitor", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_3, 850000.0, 0, "Cold-Chain Perishables Sensors", "reefer.fleet.internal", "IoT Hub", [("CVE-2023-27997", "Perimeter Heap Overflow", 8.2, 0.485, False)], 0.48)
    ]
    catalog[meta_15.id] = (meta_15, assets_15)

    # 16. Media Streaming & Entertainment
    meta_16 = IndustryDatasetMetadata(
        id="DATASET-MEDIA",
        name="OTT Streaming & Entertainment Studio",
        sector="Media & Entertainment",
        icon="film",
        description="High-bitrate 4K encoding farms, Widevine/FairPlay DRM licensing, and unreleased movie vaults.",
        risk_profile="Pre-Release Movie Leakage, DRM Decryption & Global CDN Sabotage",
        asset_count=5,
        primary_threat="Insider Threat / Hacker Syndicate Leaking Multi-Million Dollar Blockbusters",
        regulatory_focus=["MPAA Content Security Best Practices", "PCI-DSS", "DPDP Act"]
    )
    assets_16 = [
        _make_asset("MED-001", "Unreleased Movie Master Vault (SAN/NAS)", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 6500000.0, 0, "Raw 8K Master Footage & Audio", "vault.studio.internal", "Air-Gapped Optical SAN", [("CVE-2024-21887", "Ivanti Zero-Day Exploit", 9.1, 0.895, True)], 0.82),
        _make_asset("MED-002", "Widevine & Apple FairPlay DRM Key Cluster", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 4800000.0, 0, "Global Streaming Decryption Keys", "drm.stream.corp", "AWS KMS / HSM", [("CVE-2023-4966", "Session Hijack in NetScaler", 9.4, 0.942, True)], 0.85),
        _make_asset("MED-003", "Subscriber Billing & Payment Ingestion API", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 3900000.0, 42000000, "Credit Cards & Recurring Billing", "billing.stream.tv", "AWS", [("CVE-2023-34362", "MOVEit Database Breach", 9.8, 0.954, True)], 0.74),
        _make_asset("MED-004", "Global CDN Origin & Transcoding Pipeline", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_2, 2800000.0, 0, "Live Video Chunk Distribution", "origin.stream.tv", "Fastly / Cloudflare / AWS", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.70),
        _make_asset("MED-005", "Dynamic Ad-Insertion & Viewer Analytics DB", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_3, 1200000.0, 65000000, "Viewer Behavioral Telemetry", "ads.stream.tv", "GCP BigQuery", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.62)
    ]
    catalog[meta_16.id] = (meta_16, assets_16)

    # 17. Smart City & Municipality
    meta_17 = IndustryDatasetMetadata(
        id="DATASET-SMARTCITY",
        name="Smart Municipal City Operations",
        sector="Public Infrastructure & IoT",
        icon="cpu",
        description="Automated traffic light grids, water purification SCADA, and citizen property tax portals.",
        risk_profile="City-Wide Traffic Paralyzation, Water Supply Tampering & Public Panic",
        asset_count=5,
        primary_threat="Urban IoT Gateway Takeover & SCADA Water Valve Disruption",
        regulatory_focus=["Ministry of Urban Affairs Cyber Guidelines", "NCIIPC Directives"]
    )
    assets_17 = [
        _make_asset("CTY-001", "Metropolitan Intelligent Traffic Light SCADA", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 5200000.0, 0, "4,500 City Traffic Signal Nodes", "traffic-control.smartcity.gov", "Municipal Enclave", [("CVE-2023-46604", "ActiveMQ Broker RCE", 9.8, 0.885, True), ("CVE-2024-21887", "Ivanti VPN Exploit", 9.1, 0.895, True)], 0.46),
        _make_asset("CTY-002", "Drinking Water Supply & Chlorination SCADA", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 6400000.0, 0, "Chemical Dosing & Reservoir Pumps", "10.90.1.15", "Water Board OT", [("CVE-2023-38606", "Embedded Linux Kernel Bug", 7.8, 0.412, False)], 0.52),
        _make_asset("CTY-003", "CCTV Surveillance & Facial Recognition AI", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 2800000.0, 12000000, "Live City Camera Feeds", "surveillance.smartcity.gov", "Dedicated Police Fiber", [("CVE-2023-4966", "NetScaler Information Leak", 9.4, 0.942, True)], 0.58),
        _make_asset("CTY-004", "Citizen Property Tax & Utility Billing Portal", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1500000.0, 8500000, "Citizen Bank Details & Land Records", "tax.smartcity.gov.in", "Govt Cloud", [("CVE-2023-34362", "MOVEit SQLi", 9.8, 0.954, True)], 0.54),
        _make_asset("CTY-005", "Emergency Response 112 / 911 Dispatch Hub", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 4800000.0, 2500000, "Emergency Ambulance / Police Calls", "dispatch.112.gov.in", "Private Dual-Homed DC", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.65)
    ]
    catalog[meta_17.id] = (meta_17, assets_17)

    # 18. Insurance Provider
    meta_18 = IndustryDatasetMetadata(
        id="DATASET-INSURANCE",
        name="Life & Health Insurance Provider",
        sector="InsurTech & Actuarial",
        icon="umbrella",
        description="Automated underwriting, cashless hospital claim settlement, and policyholder health records.",
        risk_profile="Mass Medical History Leak, Fraudulent Claim Injections & Statutory Sanctions",
        asset_count=5,
        primary_threat="Compromised TPA Gateway Fabricating Multi-Crore Health Claims",
        regulatory_focus=["IRDAI Cyber Security Guidelines", "DPDP Act 2023", "ISO 27001"]
    )
    assets_18 = [
        _make_asset("INS-001", "Cashless Hospital TPA Settlement Switch", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 4600000.0, 8500000, "Direct Hospital Payouts / Claim Bills", "tpa.insurance.corp", "Hybrid Cloud", [("CVE-2024-21887", "Ivanti SSL VPN RCE", 9.1, 0.895, True), ("CVE-2023-4966", "Citrix ADC Token Leak", 9.4, 0.942, True)], 0.65),
        _make_asset("INS-002", "Policyholder Medical Diagnostic Records DB", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_1, 3800000.0, 24000000, "Diagnostic Lab Tests & Pre-Existing Illness", "medical-vault.insurance.corp", "Azure Private Enclave", [("CVE-2023-34362", "MOVEit Database Breach", 9.8, 0.954, True)], 0.60),
        _make_asset("INS-003", "Actuarial Mortality Risk Calculation Engine", BusinessUnit.CORPORATE_TREASURY, CriticalityTier.TIER_1, 2900000.0, 0, "Proprietary Life Pricing Models", "actuary.insurance.internal", "On-Premises HPC", [("CVE-2024-22243", "Spring Cloud SSRF", 8.8, 0.725, False)], 0.72),
        _make_asset("INS-004", "Insurance Agent Mobile POS & Onboarding", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1800000.0, 16000000, "Aadhaar / KYC & Premium Collection", "agent-api.insurance.in", "AWS", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.62),
        _make_asset("INS-005", "Automated Fraudulent Claim ML Detector", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_2, 1200000.0, 5000000, "Suspicious Hospital Flagging", "ml-claims.insurance.corp", "AWS SageMaker", [("CVE-2023-38606", "Kernel Escalation", 7.8, 0.412, False)], 0.68)
    ]
    catalog[meta_18.id] = (meta_18, assets_18)

    # 19. Luxury Hotel Chain
    meta_19 = IndustryDatasetMetadata(
        id="DATASET-HOSPITALITY",
        name="Global Luxury Hotel & Resort Chain",
        sector="Hospitality & Travel",
        icon="hotel",
        description="Central Reservation System (CRS), RFID room keycard controllers, and guest passport databases.",
        risk_profile="Point-of-Sale (POS) Card Scraping, VIP Guest Extortion & Keycard Bypass",
        asset_count=5,
        primary_threat="Magecart & POS Memory Scraping Stealing High-Net-Worth Credit Cards",
        regulatory_focus=["PCI-DSS v4.0", "GDPR", "DPDP Act 2023"]
    )
    assets_19 = [
        _make_asset("HTL-001", "Central Reservation & Booking Engine (CRS)", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_1, 3800000.0, 14000000, "Guest Credit Cards & Itineraries", "crs.luxuryhotels.com", "AWS Multi-Region", [("CVE-2023-4966", "Citrix NetScaler Token Leak", 9.4, 0.942, True)], 0.68),
        _make_asset("HTL-002", "RFID Guest Room Keycard Master Server", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 2800000.0, 0, "Master Door Cryptographic Keys", "keycard.hotel.internal", "Property Edge Server", [("CVE-2024-21887", "Ivanti SSL VPN Exploit", 9.1, 0.895, True)], 0.52),
        _make_asset("HTL-003", "Guest Passport & Immigration Records Vault", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_1, 3200000.0, 8500000, "VIP Diplomatic Passports & IDs", "passports.hotel.corp", "Encrypted NAS", [("CVE-2023-34362", "MOVEit Transfer SQLi", 9.8, 0.954, True)], 0.58),
        _make_asset("HTL-004", "Restaurant & Spa Point-of-Sale (POS) Network", BusinessUnit.RETAIL_BANKING, CriticalityTier.TIER_2, 1500000.0, 4200000, "Live EMV Card Authorizations", "10.20.5.1", "Property VLAN 10", [("CVE-2023-27997", "Fortinet Heap Buffer Overflow", 8.2, 0.485, False)], 0.50),
        _make_asset("HTL-005", "Global Loyalty Rewards & Points Ledger", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_2, 1100000.0, 22000000, "Reward Points & Flight Miles", "loyalty.luxuryhotels.com", "Azure", [("CVE-2024-22243", "Spring Framework SSRF", 8.8, 0.725, False)], 0.62)
    ]
    catalog[meta_19.id] = (meta_19, assets_19)

    # 20. Semiconductor Foundry
    meta_20 = IndustryDatasetMetadata(
        id="DATASET-SEMICONDUCTOR",
        name="Semiconductor Foundry & Chip Fab",
        sector="High-Tech Manufacturing",
        icon="cpu",
        description="Extreme Ultraviolet (EUV) lithography controllers, GDSII 3nm chip designs, and cleanroom SCADA.",
        risk_profile="Billion-Dollar 3nm Chip Mask Theft & Cleanroom Wafer Contamination",
        asset_count=5,
        primary_threat="Foreign Espionage Syphoning GDSII Microprocessor Blueprints",
        regulatory_focus=["NIST SP 800-161 (Supply Chain)", "ISO 27001", "ITAR"]
    )
    assets_20 = [
        _make_asset("SEMI-001", "GDSII 3nm Next-Gen Microprocessor Mask Vault", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 9500000.0, 0, "Proprietary 3nm Transistor Geometry", "masks.fab.corp", "Air-Gapped HSM Storage", [("CVE-2024-21413", "Outlook Moniker Exploit", 9.8, 0.885, True)], 0.88),
        _make_asset("SEMI-002", "Extreme Ultraviolet (EUV) Lithography SCADA", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 8500000.0, 0, "ASML Laser Lithography Controllers", "10.120.1.5", "Cleanroom Fab OT", [("CVE-2024-21887", "Ivanti SSL VPN Exploit", 9.1, 0.895, True)], 0.82),
        _make_asset("SEMI-003", "Silicon Wafer Yield Analytics Cluster", BusinessUnit.CLOUD_INFRASTRUCTURE, CriticalityTier.TIER_1, 4800000.0, 0, "Defect Scans & Wafer Yield Models", "yield.fab.corp", "On-Premises HPC", [("CVE-2023-38606", "Kernel Privilege Escalation", 7.8, 0.412, False)], 0.75),
        _make_asset("SEMI-004", "Cleanroom Chemical & Ultra-Pure Gas PLC", BusinessUnit.ENTERPRISE_OPS, CriticalityTier.TIER_1, 6200000.0, 0, "Silane Gas & Acid Delivery Lines", "10.120.50.1", "Hazardous Chemical OT", [("CVE-2023-46604", "ActiveMQ RCE", 9.8, 0.885, True)], 0.60),
        _make_asset("SEMI-005", "Customer Chip Design EDA Simulation Server", BusinessUnit.CARDS_WEALTH, CriticalityTier.TIER_2, 3500000.0, 50000, "Fabless Customer Netlists (Apple/Nvidia)", "eda.fab.corp", "Dedicated Isolated Cloud", [("CVE-2023-4966", "Citrix NetScaler Token Leak", 9.4, 0.942, True)], 0.78)
    ]
    catalog[meta_20.id] = (meta_20, assets_20)

    return catalog


# Pre-built singleton catalog
_DATASET_CATALOG = _build_dataset_catalog()


def get_all_industry_datasets_metadata() -> List[Dict[str, Any]]:
    """Returns metadata for all 20 pre-configured enterprise datasets."""
    return [meta.model_dump() for meta, _ in _DATASET_CATALOG.values()]


def get_industry_dataset_by_id(dataset_id: str) -> Optional[Tuple[IndustryDatasetMetadata, List[Asset]]]:
    """Retrieves metadata and full asset inventory for a specific dataset ID."""
    return _DATASET_CATALOG.get(dataset_id.upper().strip())
