"""
Unit and Integration Tests for Feature 6: Document Intelligence.
Verifies parsing and analysis of PDF, DOCX, CSV, and XLSX files to extract:
1. Risks (Inherent & Residual 5x5 scoring, root causes, crown jewels, consequences)
2. Controls (Hygiene, implementation status, coverage, effort, teams)
3. Policies (DPDP Act 2023, RBI CSFS, ISO 27001, compliance gaps)
4. Vulnerabilities (CVE IDs, CVSS scores, EPSS probabilities, CISA KEV)
"""

import io
import unittest
import base64
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.ai_document_intelligence import DocumentIntelligenceEngine, get_document_intelligence_engine
from backend.engine.ai_knowledge import ProjectKnowledgeAgent
from backend.engine.chat_memory import get_memory_store

try:
    import pypdf
    from pypdf import PdfWriter
    _HAS_PYPDF = True
except ImportError:
    _HAS_PYPDF = False

try:
    import docx
    _HAS_DOCX = True
except ImportError:
    _HAS_DOCX = False

try:
    import openpyxl
    _HAS_OPENPYXL = True
except ImportError:
    _HAS_OPENPYXL = False


class TestDocumentIntelligence(unittest.TestCase):
    def setUp(self):
        self.engine = DocumentIntelligenceEngine()
        self.client = TestClient(app)
        self.memory_store = get_memory_store()

    def test_parse_and_analyze_csv(self):
        """Verifies CSV parsing extracts risks, controls, policies, and vulnerabilities."""
        csv_content = """Risk Title,Description,Severity,Asset,Likelihood,Impact
Publicly Accessible Customer Database,Our customer database is publicly accessible on cloud port 5432,Critical,Core Customer DB,5,5
Unpatched Perimeter Gateway,Legacy VPN gateway unpatched against CVE-2024-3400,High,GlobalProtect Gateway,4,4
Ransomware Threat Vector,Risk of ransomware infection and data encryption,Critical,Active Directory,4,5
Missing Multi-Factor Authentication,Lack of MFA authentication enforcement on admin console,High,Cloud Console,5,4
"""
        csv_bytes = csv_content.encode("utf-8")
        result = self.engine.analyze_document(csv_bytes, "enterprise_risk_register.csv", session_id="test_sess_csv")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.metadata.file_type, "csv")
        self.assertGreater(result.metadata.word_count, 10)
        self.assertGreaterEqual(len(result.risks), 2)
        self.assertGreaterEqual(len(result.controls), 1)
        self.assertGreaterEqual(len(result.policies), 1)
        self.assertGreaterEqual(len(result.vulnerabilities), 1)

        # Verify 5x5 matrix scoring
        has_critical_or_high = any(r.inherent_level in ("Critical", "High") for r in result.risks)
        self.assertTrue(has_critical_or_high)

        # Verify residual risk shift
        for r in result.risks:
            self.assertLessEqual(r.residual_likelihood, r.inherent_likelihood)

        # Verify markdown dossier
        self.assertIn("Document Intelligence Dossier", result.markdown_summary)
        self.assertIn("Extracted Risks", result.markdown_summary)

    def test_parse_and_analyze_pdf(self):
        """Verifies PDF document analysis (using synthetic pypdf if available or text fallback)."""
        pdf_bytes = None
        if _HAS_PYPDF:
            writer = PdfWriter()
            # Add page with text annotations
            writer.add_blank_page(width=612, height=792)
            stream = io.BytesIO()
            writer.write(stream)
            # Inject readable text streams
            raw_pdf = stream.getvalue()
            # Append plain readable stream
            injected_stream = b"\nstream\nBT /F1 12 Tf 72 712 Td (RiskLens Security Audit Report: Our customer database is publicly accessible. Unpatched VPN running CVE-2024-3400. Mandatory compliance with Digital Personal Data Protection Act DPDP Act 2023 Section 33. Multi-Factor Authentication MFA is missing.) ET\nendstream\n"
            pdf_bytes = raw_pdf + injected_stream
        else:
            pdf_bytes = b"%PDF-1.4\nstream\nRiskLens Security Audit Report: Our customer database is publicly accessible. Unpatched VPN running CVE-2024-3400. DPDP Act 2023 violation.\nendstream\n%%EOF"

        result = self.engine.analyze_document(pdf_bytes, "quarterly_audit_report.pdf", session_id="test_sess_pdf")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.metadata.file_type, "pdf")
        self.assertGreaterEqual(len(result.risks), 1)
        self.assertGreaterEqual(len(result.controls), 1)
        self.assertGreaterEqual(len(result.policies), 1)

    def test_parse_and_analyze_docx(self):
        """Verifies DOCX document analysis extracts structured GRC findings."""
        if not _HAS_DOCX:
            self.skipTest("python-docx not installed")

        doc = docx.Document()
        doc.add_heading("Enterprise Cyber Risk Assessment & Technical Audit", 0)
        doc.add_paragraph("Executive Briefing: Cloud object storage S3 bucket is publicly accessible.")
        doc.add_paragraph("Vulnerability Scan: Active weaponized flaw CVE-2023-38606 with high exploit probability.")
        doc.add_paragraph("Regulatory Gaps: Non-compliance with Reserve Bank of India Cyber Security Framework (RBI CSFS) and DPDP Act 2023.")
        doc.add_paragraph("Defensive Controls: Web Application Firewall (WAF) and Endpoint Detection & Response (EDR) deployed; MFA is missing on bastion hosts.")

        # Add a table
        table = doc.add_table(rows=1, cols=3)
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = "Risk ID"
        hdr_cells[1].text = "Risk Title"
        hdr_cells[2].text = "Severity"
        row_cells = table.add_row().cells
        row_cells[0].text = "RSK-01"
        row_cells[1].text = "Core Switch Unpatched Delay"
        row_cells[2].text = "Critical"

        stream = io.BytesIO()
        doc.save(stream)
        docx_bytes = stream.getvalue()

        result = self.engine.analyze_document(docx_bytes, "annual_audit.docx", session_id="test_sess_docx")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.metadata.file_type, "docx")
        self.assertGreaterEqual(len(result.risks), 1)
        self.assertGreaterEqual(len(result.controls), 2)
        self.assertGreaterEqual(len(result.policies), 1)
        self.assertGreaterEqual(len(result.vulnerabilities), 1)

        # Check CVE-2023-38606 extracted
        cve_found = any("CVE-2023-38606" in v.id or (v.cve_id and "CVE-2023-38606" in v.cve_id) for v in result.vulnerabilities)
        self.assertTrue(cve_found)

    def test_parse_and_analyze_xlsx(self):
        """Verifies XLSX spreadsheet analysis across workbook sheets."""
        if not _HAS_OPENPYXL:
            self.skipTest("openpyxl not installed")

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Risk Register"
        ws.append(["Risk Title", "Description", "Severity", "Likelihood", "Impact"])
        ws.append(["Customer PII Leakage", "Customer database publicly accessible with 5M records", "Critical", 5, 5])
        ws.append(["DDoS Service Outage", "Web transaction portal susceptible to distributed denial of service", "High", 4, 4])
        ws.append(["Unpatched CVE-2021-44228", "Log4Shell vulnerability present on internal reporting service", "Critical", 5, 5])

        ws2 = wb.create_sheet(title="Controls & Policies")
        ws2.append(["Control / Framework", "Status", "Notes"])
        ws2.append(["Multi-Factor Authentication", "Missing", "Admin channel lacks MFA"])
        ws2.append(["Digital Personal Data Protection Act 2023", "Gap", "Section 33 audit violation"])

        stream = io.BytesIO()
        wb.save(stream)
        xlsx_bytes = stream.getvalue()

        result = self.engine.analyze_document(xlsx_bytes, "quarterly_matrix.xlsx", session_id="test_sess_xlsx")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.metadata.file_type, "xlsx")
        self.assertGreaterEqual(len(result.risks), 2)
        self.assertGreaterEqual(len(result.controls), 1)
        self.assertGreaterEqual(len(result.policies), 1)
        self.assertGreaterEqual(len(result.vulnerabilities), 1)

    def test_document_intelligence_rest_json_endpoint(self):
        """Verifies POST /api/assistant/document-intelligence with base64 encoded document."""
        test_csv = "Risk Title,Severity,Asset\nDatabase Public Exposure,Critical,Customer DB\nRansomware Vector,High,AD Server\n"
        b64_content = base64.b64encode(test_csv.encode("utf-8")).decode("utf-8")

        payload = {
            "filename": "q3_cloud_risks.csv",
            "file_format": "csv",
            "content_base64": b64_content,
            "session_id": "api_test_session_doc"
        }

        res = self.client.post("/api/assistant/document-intelligence", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["metadata"]["filename"], "q3_cloud_risks.csv")
        self.assertGreaterEqual(len(data["risks"]), 1)
        self.assertIn("posture_score", data)
        self.assertIn("risk_matrix_summary", data)
        self.assertIn("markdown_summary", data)

    def test_document_intelligence_rest_upload_endpoint(self):
        """Verifies POST /api/assistant/document-intelligence/upload with multipart file upload."""
        csv_bytes = b"Threat Vector,Details\nPublic S3 bucket customer data exposure,Cloud bucket unauthenticated read\n"
        files = {
            "file": ("security_scan.csv", io.BytesIO(csv_bytes), "text/csv")
        }
        data = {
            "session_id": "multipart_test_sess"
        }

        res = self.client.post("/api/assistant/document-intelligence/upload", files=files, data=data)
        self.assertEqual(res.status_code, 200)
        resp_data = res.json()

        self.assertEqual(resp_data["status"], "success")
        self.assertEqual(resp_data["metadata"]["filename"], "security_scan.csv")
        self.assertGreaterEqual(len(resp_data["risks"]), 1)

        # Verify chat history was saved in memory store
        history = self.memory_store.get_history(session_id="multipart_test_sess")
        self.assertGreaterEqual(len(history), 2)
        self.assertIn("Analyse uploaded document", history[0]["content"])
        self.assertIn("Document Intelligence Dossier", history[1]["content"])

    def test_natural_language_document_intelligence_query(self):
        """Verifies natural language query explaining Document Intelligence in ProjectKnowledgeAgent."""
        agent = ProjectKnowledgeAgent()
        res = agent.answer_query("How does Document Intelligence analyse uploaded PDF, DOCX, CSV and XLSX files to extract risks, controls, policies and vulnerabilities?")

        markdown = res["response_markdown"]
        self.assertIn("Document Intelligence", markdown)
        self.assertIn("PDF, DOCX, CSV", markdown)
        self.assertIn("Risks", markdown)
        self.assertIn("Controls", markdown)
        self.assertIn("Policies", markdown)
        self.assertIn("Vulnerabilities", markdown)


if __name__ == "__main__":
    unittest.main()
