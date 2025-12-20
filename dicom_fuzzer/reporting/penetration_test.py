"""Penetration Testing Report Generator for FDA Submissions.

Generates structured penetration testing reports per FDA June 2025 guidance
and ANSI/ISA 62443-4-1 Section 9.4 requirements.

This module provides:
- Standardized pentest report format for medical devices
- CVSS 3.1/4.0 scoring integration
- CWE/CAPEC mapping for vulnerabilities
- Executive summary generation
- Remediation tracking

References:
- FDA Cybersecurity Guidance (June 2025)
- ANSI/ISA 62443-4-1:2018 Section 9.4
- OWASP Testing Guide v4.2
- PTES (Penetration Testing Execution Standard)
- CVSS v3.1 and v4.0 Specifications

"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class VulnerabilitySeverity(Enum):
    """CVSS-based severity ratings."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @classmethod
    def from_cvss(cls, score: float) -> VulnerabilitySeverity:
        """Derive severity from CVSS score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score >= 0.1:
            return cls.LOW
        return cls.INFORMATIONAL


class TestingPhase(Enum):
    """Penetration testing phases per PTES."""

    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class AttackVector(Enum):
    """Attack vectors for vulnerability classification."""

    NETWORK = "network"
    ADJACENT_NETWORK = "adjacent_network"
    LOCAL = "local"
    PHYSICAL = "physical"


class RemediationStatus(Enum):
    """Remediation tracking status."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


@dataclass
class CVSSScore:
    """CVSS scoring details."""

    version: str = "3.1"
    vector_string: str = ""
    base_score: float = 0.0
    temporal_score: float | None = None
    environmental_score: float | None = None
    severity: str = ""

    def __post_init__(self) -> None:
        if not self.severity and self.base_score:
            self.severity = VulnerabilitySeverity.from_cvss(self.base_score).value


@dataclass
class VulnerabilityReference:
    """External references for vulnerabilities."""

    cve_id: str | None = None
    cwe_id: str | None = None
    capec_id: str | None = None
    owasp_category: str | None = None
    nvd_url: str | None = None
    vendor_advisory: str | None = None
    exploit_db_id: str | None = None


@dataclass
class AffectedComponent:
    """Component affected by vulnerability."""

    name: str
    version: str
    component_type: str = ""
    location: str = ""
    purl: str = ""
    cpe: str = ""


@dataclass
class ProofOfConcept:
    """Proof of concept for vulnerability."""

    description: str
    steps: list[str] = field(default_factory=list)
    payload: str | None = None
    screenshot_paths: list[str] = field(default_factory=list)
    video_path: str | None = None
    request_response: str | None = None
    tool_used: str | None = None


@dataclass
class Remediation:
    """Remediation details for vulnerability."""

    recommendation: str
    priority: str = ""
    effort_estimate: str = ""
    status: RemediationStatus = RemediationStatus.OPEN
    assigned_to: str = ""
    target_date: str = ""
    completion_date: str = ""
    notes: str = ""


@dataclass
class PentestVulnerability:
    """Individual vulnerability finding from penetration test."""

    finding_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    cvss: CVSSScore
    affected_components: list[AffectedComponent] = field(default_factory=list)
    attack_vector: AttackVector = AttackVector.NETWORK
    references: VulnerabilityReference = field(default_factory=VulnerabilityReference)
    proof_of_concept: ProofOfConcept | None = None
    remediation: Remediation | None = None
    testing_phase: TestingPhase = TestingPhase.EXPLOITATION
    discovered_date: str = ""
    verified: bool = False
    exploitable: bool = False
    business_impact: str = ""
    technical_impact: str = ""
    likelihood: str = ""
    risk_rating: str = ""

    def __post_init__(self) -> None:
        if not self.discovered_date:
            self.discovered_date = datetime.now(UTC).isoformat()
        if not self.risk_rating:
            self.risk_rating = self.severity.value


@dataclass
class TestScope:
    """Scope definition for penetration test."""

    in_scope_systems: list[str] = field(default_factory=list)
    out_of_scope_systems: list[str] = field(default_factory=list)
    testing_types: list[str] = field(default_factory=list)
    excluded_tests: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    credentials_provided: bool = False
    physical_access: bool = False
    social_engineering: bool = False


@dataclass
class TestingMethodology:
    """Testing methodology used."""

    framework: str = "PTES"
    standards: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    manual_testing: bool = True
    automated_scanning: bool = True
    custom_scripts: bool = False


@dataclass
class ExecutiveSummary:
    """Executive summary of penetration test."""

    overview: str = ""
    key_findings: list[str] = field(default_factory=list)
    risk_summary: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    overall_risk_rating: str = ""
    recommendations: list[str] = field(default_factory=list)
    positive_observations: list[str] = field(default_factory=list)


@dataclass
class PenetrationTestReport:
    """Complete penetration test report structure."""

    # Report metadata
    report_id: str = ""
    report_version: str = "1.0"
    report_date: str = ""
    report_title: str = "Penetration Test Report"
    classification: str = "Confidential"

    # Client and engagement info
    client_name: str = ""
    client_contact: str = ""
    engagement_id: str = ""
    engagement_type: str = "External Network Penetration Test"
    test_start_date: str = ""
    test_end_date: str = ""

    # Testing team
    lead_tester: str = ""
    testing_team: list[str] = field(default_factory=list)
    company_name: str = ""
    company_contact: str = ""

    # Report content
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    scope: TestScope = field(default_factory=TestScope)
    methodology: TestingMethodology = field(default_factory=TestingMethodology)
    vulnerabilities: list[PentestVulnerability] = field(default_factory=list)

    # Device under test (FDA specific)
    device_name: str = ""
    device_version: str = ""
    device_manufacturer: str = ""
    fda_510k_number: str = ""

    def __post_init__(self) -> None:
        if not self.report_date:
            self.report_date = datetime.now(UTC).isoformat()
        if not self.report_id:
            hash_input = f"{self.client_name}{self.report_date}"
            self.report_id = (
                f"PT-{hashlib.sha256(hash_input.encode()).hexdigest()[:8].upper()}"
            )


class PenetrationTestReporter:
    """Generate FDA-compliant penetration test reports."""

    def __init__(
        self,
        client_name: str = "",
        device_name: str = "",
        device_version: str = "",
        lead_tester: str = "",
        company_name: str = "",
    ) -> None:
        self.report = PenetrationTestReport(
            client_name=client_name,
            device_name=device_name,
            device_version=device_version,
            lead_tester=lead_tester,
            company_name=company_name,
        )

    def set_scope(
        self,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        testing_types: list[str] | None = None,
        ip_ranges: list[str] | None = None,
    ) -> None:
        """Define the testing scope."""
        self.report.scope = TestScope(
            in_scope_systems=in_scope,
            out_of_scope_systems=out_of_scope or [],
            testing_types=testing_types
            or [
                "Network Penetration Testing",
                "Application Security Testing",
                "Protocol Fuzzing",
                "Configuration Review",
            ],
            ip_ranges=ip_ranges or [],
        )

    def set_methodology(
        self,
        framework: str = "PTES",
        standards: list[str] | None = None,
        tools: list[str] | None = None,
    ) -> None:
        """Define testing methodology."""
        self.report.methodology = TestingMethodology(
            framework=framework,
            standards=standards
            or [
                "ANSI/ISA 62443-4-1:2018",
                "OWASP Testing Guide v4.2",
                "NIST SP 800-115",
            ],
            tools_used=tools
            or [
                "DICOM Fuzzer",
                "Nmap",
                "Burp Suite",
                "Wireshark",
                "Custom Scripts",
            ],
        )

    def add_vulnerability(
        self,
        title: str,
        description: str,
        severity: VulnerabilitySeverity | str,
        cvss_score: float,
        cvss_vector: str = "",
        cwe_id: str | None = None,
        cve_id: str | None = None,
        affected_component: str = "",
        component_version: str = "",
        attack_vector: AttackVector | str = AttackVector.NETWORK,
        proof_of_concept: str = "",
        poc_steps: list[str] | None = None,
        recommendation: str = "",
        business_impact: str = "",
        technical_impact: str = "",
    ) -> str:
        """Add a vulnerability finding to the report.

        Returns:
            The generated finding ID.

        """
        # Generate finding ID
        finding_num = len(self.report.vulnerabilities) + 1
        finding_id = f"{self.report.report_id}-{finding_num:03d}"

        # Handle string severity
        if isinstance(severity, str):
            severity = VulnerabilitySeverity(severity)

        # Handle string attack vector
        if isinstance(attack_vector, str):
            attack_vector = AttackVector(attack_vector)

        # Build CVSS score
        cvss = CVSSScore(
            base_score=cvss_score,
            vector_string=cvss_vector,
        )

        # Build references
        references = VulnerabilityReference(
            cwe_id=cwe_id,
            cve_id=cve_id,
        )

        # Build affected components
        affected = []
        if affected_component:
            affected.append(
                AffectedComponent(
                    name=affected_component,
                    version=component_version,
                )
            )

        # Build PoC if provided
        poc = None
        if proof_of_concept or poc_steps:
            poc = ProofOfConcept(
                description=proof_of_concept,
                steps=poc_steps or [],
            )

        # Build remediation
        remediation = None
        if recommendation:
            remediation = Remediation(recommendation=recommendation)

        vuln = PentestVulnerability(
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            cvss=cvss,
            affected_components=affected,
            attack_vector=attack_vector,
            references=references,
            proof_of_concept=poc,
            remediation=remediation,
            business_impact=business_impact,
            technical_impact=technical_impact,
        )

        self.report.vulnerabilities.append(vuln)
        return finding_id

    def generate_executive_summary(self) -> ExecutiveSummary:
        """Auto-generate executive summary from vulnerabilities."""
        summary = ExecutiveSummary()

        # Count by severity
        for vuln in self.report.vulnerabilities:
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                summary.critical_count += 1
            elif vuln.severity == VulnerabilitySeverity.HIGH:
                summary.high_count += 1
            elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                summary.medium_count += 1
            elif vuln.severity == VulnerabilitySeverity.LOW:
                summary.low_count += 1
            else:
                summary.info_count += 1

        # Generate overview
        total = len(self.report.vulnerabilities)
        summary.overview = (
            f"A penetration test was conducted on {self.report.device_name or 'the target system'} "
            f"from {self.report.test_start_date or 'N/A'} to {self.report.test_end_date or 'N/A'}. "
            f"The assessment identified {total} vulnerabilities: "
            f"{summary.critical_count} Critical, {summary.high_count} High, "
            f"{summary.medium_count} Medium, {summary.low_count} Low, "
            f"and {summary.info_count} Informational."
        )

        # Key findings (top 5 by severity)
        sorted_vulns = sorted(
            self.report.vulnerabilities,
            key=lambda v: v.cvss.base_score,
            reverse=True,
        )
        for vuln in sorted_vulns[:5]:
            summary.key_findings.append(
                f"{vuln.severity.value}: {vuln.title} (CVSS {vuln.cvss.base_score})"
            )

        # Overall risk rating
        if summary.critical_count > 0:
            summary.overall_risk_rating = "Critical"
        elif summary.high_count > 0:
            summary.overall_risk_rating = "High"
        elif summary.medium_count > 0:
            summary.overall_risk_rating = "Medium"
        elif summary.low_count > 0:
            summary.overall_risk_rating = "Low"
        else:
            summary.overall_risk_rating = "Informational"

        # Risk summary
        summary.risk_summary = (
            f"The overall risk rating for {self.report.device_name or 'the target'} is "
            f"**{summary.overall_risk_rating}**. "
        )
        if summary.critical_count > 0 or summary.high_count > 0:
            summary.risk_summary += "Immediate remediation is recommended for Critical and High severity findings."

        # Generate recommendations
        if summary.critical_count > 0:
            summary.recommendations.append(
                "Address all Critical severity findings immediately before deployment."
            )
        if summary.high_count > 0:
            summary.recommendations.append(
                "Remediate High severity findings within 30 days."
            )
        if summary.medium_count > 0:
            summary.recommendations.append(
                "Plan remediation for Medium severity findings within 90 days."
            )

        self.report.executive_summary = summary
        return summary

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        self.generate_executive_summary()

        def convert_dataclass(obj: Any) -> Any:
            if hasattr(obj, "__dataclass_fields__"):
                result = {}
                for k, v in asdict(obj).items():
                    if isinstance(v, Enum):
                        result[k] = v.value
                    elif isinstance(v, list):
                        result[k] = [
                            convert_dataclass(item)
                            if hasattr(item, "__dataclass_fields__")
                            else item
                            for item in v
                        ]
                    else:
                        result[k] = v
                return result
            return obj

        result = convert_dataclass(self.report)
        return dict(result) if isinstance(result, dict) else {}

    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, path: Path | str) -> Path:
        """Save report as JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())
        return path

    def generate_markdown(self) -> str:
        """Generate FDA-compliant markdown report."""
        self.generate_executive_summary()
        summary = self.report.executive_summary

        md = f"""# {self.report.report_title}

## Document Information

| Field | Value |
|-------|-------|
| Report ID | {self.report.report_id} |
| Report Date | {self.report.report_date} |
| Classification | {self.report.classification} |
| Client | {self.report.client_name or "N/A"} |
| Engagement Type | {self.report.engagement_type} |

---

## Device Under Test (FDA Section 8)

| Field | Value |
|-------|-------|
| Device Name | {self.report.device_name or "N/A"} |
| Device Version | {self.report.device_version or "N/A"} |
| Manufacturer | {self.report.device_manufacturer or "N/A"} |
| 510(k) Number | {self.report.fda_510k_number or "N/A"} |

---

## 1. Executive Summary

{summary.overview}

### 1.1 Risk Summary

{summary.risk_summary}

### 1.2 Vulnerability Distribution

| Severity | Count |
|----------|-------|
| Critical | {summary.critical_count} |
| High | {summary.high_count} |
| Medium | {summary.medium_count} |
| Low | {summary.low_count} |
| Informational | {summary.info_count} |
| **Total** | **{len(self.report.vulnerabilities)}** |

### 1.3 Key Findings

"""
        for finding in summary.key_findings:
            md += f"- {finding}\n"

        md += """
### 1.4 Recommendations

"""
        for rec in summary.recommendations:
            md += f"- {rec}\n"

        md += """
---

## 2. Scope of Assessment

### 2.1 In-Scope Systems

"""
        for system in self.report.scope.in_scope_systems:
            md += f"- {system}\n"

        md += """
### 2.2 Testing Types

"""
        for test_type in self.report.scope.testing_types:
            md += f"- {test_type}\n"

        md += f"""
---

## 3. Methodology

**Framework:** {self.report.methodology.framework}

### 3.1 Standards Applied

"""
        for standard in self.report.methodology.standards:
            md += f"- {standard}\n"

        md += """
### 3.2 Tools Used

"""
        for tool in self.report.methodology.tools_used:
            md += f"- {tool}\n"

        md += """
---

## 4. Detailed Findings

"""
        for i, vuln in enumerate(self.report.vulnerabilities, 1):
            md += f"""### 4.{i} {vuln.title}

| Attribute | Value |
|-----------|-------|
| Finding ID | {vuln.finding_id} |
| Severity | {vuln.severity.value} |
| CVSS Score | {vuln.cvss.base_score} |
| CVSS Vector | {vuln.cvss.vector_string or "N/A"} |
| CWE | {vuln.references.cwe_id or "N/A"} |
| CVE | {vuln.references.cve_id or "N/A"} |
| Attack Vector | {vuln.attack_vector.value} |

**Description:**

{vuln.description}

"""
            if vuln.affected_components:
                md += "**Affected Components:**\n\n"
                for comp in vuln.affected_components:
                    md += f"- {comp.name} {comp.version}\n"
                md += "\n"

            if vuln.proof_of_concept:
                md += f"""**Proof of Concept:**

{vuln.proof_of_concept.description}

"""
                if vuln.proof_of_concept.steps:
                    md += "**Steps to Reproduce:**\n\n"
                    for j, step in enumerate(vuln.proof_of_concept.steps, 1):
                        md += f"{j}. {step}\n"
                    md += "\n"

            if vuln.business_impact:
                md += f"**Business Impact:** {vuln.business_impact}\n\n"

            if vuln.technical_impact:
                md += f"**Technical Impact:** {vuln.technical_impact}\n\n"

            if vuln.remediation:
                md += f"""**Remediation:**

{vuln.remediation.recommendation}

| Status | {vuln.remediation.status.value} |
|--------|------|

"""
            md += "---\n\n"

        md += """## 5. Appendix

### 5.1 Testing Timeline

| Phase | Dates |
|-------|-------|
"""
        md += f"| Testing Start | {self.report.test_start_date or 'N/A'} |\n"
        md += f"| Testing End | {self.report.test_end_date or 'N/A'} |\n"
        md += f"| Report Date | {self.report.report_date} |\n"

        md += f"""
### 5.2 Testing Team

| Role | Name |
|------|------|
| Lead Tester | {self.report.lead_tester or "N/A"} |
"""
        for member in self.report.testing_team:
            md += f"| Team Member | {member} |\n"

        md += """
---

## References

- FDA Cybersecurity Guidance (June 2025): "Cybersecurity in Medical Devices"
- ANSI/ISA 62443-4-1:2018 Section 9.4: Security Verification and Validation
- OWASP Testing Guide v4.2
- PTES (Penetration Testing Execution Standard)
- CVSS v3.1 Specification

---

*This report was generated by DICOM Fuzzer for FDA premarket cybersecurity submission documentation.*
"""
        return md

    def save_markdown(self, path: Path | str) -> Path:
        """Save report as markdown."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_markdown())
        return path


def create_sample_pentest_report() -> PenetrationTestReporter:
    """Create a sample penetration test report for demonstration."""
    reporter = PenetrationTestReporter(
        client_name="Medical Device Corp",
        device_name="DICOM PACS Server",
        device_version="3.2.1",
        lead_tester="Security Engineer",
        company_name="Security Testing Firm",
    )

    reporter.report.test_start_date = "2025-01-15"
    reporter.report.test_end_date = "2025-01-20"
    reporter.report.device_manufacturer = "Medical Device Corp"

    reporter.set_scope(
        in_scope=[
            "DICOM PACS Server (192.168.1.100)",
            "DICOM Web Interface",
            "DICOM Protocol Implementation",
        ],
        testing_types=[
            "Network Penetration Testing",
            "DICOM Protocol Fuzzing",
            "Web Application Testing",
            "Configuration Review",
        ],
    )

    reporter.set_methodology(
        framework="PTES",
        standards=[
            "ANSI/ISA 62443-4-1:2018",
            "OWASP Testing Guide v4.2",
            "FDA Cybersecurity Guidance (June 2025)",
        ],
        tools=["DICOM Fuzzer", "Nmap", "Burp Suite", "Wireshark"],
    )

    # Sample vulnerabilities
    reporter.add_vulnerability(
        title="DICOM Association Rejection Bypass",
        description=(
            "The DICOM server accepts associations from any AE Title without "
            "proper validation, allowing unauthorized access to medical images."
        ),
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-287",
        affected_component="DICOM Association Handler",
        component_version="3.2.1",
        recommendation=(
            "Implement AE Title whitelist validation and configure proper "
            "access controls for DICOM associations."
        ),
        business_impact="Unauthorized access to protected health information (PHI)",
        technical_impact="Complete bypass of authentication controls",
    )

    reporter.add_vulnerability(
        title="Buffer Overflow in DICOM Parser",
        description=(
            "A buffer overflow vulnerability exists in the DICOM file parser "
            "when processing malformed Transfer Syntax UIDs exceeding 64 bytes."
        ),
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-120",
        cve_id="CVE-2025-XXXX",
        affected_component="DICOM Parser",
        component_version="3.2.1",
        proof_of_concept="Send malformed A-ASSOCIATE-RQ with oversized Transfer Syntax UID",
        poc_steps=[
            "Connect to DICOM port 104",
            "Send A-ASSOCIATE-RQ with Transfer Syntax UID > 64 bytes",
            "Observe server crash",
        ],
        recommendation=(
            "Validate Transfer Syntax UID length before buffer copy. "
            "Implement bounds checking for all UID fields."
        ),
        business_impact="Remote code execution could compromise entire PACS system",
        technical_impact="Memory corruption leading to potential RCE",
    )

    return reporter


if __name__ == "__main__":
    reporter = create_sample_pentest_report()
    print(reporter.generate_markdown())
