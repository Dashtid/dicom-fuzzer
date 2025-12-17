"""Security Risk Management Report Generator for FDA eSTAR.

Generates security risk management documentation compliant with FDA June 2025
Cybersecurity Guidance and eSTAR (electronic Submission Template And Resource).

FDA Requirements:
- Security risk analysis documenting identified risks
- Risk evaluation with severity and likelihood
- Risk control measures implemented
- Residual risk acceptance rationale
- Traceability matrix linking risks to controls

References:
- FDA Cybersecurity Guidance (June 2025) Section V.A
- ISO 14971:2019 (Medical device risk management)
- IEC 62443-4-1 (Product security development lifecycle)
- AAMI TIR57 (Principles for medical device security)

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class RiskSeverity(Enum):
    """Severity levels per ISO 14971."""

    NEGLIGIBLE = 1
    MINOR = 2
    SERIOUS = 3
    CRITICAL = 4
    CATASTROPHIC = 5


class RiskLikelihood(Enum):
    """Likelihood levels for risk occurrence."""

    IMPROBABLE = 1
    REMOTE = 2
    OCCASIONAL = 3
    PROBABLE = 4
    FREQUENT = 5


class RiskAcceptability(Enum):
    """Risk acceptability determination."""

    ACCEPTABLE = "Acceptable"
    ALARP = "ALARP"  # As Low As Reasonably Practicable
    UNACCEPTABLE = "Unacceptable"


@dataclass
class SecurityRisk:
    """Individual security risk entry."""

    risk_id: str
    title: str
    description: str
    threat_source: str
    vulnerability: str
    asset_affected: str
    severity: RiskSeverity
    likelihood: RiskLikelihood
    initial_risk_score: int = 0
    control_measures: list[str] = field(default_factory=list)
    residual_severity: RiskSeverity | None = None
    residual_likelihood: RiskLikelihood | None = None
    residual_risk_score: int = 0
    acceptability: RiskAcceptability = RiskAcceptability.UNACCEPTABLE
    rationale: str = ""
    cve_references: list[str] = field(default_factory=list)
    test_evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Calculate initial risk score."""
        self.initial_risk_score = self.severity.value * self.likelihood.value
        if self.residual_severity and self.residual_likelihood:
            self.residual_risk_score = (
                self.residual_severity.value * self.residual_likelihood.value
            )


@dataclass
class RiskControlMeasure:
    """Risk control measure documentation."""

    control_id: str
    title: str
    description: str
    control_type: str  # Prevention, Detection, Mitigation
    implementation_status: str
    verification_method: str
    linked_risks: list[str] = field(default_factory=list)


@dataclass
class SecurityRiskReportConfig:
    """Configuration for security risk report generation."""

    # Document metadata
    document_number: str = ""
    document_version: str = "1.0"
    organization_name: str = ""
    product_name: str = ""
    software_version: str = ""
    submission_type: str = "510(k)"  # 510(k), PMA, De Novo

    # Risk analysis parameters
    risk_matrix_rows: int = 5  # Severity levels
    risk_matrix_cols: int = 5  # Likelihood levels
    acceptable_threshold: int = 6  # Risk score <= this is acceptable
    alarp_threshold: int = 12  # Risk score <= this requires ALARP

    # Stakeholders
    prepared_by: str = ""
    reviewed_by: str = ""
    approved_by: str = ""


class SecurityRiskReportGenerator:
    """Generate FDA-compliant Security Risk Management Report."""

    def __init__(self, config: SecurityRiskReportConfig | None = None) -> None:
        self.config = config or SecurityRiskReportConfig()
        self.risks: list[SecurityRisk] = []
        self.controls: list[RiskControlMeasure] = []

    def add_risk(self, risk: SecurityRisk) -> None:
        """Add a security risk to the report."""
        self.risks.append(risk)

    def add_control(self, control: RiskControlMeasure) -> None:
        """Add a risk control measure."""
        self.controls.append(control)

    def add_standard_dicom_risks(self) -> None:
        """Add standard DICOM-related security risks."""
        standard_risks = [
            SecurityRisk(
                risk_id="SR-001",
                title="Malformed DICOM Header Exploitation",
                description=(
                    "Attacker crafts DICOM file with malformed header to exploit "
                    "parsing vulnerabilities in the device software."
                ),
                threat_source="Malicious Actor",
                vulnerability="Insufficient input validation of DICOM headers",
                asset_affected="DICOM Parser Module",
                severity=RiskSeverity.CRITICAL,
                likelihood=RiskLikelihood.OCCASIONAL,
                control_measures=[
                    "Input validation for all DICOM header fields",
                    "Bounds checking on all length fields",
                    "Fuzz testing with malformed inputs",
                ],
                residual_severity=RiskSeverity.MINOR,
                residual_likelihood=RiskLikelihood.REMOTE,
                acceptability=RiskAcceptability.ACCEPTABLE,
                rationale="Comprehensive input validation and fuzz testing reduce risk",
                cve_references=["CVE-2019-11687", "CVE-2024-41952"],
                test_evidence=["Fuzz test report", "Static analysis report"],
            ),
            SecurityRisk(
                risk_id="SR-002",
                title="Buffer Overflow in Pixel Data Processing",
                description=(
                    "Maliciously crafted PixelData element causes buffer overflow "
                    "during decompression or rendering."
                ),
                threat_source="Malicious Actor",
                vulnerability="Unchecked buffer sizes in pixel processing",
                asset_affected="Image Rendering Engine",
                severity=RiskSeverity.CATASTROPHIC,
                likelihood=RiskLikelihood.REMOTE,
                control_measures=[
                    "Safe memory allocation with size limits",
                    "AddressSanitizer testing",
                    "Memory-safe decompression libraries",
                ],
                residual_severity=RiskSeverity.SERIOUS,
                residual_likelihood=RiskLikelihood.IMPROBABLE,
                acceptability=RiskAcceptability.ALARP,
                rationale=(
                    "Memory safety measures significantly reduce likelihood; "
                    "residual risk accepted with monitoring"
                ),
                cve_references=["CVE-2021-33034", "CVE-2024-36049"],
                test_evidence=["ASan test results", "Penetration test report"],
            ),
            SecurityRisk(
                risk_id="SR-003",
                title="Path Traversal via DICOM Filename",
                description=(
                    "Attacker uses path traversal sequences in DICOM metadata "
                    "fields to write files outside intended directories."
                ),
                threat_source="Malicious Actor",
                vulnerability="Insufficient path sanitization",
                asset_affected="File Storage System",
                severity=RiskSeverity.CRITICAL,
                likelihood=RiskLikelihood.OCCASIONAL,
                control_measures=[
                    "Path canonicalization and validation",
                    "Whitelist-based filename filtering",
                    "Sandboxed file operations",
                ],
                residual_severity=RiskSeverity.MINOR,
                residual_likelihood=RiskLikelihood.IMPROBABLE,
                acceptability=RiskAcceptability.ACCEPTABLE,
                rationale="Path validation controls effectively prevent exploitation",
                cve_references=["CVE-2022-2121", "CVE-2024-22281"],
                test_evidence=["Path traversal test results"],
            ),
            SecurityRisk(
                risk_id="SR-004",
                title="XML External Entity (XXE) in DICOM-SR",
                description=(
                    "DICOM Structured Reports containing XML may be vulnerable "
                    "to XXE attacks allowing data exfiltration."
                ),
                threat_source="Malicious Actor",
                vulnerability="Unsafe XML parser configuration",
                asset_affected="Structured Report Parser",
                severity=RiskSeverity.SERIOUS,
                likelihood=RiskLikelihood.REMOTE,
                control_measures=[
                    "Disable external entity processing",
                    "Use defused XML library",
                    "Input validation for SR content",
                ],
                residual_severity=RiskSeverity.NEGLIGIBLE,
                residual_likelihood=RiskLikelihood.IMPROBABLE,
                acceptability=RiskAcceptability.ACCEPTABLE,
                rationale="XXE disabled at parser level eliminates vulnerability",
                cve_references=["CVE-2023-38249"],
                test_evidence=["XXE penetration test results"],
            ),
            SecurityRisk(
                risk_id="SR-005",
                title="Denial of Service via Resource Exhaustion",
                description=(
                    "Attacker sends DICOM files designed to exhaust memory or "
                    "CPU resources, causing system unavailability."
                ),
                threat_source="Malicious Actor",
                vulnerability="Lack of resource limits",
                asset_affected="System Resources",
                severity=RiskSeverity.SERIOUS,
                likelihood=RiskLikelihood.PROBABLE,
                control_measures=[
                    "File size limits",
                    "Processing timeouts",
                    "Memory allocation limits",
                    "Rate limiting",
                ],
                residual_severity=RiskSeverity.MINOR,
                residual_likelihood=RiskLikelihood.OCCASIONAL,
                acceptability=RiskAcceptability.ALARP,
                rationale=(
                    "Resource limits reduce impact; some DoS risk inherent "
                    "in network services"
                ),
                cve_references=["CVE-2025-5943"],
                test_evidence=["Load test results", "Stress test report"],
            ),
            SecurityRisk(
                risk_id="SR-006",
                title="Authentication Bypass in DICOM C-STORE",
                description=(
                    "Attacker bypasses authentication to send unauthorized "
                    "DICOM files to the system."
                ),
                threat_source="Malicious Actor",
                vulnerability="Weak or missing authentication",
                asset_affected="DICOM Network Interface",
                severity=RiskSeverity.CRITICAL,
                likelihood=RiskLikelihood.OCCASIONAL,
                control_measures=[
                    "TLS mutual authentication",
                    "AE Title validation",
                    "Network segmentation",
                    "Audit logging",
                ],
                residual_severity=RiskSeverity.MINOR,
                residual_likelihood=RiskLikelihood.REMOTE,
                acceptability=RiskAcceptability.ACCEPTABLE,
                rationale="Strong authentication and network controls mitigate risk",
                cve_references=[],
                test_evidence=["Authentication test results", "Network scan report"],
            ),
        ]

        for risk in standard_risks:
            self.add_risk(risk)

    def add_standard_controls(self) -> None:
        """Add standard risk control measures."""
        standard_controls = [
            RiskControlMeasure(
                control_id="RC-001",
                title="Input Validation Framework",
                description=(
                    "Comprehensive input validation for all DICOM data elements "
                    "including bounds checking, type validation, and format verification."
                ),
                control_type="Prevention",
                implementation_status="Implemented",
                verification_method="Unit tests, fuzz testing, code review",
                linked_risks=["SR-001", "SR-002", "SR-003"],
            ),
            RiskControlMeasure(
                control_id="RC-002",
                title="Memory Safety Measures",
                description=(
                    "Use of memory-safe programming practices including bounds-checked "
                    "arrays, smart pointers, and sanitizer testing."
                ),
                control_type="Prevention",
                implementation_status="Implemented",
                verification_method="AddressSanitizer, static analysis",
                linked_risks=["SR-002"],
            ),
            RiskControlMeasure(
                control_id="RC-003",
                title="Secure XML Processing",
                description=(
                    "XML parser configured to disable external entities, DTD processing, "
                    "and other potentially dangerous features."
                ),
                control_type="Prevention",
                implementation_status="Implemented",
                verification_method="Security testing, code review",
                linked_risks=["SR-004"],
            ),
            RiskControlMeasure(
                control_id="RC-004",
                title="Resource Limiting",
                description=(
                    "Implementation of file size limits, processing timeouts, "
                    "memory allocation caps, and rate limiting."
                ),
                control_type="Mitigation",
                implementation_status="Implemented",
                verification_method="Load testing, stress testing",
                linked_risks=["SR-005"],
            ),
            RiskControlMeasure(
                control_id="RC-005",
                title="Network Security Controls",
                description=(
                    "TLS encryption, mutual authentication, AE Title validation, "
                    "and network segmentation for DICOM communications."
                ),
                control_type="Prevention",
                implementation_status="Implemented",
                verification_method="Penetration testing, network scan",
                linked_risks=["SR-006"],
            ),
            RiskControlMeasure(
                control_id="RC-006",
                title="Security Monitoring",
                description=(
                    "Logging of security-relevant events, anomaly detection, "
                    "and alerting for suspicious activity."
                ),
                control_type="Detection",
                implementation_status="Implemented",
                verification_method="Log review, alert testing",
                linked_risks=["SR-001", "SR-005", "SR-006"],
            ),
        ]

        for control in standard_controls:
            self.add_control(control)

    def _generate_risk_matrix_table(self) -> str:
        """Generate risk matrix table."""
        table = """
### Risk Acceptability Matrix

| Likelihood \\ Severity | Negligible (1) | Minor (2) | Serious (3) | Critical (4) | Catastrophic (5) |
|------------------------|----------------|-----------|-------------|--------------|------------------|
| **Frequent (5)**       | 5 (ALARP)      | 10 (ALARP)| 15 (UNACCEPTABLE) | 20 (UNACCEPTABLE) | 25 (UNACCEPTABLE) |
| **Probable (4)**       | 4 (Acceptable) | 8 (ALARP) | 12 (ALARP)  | 16 (UNACCEPTABLE) | 20 (UNACCEPTABLE) |
| **Occasional (3)**     | 3 (Acceptable) | 6 (ALARP) | 9 (ALARP)   | 12 (ALARP)   | 15 (UNACCEPTABLE) |
| **Remote (2)**         | 2 (Acceptable) | 4 (Acceptable) | 6 (ALARP) | 8 (ALARP)    | 10 (ALARP)        |
| **Improbable (1)**     | 1 (Acceptable) | 2 (Acceptable) | 3 (Acceptable) | 4 (Acceptable) | 5 (ALARP)         |

**Legend:**
- **Acceptable** (Score 1-6): Risk is acceptable without further action
- **ALARP** (Score 7-12): Risk reduced As Low As Reasonably Practicable
- **Unacceptable** (Score 13-25): Risk requires additional controls
"""
        return table

    def generate_report_markdown(self) -> str:
        """Generate the security risk management report in Markdown."""
        cfg = self.config
        now = datetime.now(UTC).strftime("%Y-%m-%d")

        report = f"""# Security Risk Management Report

**Document Number:** {cfg.document_number or "SRM-001"}
**Version:** {cfg.document_version}
**Date:** {now}

---

## Document Information

| Field | Value |
|-------|-------|
| Organization | {cfg.organization_name or "[Organization Name]"} |
| Product Name | {cfg.product_name or "[Product Name]"} |
| Software Version | {cfg.software_version or "[Version]"} |
| Submission Type | {cfg.submission_type} |
| Prepared By | {cfg.prepared_by or "[Name]"} |
| Reviewed By | {cfg.reviewed_by or "[Name]"} |
| Approved By | {cfg.approved_by or "[Name]"} |

---

## 1. Purpose and Scope

### 1.1 Purpose

This Security Risk Management Report documents the security risk analysis conducted
for {cfg.product_name or "[Product Name]"} in accordance with FDA Cybersecurity
Guidance (June 2025) and ISO 14971:2019. The report identifies cybersecurity risks,
evaluates their severity and likelihood, documents risk control measures, and
provides residual risk acceptance rationale.

### 1.2 Scope

This analysis covers:
- DICOM file parsing and processing
- Network communication interfaces
- Data storage and retrieval
- User interface components
- Third-party dependencies

### 1.3 Referenced Standards

| Standard | Title |
|----------|-------|
| FDA Guidance | Cybersecurity in Medical Devices (June 2025) |
| ISO 14971:2019 | Medical devices - Risk management |
| IEC 62443-4-1 | Product security development lifecycle |
| AAMI TIR57 | Principles for medical device security |
| NIST CSF | Cybersecurity Framework |

---

## 2. Risk Management Process

### 2.1 Methodology

The security risk analysis follows the process defined in ISO 14971:2019 adapted
for cybersecurity per AAMI TIR57:

1. **Hazard Identification**: Identify potential security threats and vulnerabilities
2. **Risk Estimation**: Estimate severity of harm and likelihood of occurrence
3. **Risk Evaluation**: Compare estimated risk against acceptability criteria
4. **Risk Control**: Implement measures to reduce unacceptable risks
5. **Residual Risk Assessment**: Evaluate remaining risk after controls
6. **Risk Acceptance**: Document rationale for accepting residual risks

### 2.2 Risk Estimation Criteria

#### Severity Levels

| Level | Category | Description |
|-------|----------|-------------|
| 5 | Catastrophic | Death or permanent impairment |
| 4 | Critical | Temporary impairment or injury requiring intervention |
| 3 | Serious | Medical treatment required |
| 2 | Minor | Minor injury, no medical treatment needed |
| 1 | Negligible | Inconvenience or temporary discomfort |

#### Likelihood Levels

| Level | Category | Probability |
|-------|----------|-------------|
| 5 | Frequent | Likely to occur often |
| 4 | Probable | Will probably occur several times |
| 3 | Occasional | Likely to occur sometime |
| 2 | Remote | Unlikely but possible |
| 1 | Improbable | Very unlikely to occur |

{self._generate_risk_matrix_table()}

---

## 3. Security Risk Analysis

### 3.1 Identified Risks

"""
        # Add each risk
        for risk in self.risks:
            report += f"""#### {risk.risk_id}: {risk.title}

| Attribute | Value |
|-----------|-------|
| Description | {risk.description} |
| Threat Source | {risk.threat_source} |
| Vulnerability | {risk.vulnerability} |
| Asset Affected | {risk.asset_affected} |
| Initial Severity | {risk.severity.name} ({risk.severity.value}) |
| Initial Likelihood | {risk.likelihood.name} ({risk.likelihood.value}) |
| **Initial Risk Score** | **{risk.initial_risk_score}** |

**Control Measures:**
"""
            for measure in risk.control_measures:
                report += f"- {measure}\n"

            report += f"""
| Residual Attribute | Value |
|-------------------|-------|
| Residual Severity | {risk.residual_severity.name if risk.residual_severity else "N/A"} ({risk.residual_severity.value if risk.residual_severity else "-"}) |
| Residual Likelihood | {risk.residual_likelihood.name if risk.residual_likelihood else "N/A"} ({risk.residual_likelihood.value if risk.residual_likelihood else "-"}) |
| **Residual Risk Score** | **{risk.residual_risk_score}** |
| **Acceptability** | **{risk.acceptability.value}** |

**Acceptance Rationale:** {risk.rationale}

"""
            if risk.cve_references:
                report += (
                    "**CVE References:** " + ", ".join(risk.cve_references) + "\n\n"
                )
            if risk.test_evidence:
                report += "**Test Evidence:** " + ", ".join(risk.test_evidence) + "\n\n"

            report += "---\n\n"

        # Risk summary table
        report += """### 3.2 Risk Summary

| Risk ID | Title | Initial Score | Residual Score | Acceptability |
|---------|-------|---------------|----------------|---------------|
"""
        for risk in self.risks:
            report += (
                f"| {risk.risk_id} | {risk.title} | {risk.initial_risk_score} | "
                f"{risk.residual_risk_score} | {risk.acceptability.value} |\n"
            )

        # Controls section
        report += """
---

## 4. Risk Control Measures

### 4.1 Control Measures Summary

"""
        for control in self.controls:
            report += f"""#### {control.control_id}: {control.title}

| Attribute | Value |
|-----------|-------|
| Description | {control.description} |
| Control Type | {control.control_type} |
| Implementation Status | {control.implementation_status} |
| Verification Method | {control.verification_method} |
| Linked Risks | {", ".join(control.linked_risks)} |

"""

        # Traceability matrix
        report += """### 4.2 Risk-Control Traceability Matrix

| Risk ID | Control IDs |
|---------|-------------|
"""
        for risk in self.risks:
            linked_controls = [
                c.control_id for c in self.controls if risk.risk_id in c.linked_risks
            ]
            report += f"| {risk.risk_id} | {', '.join(linked_controls) or 'None'} |\n"

        # Residual risk section
        report += f"""
---

## 5. Residual Risk Evaluation

### 5.1 Overall Residual Risk

After implementation of all risk control measures, the overall residual risk
of {cfg.product_name or "[Product Name]"} has been evaluated.

**Summary:**
- Total risks identified: {len(self.risks)}
- Risks acceptable: {sum(1 for r in self.risks if r.acceptability == RiskAcceptability.ACCEPTABLE)}
- Risks ALARP: {sum(1 for r in self.risks if r.acceptability == RiskAcceptability.ALARP)}
- Risks unacceptable: {sum(1 for r in self.risks if r.acceptability == RiskAcceptability.UNACCEPTABLE)}

### 5.2 Benefit-Risk Analysis

The benefits of {cfg.product_name or "[Product Name]"} include:
- [Document specific clinical benefits]
- [Document patient safety improvements]
- [Document workflow efficiencies]

These benefits outweigh the residual cybersecurity risks when the device
is used as intended and maintained per manufacturer instructions.

### 5.3 Residual Risk Acceptance Statement

Based on the security risk analysis documented herein, all identified
cybersecurity risks have been reduced to acceptable levels or ALARP.
The residual risks are acceptable considering the clinical benefits
provided by the device.

---

## 6. Post-Market Surveillance

### 6.1 Ongoing Risk Monitoring

The following activities support ongoing security risk management:
- Vulnerability monitoring (CVE databases, security advisories)
- Customer feedback and complaint analysis
- Security incident response process
- Coordinated Vulnerability Disclosure (CVD) program
- Periodic risk re-evaluation

### 6.2 Update Triggers

This risk analysis will be updated when:
- New vulnerabilities are discovered
- Significant software changes are made
- Security incidents occur
- New threat intelligence is received
- Regulatory requirements change

---

## 7. Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Prepared By | {cfg.prepared_by or "[Name]"} | _______________ | {now} |
| Reviewed By | {cfg.reviewed_by or "[Name]"} | _______________ | {now} |
| Approved By | {cfg.approved_by or "[Name]"} | _______________ | {now} |

---

## Appendix A: FDA Compliance Mapping

| FDA Requirement | Section Reference |
|-----------------|-------------------|
| Security risk analysis | Section 3 |
| Risk evaluation criteria | Section 2.2 |
| Risk control documentation | Section 4 |
| Residual risk acceptance | Section 5.3 |
| Post-market surveillance | Section 6 |

---

*This report was generated by DICOM Fuzzer for FDA cybersecurity compliance.*
"""
        return report

    def generate_report_json(self) -> dict[str, Any]:
        """Generate the security risk report as JSON."""
        cfg = self.config
        return {
            "document_info": {
                "document_number": cfg.document_number,
                "version": cfg.document_version,
                "date": datetime.now(UTC).isoformat(),
                "organization": cfg.organization_name,
                "product": cfg.product_name,
                "software_version": cfg.software_version,
                "submission_type": cfg.submission_type,
            },
            "risk_criteria": {
                "acceptable_threshold": cfg.acceptable_threshold,
                "alarp_threshold": cfg.alarp_threshold,
            },
            "risks": [
                {
                    "risk_id": r.risk_id,
                    "title": r.title,
                    "description": r.description,
                    "threat_source": r.threat_source,
                    "vulnerability": r.vulnerability,
                    "asset_affected": r.asset_affected,
                    "initial_severity": r.severity.name,
                    "initial_likelihood": r.likelihood.name,
                    "initial_risk_score": r.initial_risk_score,
                    "control_measures": r.control_measures,
                    "residual_severity": r.residual_severity.name
                    if r.residual_severity
                    else None,
                    "residual_likelihood": r.residual_likelihood.name
                    if r.residual_likelihood
                    else None,
                    "residual_risk_score": r.residual_risk_score,
                    "acceptability": r.acceptability.value,
                    "rationale": r.rationale,
                    "cve_references": r.cve_references,
                    "test_evidence": r.test_evidence,
                }
                for r in self.risks
            ],
            "controls": [
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "description": c.description,
                    "control_type": c.control_type,
                    "implementation_status": c.implementation_status,
                    "verification_method": c.verification_method,
                    "linked_risks": c.linked_risks,
                }
                for c in self.controls
            ],
            "summary": {
                "total_risks": len(self.risks),
                "acceptable_count": sum(
                    1
                    for r in self.risks
                    if r.acceptability == RiskAcceptability.ACCEPTABLE
                ),
                "alarp_count": sum(
                    1 for r in self.risks if r.acceptability == RiskAcceptability.ALARP
                ),
                "unacceptable_count": sum(
                    1
                    for r in self.risks
                    if r.acceptability == RiskAcceptability.UNACCEPTABLE
                ),
            },
        }

    def save_report(self, output_path: Path | str, format: str = "markdown") -> Path:
        """Save the security risk report to file.

        Args:
            output_path: Output file path
            format: Output format ('markdown' or 'json')

        Returns:
            Path to saved file

        """
        import json

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(self.generate_report_json(), f, indent=2)
        else:
            output_path.write_text(self.generate_report_markdown())

        return output_path


def generate_security_risk_report(
    organization: str = "",
    product: str = "",
    output_path: Path | str | None = None,
    include_standard_risks: bool = True,
) -> str:
    """Generate a security risk report with minimal configuration.

    Args:
        organization: Organization name
        product: Product name
        output_path: Optional path to save the report
        include_standard_risks: Include standard DICOM security risks

    Returns:
        Report content as string

    """
    config = SecurityRiskReportConfig(
        organization_name=organization,
        product_name=product,
    )

    generator = SecurityRiskReportGenerator(config)

    if include_standard_risks:
        generator.add_standard_dicom_risks()
        generator.add_standard_controls()

    report = generator.generate_report_markdown()

    if output_path:
        generator.save_report(output_path)

    return report


if __name__ == "__main__":
    # Generate sample report
    config = SecurityRiskReportConfig(
        document_number="SRM-DICOM-001",
        organization_name="Medical Device Corp",
        product_name="DICOM Viewer Pro",
        software_version="2.0.0",
        submission_type="510(k)",
        prepared_by="Security Team",
        reviewed_by="QA Manager",
        approved_by="VP Engineering",
    )

    generator = SecurityRiskReportGenerator(config)
    generator.add_standard_dicom_risks()
    generator.add_standard_controls()

    print(generator.generate_report_markdown())
