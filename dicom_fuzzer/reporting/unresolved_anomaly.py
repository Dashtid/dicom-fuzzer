"""Unresolved Anomaly Assessment Generator for FDA Premarket Submissions.

Generates documentation for software anomalies (bugs/defects) identified during
testing that remain unresolved at time of release, per FDA guidance.

FDA Requirements:
- List of all known anomalies not corrected prior to release
- Assessment of each anomaly's impact on safety and effectiveness
- Rationale for acceptability of releasing with known anomalies
- Sequence of events that could lead to patient harm

References:
- FDA Guidance: Content of Premarket Submissions for Device Software Functions
- FDA Guidance: Cybersecurity in Medical Devices (June 2025)
- IEC 62304:2006+AMD1:2015 (Medical device software lifecycle)
- ISO 14971:2019 (Risk management)

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class AnomalySeverity(Enum):
    """Anomaly severity classification per IEC 62304."""

    MINOR = "Minor"
    MAJOR = "Major"
    CRITICAL = "Critical"


class AnomalyType(Enum):
    """Type of software anomaly."""

    FUNCTIONAL = "Functional"
    PERFORMANCE = "Performance"
    USABILITY = "Usability"
    SECURITY = "Security"
    COMPATIBILITY = "Compatibility"
    DOCUMENTATION = "Documentation"


class SafetyImpact(Enum):
    """Impact on patient safety."""

    NONE = "No safety impact"
    MINIMAL = "Minimal - inconvenience only"
    LOW = "Low - minor delay in care possible"
    MODERATE = "Moderate - potential for minor injury"
    HIGH = "High - potential for serious injury"


@dataclass
class UnresolvedAnomaly:
    """Individual unresolved anomaly entry."""

    anomaly_id: str
    title: str
    description: str
    severity: AnomalySeverity
    anomaly_type: AnomalyType
    safety_impact: SafetyImpact

    # Discovery information
    discovery_date: str = ""
    discovery_method: str = ""  # Testing, field report, code review, fuzzing
    affected_versions: list[str] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)

    # Reproduction
    steps_to_reproduce: list[str] = field(default_factory=list)
    frequency: str = ""  # Always, Often, Sometimes, Rarely

    # Analysis
    root_cause: str = ""
    sequence_to_harm: str = ""  # Sequence of events that could lead to harm
    probability_of_harm: str = ""
    existing_mitigations: list[str] = field(default_factory=list)

    # Justification
    justification: str = ""
    workaround: str = ""
    planned_fix_version: str = ""

    # Related items
    related_risks: list[str] = field(default_factory=list)
    related_cves: list[str] = field(default_factory=list)
    test_evidence: list[str] = field(default_factory=list)


@dataclass
class AnomalyAssessmentConfig:
    """Configuration for anomaly assessment report generation."""

    # Document metadata
    document_number: str = ""
    document_version: str = "1.0"
    organization_name: str = ""
    product_name: str = ""
    software_version: str = ""
    submission_type: str = "510(k)"

    # Device classification
    device_class: str = "II"  # I, II, or III
    software_safety_class: str = "B"  # A, B, or C per IEC 62304

    # Stakeholders
    prepared_by: str = ""
    reviewed_by: str = ""
    approved_by: str = ""


class UnresolvedAnomalyAssessmentGenerator:
    """Generate FDA-compliant Unresolved Anomaly Assessment."""

    def __init__(self, config: AnomalyAssessmentConfig | None = None) -> None:
        self.config = config or AnomalyAssessmentConfig()
        self.anomalies: list[UnresolvedAnomaly] = []

    def add_anomaly(self, anomaly: UnresolvedAnomaly) -> None:
        """Add an unresolved anomaly to the assessment."""
        self.anomalies.append(anomaly)

    def add_example_anomalies(self) -> None:
        """Add example anomalies for template reference."""
        examples = [
            UnresolvedAnomaly(
                anomaly_id="ANO-001",
                title="Intermittent UI Freeze During Large Series Loading",
                description=(
                    "When loading DICOM series with >500 images, the user interface "
                    "may become unresponsive for 2-5 seconds while images are loaded "
                    "into memory."
                ),
                severity=AnomalySeverity.MINOR,
                anomaly_type=AnomalyType.PERFORMANCE,
                safety_impact=SafetyImpact.MINIMAL,
                discovery_date="2024-10-15",
                discovery_method="Performance Testing",
                affected_versions=["2.0.0"],
                affected_components=["Image Loader", "UI Thread"],
                steps_to_reproduce=[
                    "Open application",
                    "Load DICOM series with 500+ images",
                    "Observe UI responsiveness during loading",
                ],
                frequency="Sometimes",
                root_cause="Synchronous image loading on UI thread",
                sequence_to_harm=(
                    "None identified. UI freeze is temporary and does not affect "
                    "image data integrity or diagnostic accuracy."
                ),
                probability_of_harm="Negligible",
                existing_mitigations=[
                    "Progress indicator shows loading status",
                    "User can cancel loading operation",
                    "Images remain accurate after loading completes",
                ],
                justification=(
                    "This anomaly causes minor inconvenience but does not impact "
                    "patient safety or diagnostic accuracy. The freeze is temporary "
                    "and self-resolving. No clinical workflow impact identified."
                ),
                workaround="User can wait for loading to complete or cancel operation.",
                planned_fix_version="2.1.0",
            ),
            UnresolvedAnomaly(
                anomaly_id="ANO-002",
                title="Warning Not Displayed for Unsupported Transfer Syntax",
                description=(
                    "When opening a DICOM file with an unsupported transfer syntax, "
                    "the application displays a generic error instead of a specific "
                    "warning identifying the unsupported syntax."
                ),
                severity=AnomalySeverity.MINOR,
                anomaly_type=AnomalyType.USABILITY,
                safety_impact=SafetyImpact.NONE,
                discovery_date="2024-11-02",
                discovery_method="Fuzz Testing",
                affected_versions=["2.0.0"],
                affected_components=["DICOM Parser", "Error Handler"],
                steps_to_reproduce=[
                    "Obtain DICOM file with unsupported transfer syntax",
                    "Attempt to open file in application",
                    "Observe error message displayed",
                ],
                frequency="Always",
                root_cause="Error handler does not extract transfer syntax from exception",
                sequence_to_harm=(
                    "None. File is correctly rejected and not displayed. User receives "
                    "error notification, though message could be more specific."
                ),
                probability_of_harm="None",
                existing_mitigations=[
                    "File is correctly rejected (not displayed)",
                    "Error message indicates file cannot be opened",
                    "No incorrect data is displayed to user",
                ],
                justification=(
                    "This anomaly affects user experience but has no safety impact. "
                    "The unsupported file is correctly rejected, preventing any "
                    "potential for misdiagnosis from corrupted rendering."
                ),
                workaround="User should use a tool supporting the specific transfer syntax.",
                planned_fix_version="2.0.1",
            ),
        ]

        for anomaly in examples:
            self.add_anomaly(anomaly)

    def _get_severity_acceptability_criteria(self) -> str:
        """Get severity-based acceptability criteria."""
        return f"""
### Severity Acceptability Criteria

Per IEC 62304 and FDA guidance, anomalies are evaluated against the following criteria:

| Severity | Class A Device | Class B Device | Class C Device |
|----------|---------------|----------------|----------------|
| Minor | Release acceptable | Release acceptable | Requires justification |
| Major | Release acceptable | Requires justification | Generally unacceptable |
| Critical | Requires justification | Generally unacceptable | Not acceptable |

**Software Safety Classification:** {self.config.software_safety_class}

Release criteria for this product:
- **Minor anomalies:** Acceptable with documented justification
- **Major anomalies:** Acceptable only if mitigations reduce safety impact to minimal
- **Critical anomalies:** Must be resolved prior to release
"""

    def generate_assessment_markdown(self) -> str:
        """Generate the unresolved anomaly assessment in Markdown."""
        cfg = self.config
        now = datetime.now(UTC).strftime("%Y-%m-%d")

        report = f"""# Unresolved Software Anomaly Assessment

**Document Number:** {cfg.document_number or "UAA-001"}
**Version:** {cfg.document_version}
**Date:** {now}

---

## Document Information

| Field | Value |
|-------|-------|
| Organization | {cfg.organization_name or "[Organization Name]"} |
| Product Name | {cfg.product_name or "[Product Name]"} |
| Software Version | {cfg.software_version or "[Version]"} |
| Device Class | Class {cfg.device_class} |
| Software Safety Class | {cfg.software_safety_class} |
| Submission Type | {cfg.submission_type} |

---

## 1. Purpose

This document identifies and assesses all known software anomalies (defects, bugs)
that remain unresolved in {cfg.product_name or "[Product Name]"} version
{cfg.software_version or "[Version]"} at the time of release.

Per FDA guidance for premarket submissions, this assessment provides:
- Complete list of known anomalies not corrected prior to release
- Assessment of each anomaly's impact on safety and effectiveness
- Rationale for acceptability of releasing with these known anomalies
- Sequence of events that could lead to patient harm (where applicable)

---

## 2. Scope

### 2.1 Included Anomalies

This assessment covers anomalies identified through:
- System testing and integration testing
- User acceptance testing
- Fuzz testing and security testing
- Code review and static analysis
- Beta testing and field trials

### 2.2 Exclusion Criteria

The following are NOT included in this assessment:
- Anomalies resolved prior to release
- Feature requests and enhancements
- Known limitations documented in user manual
- Third-party issues with documented workarounds

{self._get_severity_acceptability_criteria()}

---

## 3. Summary of Unresolved Anomalies

**Total Unresolved Anomalies:** {len(self.anomalies)}

| Severity | Count |
|----------|-------|
| Critical | {sum(1 for a in self.anomalies if a.severity == AnomalySeverity.CRITICAL)} |
| Major | {sum(1 for a in self.anomalies if a.severity == AnomalySeverity.MAJOR)} |
| Minor | {sum(1 for a in self.anomalies if a.severity == AnomalySeverity.MINOR)} |

| Safety Impact | Count |
|---------------|-------|
| None | {sum(1 for a in self.anomalies if a.safety_impact == SafetyImpact.NONE)} |
| Minimal | {sum(1 for a in self.anomalies if a.safety_impact == SafetyImpact.MINIMAL)} |
| Low | {sum(1 for a in self.anomalies if a.safety_impact == SafetyImpact.LOW)} |
| Moderate | {sum(1 for a in self.anomalies if a.safety_impact == SafetyImpact.MODERATE)} |
| High | {sum(1 for a in self.anomalies if a.safety_impact == SafetyImpact.HIGH)} |

---

## 4. Detailed Anomaly Assessments

"""
        # Add each anomaly
        for anomaly in self.anomalies:
            report += f"""### {anomaly.anomaly_id}: {anomaly.title}

#### Basic Information

| Attribute | Value |
|-----------|-------|
| Severity | {anomaly.severity.value} |
| Type | {anomaly.anomaly_type.value} |
| Safety Impact | {anomaly.safety_impact.value} |
| Discovery Date | {anomaly.discovery_date or "N/A"} |
| Discovery Method | {anomaly.discovery_method or "N/A"} |
| Frequency | {anomaly.frequency or "N/A"} |

#### Description

{anomaly.description}

#### Affected Components

"""
            if anomaly.affected_components:
                for component in anomaly.affected_components:
                    report += f"- {component}\n"
            else:
                report += "- Not specified\n"

            report += "\n#### Steps to Reproduce\n\n"
            if anomaly.steps_to_reproduce:
                for i, step in enumerate(anomaly.steps_to_reproduce, 1):
                    report += f"{i}. {step}\n"
            else:
                report += "Not specified\n"

            report += f"""
#### Root Cause Analysis

{anomaly.root_cause or "Analysis pending"}

#### Sequence of Events Leading to Harm

{anomaly.sequence_to_harm or "No sequence to harm identified"}

**Probability of Harm:** {anomaly.probability_of_harm or "Not assessed"}

#### Existing Mitigations

"""
            if anomaly.existing_mitigations:
                for mitigation in anomaly.existing_mitigations:
                    report += f"- {mitigation}\n"
            else:
                report += "- None\n"

            report += f"""
#### Justification for Release

{anomaly.justification or "[Justification required]"}

#### Workaround

{anomaly.workaround or "No workaround available"}

#### Planned Resolution

**Target Version:** {anomaly.planned_fix_version or "TBD"}

"""
            if anomaly.related_risks:
                report += (
                    "**Related Risks:** " + ", ".join(anomaly.related_risks) + "\n\n"
                )
            if anomaly.related_cves:
                report += (
                    "**Related CVEs:** " + ", ".join(anomaly.related_cves) + "\n\n"
                )

            report += "---\n\n"

        # Summary table
        report += """## 5. Anomaly Summary Table

| ID | Title | Severity | Safety Impact | Planned Fix |
|----|-------|----------|---------------|-------------|
"""
        for anomaly in self.anomalies:
            title_short = (
                anomaly.title[:40] + "..." if len(anomaly.title) > 40 else anomaly.title
            )
            report += (
                f"| {anomaly.anomaly_id} | {title_short} | {anomaly.severity.value} | "
                f"{anomaly.safety_impact.value} | {anomaly.planned_fix_version or 'TBD'} |\n"
            )

        report += f"""
---

## 6. Overall Assessment

### 6.1 Release Acceptability Determination

Based on the analysis documented herein:

- **Total unresolved anomalies:** {len(self.anomalies)}
- **Critical anomalies:** {sum(1 for a in self.anomalies if a.severity == AnomalySeverity.CRITICAL)}
- **Anomalies with safety impact:** {sum(1 for a in self.anomalies if a.safety_impact not in [SafetyImpact.NONE, SafetyImpact.MINIMAL])}

**Determination:** {"Release is acceptable" if not any(a.severity == AnomalySeverity.CRITICAL for a in self.anomalies) else "Release requires additional review"}

### 6.2 Rationale

[Document overall rationale for releasing with these known anomalies]

The unresolved anomalies documented in this assessment:
- Do not compromise patient safety
- Do not prevent the device from performing its intended use
- Have acceptable workarounds where user impact exists
- Will be addressed in future maintenance releases

### 6.3 Monitoring Plan

Post-market surveillance will monitor for:
- Field reports related to documented anomalies
- New anomalies discovered in production use
- Changes in frequency or severity of known anomalies

---

## 7. Approval

The undersigned have reviewed this Unresolved Anomaly Assessment and approve
the release of {cfg.product_name or "[Product Name]"} version
{cfg.software_version or "[Version]"} with the documented anomalies.

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Prepared By | {cfg.prepared_by or "[Name]"} | _______________ | {now} |
| Reviewed By | {cfg.reviewed_by or "[Name]"} | _______________ | {now} |
| Approved By | {cfg.approved_by or "[Name]"} | _______________ | {now} |

---

## Appendix A: Definitions

| Term | Definition |
|------|------------|
| Anomaly | Any condition that deviates from expectations (defect, bug, fault) |
| Minor | Anomaly causing inconvenience without safety impact |
| Major | Anomaly causing significant functional impact but mitigatable |
| Critical | Anomaly that could compromise safety or essential functions |
| Mitigation | Action taken to reduce risk from an anomaly |
| Workaround | Alternative procedure to achieve intended function |

---

## Appendix B: FDA Compliance Mapping

| FDA Requirement | Section Reference |
|-----------------|-------------------|
| List of known anomalies | Section 4 |
| Assessment of impact | Section 4 (each anomaly) |
| Sequence of events to harm | Section 4 (each anomaly) |
| Rationale for acceptability | Section 6.2 |
| Monitoring plan | Section 6.3 |

---

*This assessment was generated by DICOM Fuzzer for FDA cybersecurity compliance.*
"""
        return report

    def generate_assessment_json(self) -> dict[str, Any]:
        """Generate the assessment as JSON."""
        cfg = self.config
        return {
            "document_info": {
                "document_number": cfg.document_number,
                "version": cfg.document_version,
                "date": datetime.now(UTC).isoformat(),
                "organization": cfg.organization_name,
                "product": cfg.product_name,
                "software_version": cfg.software_version,
                "device_class": cfg.device_class,
                "software_safety_class": cfg.software_safety_class,
            },
            "summary": {
                "total_anomalies": len(self.anomalies),
                "by_severity": {
                    "critical": sum(
                        1
                        for a in self.anomalies
                        if a.severity == AnomalySeverity.CRITICAL
                    ),
                    "major": sum(
                        1 for a in self.anomalies if a.severity == AnomalySeverity.MAJOR
                    ),
                    "minor": sum(
                        1 for a in self.anomalies if a.severity == AnomalySeverity.MINOR
                    ),
                },
                "by_safety_impact": {
                    "none": sum(
                        1
                        for a in self.anomalies
                        if a.safety_impact == SafetyImpact.NONE
                    ),
                    "minimal": sum(
                        1
                        for a in self.anomalies
                        if a.safety_impact == SafetyImpact.MINIMAL
                    ),
                    "low": sum(
                        1 for a in self.anomalies if a.safety_impact == SafetyImpact.LOW
                    ),
                    "moderate": sum(
                        1
                        for a in self.anomalies
                        if a.safety_impact == SafetyImpact.MODERATE
                    ),
                    "high": sum(
                        1
                        for a in self.anomalies
                        if a.safety_impact == SafetyImpact.HIGH
                    ),
                },
            },
            "anomalies": [
                {
                    "anomaly_id": a.anomaly_id,
                    "title": a.title,
                    "description": a.description,
                    "severity": a.severity.value,
                    "type": a.anomaly_type.value,
                    "safety_impact": a.safety_impact.value,
                    "discovery_date": a.discovery_date,
                    "discovery_method": a.discovery_method,
                    "affected_versions": a.affected_versions,
                    "affected_components": a.affected_components,
                    "steps_to_reproduce": a.steps_to_reproduce,
                    "frequency": a.frequency,
                    "root_cause": a.root_cause,
                    "sequence_to_harm": a.sequence_to_harm,
                    "probability_of_harm": a.probability_of_harm,
                    "existing_mitigations": a.existing_mitigations,
                    "justification": a.justification,
                    "workaround": a.workaround,
                    "planned_fix_version": a.planned_fix_version,
                    "related_risks": a.related_risks,
                    "related_cves": a.related_cves,
                }
                for a in self.anomalies
            ],
        }

    def save_assessment(
        self, output_path: Path | str, format: str = "markdown"
    ) -> Path:
        """Save the assessment to file.

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
                json.dump(self.generate_assessment_json(), f, indent=2)
        else:
            output_path.write_text(self.generate_assessment_markdown())

        return output_path


def generate_anomaly_assessment(
    organization: str = "",
    product: str = "",
    version: str = "",
    output_path: Path | str | None = None,
    include_examples: bool = False,
) -> str:
    """Generate an anomaly assessment with minimal configuration.

    Args:
        organization: Organization name
        product: Product name
        version: Software version
        output_path: Optional path to save the assessment
        include_examples: Include example anomalies for reference

    Returns:
        Assessment content as string

    """
    config = AnomalyAssessmentConfig(
        organization_name=organization,
        product_name=product,
        software_version=version,
    )

    generator = UnresolvedAnomalyAssessmentGenerator(config)

    if include_examples:
        generator.add_example_anomalies()

    assessment = generator.generate_assessment_markdown()

    if output_path:
        generator.save_assessment(output_path)

    return assessment


if __name__ == "__main__":
    # Generate sample assessment
    config = AnomalyAssessmentConfig(
        document_number="UAA-DICOM-001",
        organization_name="Medical Device Corp",
        product_name="DICOM Viewer Pro",
        software_version="2.0.0",
        device_class="II",
        software_safety_class="B",
        prepared_by="QA Team",
        reviewed_by="Engineering Lead",
        approved_by="VP Engineering",
    )

    generator = UnresolvedAnomalyAssessmentGenerator(config)
    generator.add_example_anomalies()

    print(generator.generate_assessment_markdown())
