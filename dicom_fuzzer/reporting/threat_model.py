"""Threat Model Template Generator for DICOM Medical Devices.

Generates threat model documentation for FDA premarket cybersecurity submissions.

FDA Requirements (June 2025 Guidance):
- Comprehensive threat model for the device
- Identification of attack surfaces
- Security controls and mitigations
- Risk assessment methodology

References:
- FDA Cybersecurity Guidance (June 2025) Section V.A
- STRIDE Threat Modeling (Microsoft)
- AAMI TIR57:2016 (Medical Device Cybersecurity)
- IEC 62443-4-1 (Secure Development Lifecycle)

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# STRIDE threat categories
STRIDE_CATEGORIES = {
    "S": "Spoofing Identity",
    "T": "Tampering with Data",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# DICOM-specific attack surfaces
DICOM_ATTACK_SURFACES = [
    {
        "id": "AS-01",
        "name": "DICOM File Parser",
        "description": "Processing of DICOM files from storage media or network",
        "entry_points": ["File import", "DICOMDIR reading", "Series loading"],
        "threats": ["T", "I", "D"],  # STRIDE categories
        "data_processed": ["Patient data", "Image data", "Metadata"],
    },
    {
        "id": "AS-02",
        "name": "DICOM Network Services",
        "description": "DICOM networking (Association, C-STORE, C-FIND, C-MOVE)",
        "entry_points": [
            "TCP port 104/11112",
            "TLS connections",
            "Association negotiation",
        ],
        "threats": ["S", "T", "I", "D"],
        "data_processed": ["PHI", "Study data", "Worklists"],
    },
    {
        "id": "AS-03",
        "name": "Image Codec Processing",
        "description": "Decompression of encoded pixel data (JPEG, JPEG2000, RLE)",
        "entry_points": ["Transfer syntax decoding", "Multi-frame processing"],
        "threats": ["T", "D", "E"],
        "data_processed": ["Compressed pixel data", "Encapsulated data"],
    },
    {
        "id": "AS-04",
        "name": "User Interface",
        "description": "GUI interactions and display rendering",
        "entry_points": ["Image display", "Report generation", "Export functions"],
        "threats": ["S", "T", "I"],
        "data_processed": ["Rendered images", "Patient information display"],
    },
    {
        "id": "AS-05",
        "name": "Configuration & Storage",
        "description": "Application configuration, caching, and local storage",
        "entry_points": ["Config files", "Local database", "Cache directories"],
        "threats": ["T", "I", "E"],
        "data_processed": ["Credentials", "Settings", "Cached PHI"],
    },
]

# Common DICOM security controls
SECURITY_CONTROLS = [
    {
        "id": "SC-01",
        "name": "Input Validation",
        "description": "Validate all DICOM data elements before processing",
        "mitigates": ["T", "D", "E"],
        "implementation": "Strict tag parsing, VR validation, length bounds checking",
    },
    {
        "id": "SC-02",
        "name": "Memory Safety",
        "description": "Prevent buffer overflows and memory corruption",
        "mitigates": ["E", "D"],
        "implementation": "Safe memory allocation, bounds checking, ASLR/DEP",
    },
    {
        "id": "SC-03",
        "name": "Authentication",
        "description": "Verify identity of DICOM association peers",
        "mitigates": ["S"],
        "implementation": "TLS mutual authentication, AE title validation",
    },
    {
        "id": "SC-04",
        "name": "Encryption",
        "description": "Protect data in transit and at rest",
        "mitigates": ["I"],
        "implementation": "TLS 1.2+, encrypted storage, secure key management",
    },
    {
        "id": "SC-05",
        "name": "Access Control",
        "description": "Restrict access to functions and data",
        "mitigates": ["S", "E", "I"],
        "implementation": "Role-based access, least privilege, audit logging",
    },
    {
        "id": "SC-06",
        "name": "Integrity Protection",
        "description": "Detect and prevent unauthorized modifications",
        "mitigates": ["T", "R"],
        "implementation": "Digital signatures, checksums, audit trails",
    },
    {
        "id": "SC-07",
        "name": "Resource Limits",
        "description": "Prevent resource exhaustion attacks",
        "mitigates": ["D"],
        "implementation": "Memory limits, timeout controls, rate limiting",
    },
]


@dataclass
class ThreatModelConfig:
    """Configuration for threat model generation."""

    # Device information
    device_name: str = ""
    device_version: str = ""
    manufacturer: str = ""
    device_class: str = "II"  # FDA device class

    # Assessment metadata
    assessment_date: str = ""
    assessor: str = ""
    methodology: str = "STRIDE"

    # Custom attack surfaces (in addition to defaults)
    additional_attack_surfaces: list[dict[str, Any]] = field(default_factory=list)

    # Custom security controls
    additional_controls: list[dict[str, Any]] = field(default_factory=list)

    # Risk assessment parameters
    risk_methodology: str = "AAMI TIR57"
    acceptable_risk_level: str = "Medium"


@dataclass
class Threat:
    """Individual threat in the model."""

    threat_id: str
    name: str
    category: str  # STRIDE category
    attack_surface: str
    description: str
    likelihood: str  # Low, Medium, High
    impact: str  # Low, Medium, High
    risk_level: str  # Low, Medium, High, Critical
    mitigations: list[str] = field(default_factory=list)
    residual_risk: str = ""
    cve_references: list[str] = field(default_factory=list)


class ThreatModelGenerator:
    """Generate threat model documentation for FDA submissions."""

    def __init__(self, config: ThreatModelConfig | None = None) -> None:
        self.config = config or ThreatModelConfig()
        self.threats: list[Threat] = []
        self._generate_default_threats()

    def _generate_default_threats(self) -> None:
        """Generate default DICOM-specific threats."""
        default_threats = [
            Threat(
                threat_id="TH-01",
                name="Buffer Overflow via Malformed DICOM",
                category="E",
                attack_surface="AS-01",
                description="Attacker crafts DICOM file with oversized data elements to overflow parser buffers",
                likelihood="Medium",
                impact="Critical",
                risk_level="High",
                mitigations=["SC-01", "SC-02"],
                cve_references=["CVE-2022-2119", "CVE-2024-22100"],
            ),
            Threat(
                threat_id="TH-02",
                name="Integer Overflow in Length Fields",
                category="E",
                attack_surface="AS-01",
                description="Malicious length values cause integer overflow leading to heap corruption",
                likelihood="Medium",
                impact="Critical",
                risk_level="High",
                mitigations=["SC-01", "SC-02"],
                cve_references=["CVE-2025-35975"],
            ),
            Threat(
                threat_id="TH-03",
                name="Path Traversal via File References",
                category="I",
                attack_surface="AS-01",
                description="DICOM file contains path traversal sequences to access unauthorized files",
                likelihood="Low",
                impact="High",
                risk_level="Medium",
                mitigations=["SC-01", "SC-05"],
                cve_references=["CVE-2022-2120"],
            ),
            Threat(
                threat_id="TH-04",
                name="DICOM Association Spoofing",
                category="S",
                attack_surface="AS-02",
                description="Attacker impersonates legitimate DICOM peer to access data",
                likelihood="Medium",
                impact="High",
                risk_level="Medium",
                mitigations=["SC-03", "SC-04"],
            ),
            Threat(
                threat_id="TH-05",
                name="PHI Exposure via Network Interception",
                category="I",
                attack_surface="AS-02",
                description="Unencrypted DICOM traffic exposes patient health information",
                likelihood="Medium",
                impact="High",
                risk_level="High",
                mitigations=["SC-04"],
            ),
            Threat(
                threat_id="TH-06",
                name="Image Codec Exploitation",
                category="E",
                attack_surface="AS-03",
                description="Malformed compressed pixel data exploits codec vulnerabilities",
                likelihood="Medium",
                impact="Critical",
                risk_level="High",
                mitigations=["SC-01", "SC-02", "SC-07"],
                cve_references=["CVE-2025-53619"],
            ),
            Threat(
                threat_id="TH-07",
                name="Denial of Service via Resource Exhaustion",
                category="D",
                attack_surface="AS-01",
                description="Large or deeply nested DICOM structures exhaust memory/CPU",
                likelihood="Medium",
                impact="Medium",
                risk_level="Medium",
                mitigations=["SC-07"],
            ),
            Threat(
                threat_id="TH-08",
                name="Polyglot File Attack",
                category="E",
                attack_surface="AS-01",
                description="DICOM file preamble contains executable code that may be triggered",
                likelihood="Low",
                impact="Critical",
                risk_level="Medium",
                mitigations=["SC-01"],
                cve_references=["CVE-2019-11687"],
            ),
            Threat(
                threat_id="TH-09",
                name="Certificate Validation Bypass",
                category="S",
                attack_surface="AS-02",
                description="Attacker performs MitM attack by exploiting weak certificate validation",
                likelihood="Medium",
                impact="High",
                risk_level="High",
                mitigations=["SC-03", "SC-04"],
                cve_references=["CVE-2025-1001"],
            ),
            Threat(
                threat_id="TH-10",
                name="Configuration Tampering",
                category="T",
                attack_surface="AS-05",
                description="Attacker modifies configuration to weaken security or gain access",
                likelihood="Low",
                impact="High",
                risk_level="Medium",
                mitigations=["SC-05", "SC-06"],
            ),
        ]
        self.threats = default_threats

    def add_threat(self, threat: Threat) -> None:
        """Add a custom threat to the model."""
        self.threats.append(threat)

    def generate_markdown(self) -> str:
        """Generate threat model documentation in Markdown format."""
        cfg = self.config
        now = cfg.assessment_date or datetime.now(UTC).strftime("%Y-%m-%d")

        doc = f"""# Threat Model: {cfg.device_name or "[Device Name]"}

## Document Information

| Field | Value |
|-------|-------|
| Device Name | {cfg.device_name or "[Device Name]"} |
| Version | {cfg.device_version or "[Version]"} |
| Manufacturer | {cfg.manufacturer or "[Manufacturer]"} |
| FDA Device Class | Class {cfg.device_class} |
| Assessment Date | {now} |
| Assessor | {cfg.assessor or "[Assessor]"} |
| Methodology | {cfg.methodology} |

---

## 1. Executive Summary

This threat model documents the security analysis of {cfg.device_name or "[Device Name]"}
performed in accordance with FDA Cybersecurity Guidance (June 2025) and {cfg.risk_methodology}.

**Key Findings:**
- {len(self.threats)} threats identified
- {sum(1 for t in self.threats if t.risk_level == "Critical")} Critical risk threats
- {sum(1 for t in self.threats if t.risk_level == "High")} High risk threats
- {sum(1 for t in self.threats if t.risk_level == "Medium")} Medium risk threats

---

## 2. System Overview

### 2.1 Device Description

{cfg.device_name or "[Device Name]"} is a DICOM-compliant medical imaging application
that processes, displays, and transmits medical imaging data.

### 2.2 Data Flow

The device processes the following data types:
- DICOM image files and series
- Patient Health Information (PHI)
- Medical imaging metadata
- Network communications (DICOM protocol)
- Configuration and credentials

---

## 3. Attack Surfaces

The following attack surfaces have been identified:

"""
        # Add attack surfaces
        all_surfaces = DICOM_ATTACK_SURFACES + cfg.additional_attack_surfaces
        for surface in all_surfaces:
            doc += f"""### {surface["id"]}: {surface["name"]}

**Description:** {surface["description"]}

**Entry Points:**
"""
            for entry in surface.get("entry_points", []):
                doc += f"- {entry}\n"

            doc += f"""
**STRIDE Threats:** {", ".join(STRIDE_CATEGORIES.get(t, t) for t in surface.get("threats", []))}

**Data Processed:**
"""
            for data in surface.get("data_processed", []):
                doc += f"- {data}\n"
            doc += "\n"

        doc += """---

## 4. Threat Catalog

### 4.1 STRIDE Methodology

This analysis uses the STRIDE threat modeling methodology:

| Category | Threat Type | Property Violated |
|----------|-------------|-------------------|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorization |

### 4.2 Identified Threats

"""
        # Add threats
        for threat in self.threats:
            doc += f"""#### {threat.threat_id}: {threat.name}

| Attribute | Value |
|-----------|-------|
| Category | {STRIDE_CATEGORIES.get(threat.category, threat.category)} ({threat.category}) |
| Attack Surface | {threat.attack_surface} |
| Likelihood | {threat.likelihood} |
| Impact | {threat.impact} |
| **Risk Level** | **{threat.risk_level}** |

**Description:** {threat.description}

**Mitigations:** {", ".join(threat.mitigations) if threat.mitigations else "None identified"}

"""
            if threat.cve_references:
                doc += f"**CVE References:** {', '.join(threat.cve_references)}\n"
            if threat.residual_risk:
                doc += f"**Residual Risk:** {threat.residual_risk}\n"
            doc += "\n"

        doc += """---

## 5. Security Controls

The following security controls are implemented or planned:

"""
        # Add security controls
        all_controls = SECURITY_CONTROLS + cfg.additional_controls
        for control in all_controls:
            doc += f"""### {control["id"]}: {control["name"]}

**Description:** {control["description"]}

**Mitigates:** {", ".join(STRIDE_CATEGORIES.get(t, t) for t in control.get("mitigates", []))}

**Implementation:** {control.get("implementation", "TBD")}

"""

        doc += f"""---

## 6. Risk Assessment

### 6.1 Risk Matrix

| Likelihood \\ Impact | Low | Medium | High | Critical |
|---------------------|-----|--------|------|----------|
| **High** | Medium | High | Critical | Critical |
| **Medium** | Low | Medium | High | Critical |
| **Low** | Low | Low | Medium | High |

### 6.2 Risk Summary

| Risk Level | Count | Threats |
|------------|-------|---------|
| Critical | {sum(1 for t in self.threats if t.risk_level == "Critical")} | {", ".join(t.threat_id for t in self.threats if t.risk_level == "Critical") or "None"} |
| High | {sum(1 for t in self.threats if t.risk_level == "High")} | {", ".join(t.threat_id for t in self.threats if t.risk_level == "High") or "None"} |
| Medium | {sum(1 for t in self.threats if t.risk_level == "Medium")} | {", ".join(t.threat_id for t in self.threats if t.risk_level == "Medium") or "None"} |
| Low | {sum(1 for t in self.threats if t.risk_level == "Low")} | {", ".join(t.threat_id for t in self.threats if t.risk_level == "Low") or "None"} |

### 6.3 Acceptable Risk

Per {cfg.risk_methodology}, risks at **{cfg.acceptable_risk_level}** level or below
are considered acceptable with proper controls in place. Risks above this level
require additional mitigation or acceptance documentation.

---

## 7. Recommendations

Based on this threat model analysis, the following recommendations are made:

1. **Implement input validation** for all DICOM data elements (addresses TH-01, TH-02, TH-07)
2. **Enable TLS encryption** for all network communications (addresses TH-04, TH-05, TH-09)
3. **Apply memory safety controls** including ASLR, DEP, and bounds checking (addresses TH-01, TH-02, TH-06)
4. **Implement resource limits** to prevent denial of service (addresses TH-07)
5. **Conduct regular fuzz testing** using DICOM-aware tools (ongoing validation)

---

## 8. FDA Compliance Statement

This threat model has been developed in accordance with:

- FDA Cybersecurity Guidance (June 2025): "Cybersecurity in Medical Devices"
- AAMI TIR57:2016: "Principles for Medical Device Security - Risk Management"
- IEC 62443-4-1: "Secure Product Development Lifecycle Requirements"

This document should be included in the cybersecurity documentation package
for FDA premarket submissions.

---

## Appendix A: CVE Reference Database

The following CVEs are relevant to DICOM software security:

| CVE ID | Description | Severity |
|--------|-------------|----------|
| CVE-2019-11687 | DICOM Preamble Polyglot Attack | High |
| CVE-2022-2119 | dcm4che Path Traversal | High |
| CVE-2022-2120 | dcm4che XXE Injection | Medium |
| CVE-2024-22100 | DCMTk Buffer Overflow | Critical |
| CVE-2024-28877 | RadiAnt Memory Corruption | High |
| CVE-2025-35975 | DCMTK Integer Overflow | Critical |
| CVE-2025-36521 | GDCM OOB Read | High |
| CVE-2025-5943 | MicroDicom Format String | Critical |
| CVE-2025-53619 | GDCM JPEG Codec Info Leak | High |
| CVE-2025-1001 | RadiAnt Certificate Bypass | Medium |

---

*This threat model was generated by DICOM Fuzzer for FDA cybersecurity compliance.*
"""
        return doc

    def save(self, output_path: Path | str) -> Path:
        """Save threat model to file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate_markdown())
        return output_path


def generate_threat_model(
    device_name: str = "",
    device_version: str = "",
    manufacturer: str = "",
    output_path: Path | str | None = None,
) -> str:
    """Generate a threat model with minimal configuration.

    Args:
        device_name: Device/product name
        device_version: Device version
        manufacturer: Manufacturer name
        output_path: Optional path to save the document

    Returns:
        Threat model content as string

    """
    config = ThreatModelConfig(
        device_name=device_name,
        device_version=device_version,
        manufacturer=manufacturer,
    )

    generator = ThreatModelGenerator(config)
    content = generator.generate_markdown()

    if output_path:
        generator.save(output_path)

    return content


if __name__ == "__main__":
    # Generate sample threat model
    config = ThreatModelConfig(
        device_name="DICOM Viewer Pro",
        device_version="2.5.0",
        manufacturer="Medical Device Corp",
        assessor="Security Team",
    )

    generator = ThreatModelGenerator(config)
    print(generator.generate_markdown())
