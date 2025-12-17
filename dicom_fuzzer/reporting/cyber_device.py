"""FDA Cyber Device Classification Helper.

Implements classification logic per FDA Section 524B (21st Century Cures Act Section 3060)
to determine if a medical device qualifies as a "cyber device" and assess its risk tier.

Cyber Device Definition (per FD&C Act Section 524B):
A device is a "cyber device" if it:
1. Includes software validated, installed, or authorized by the sponsor as a device or in a device
2. Has the ability to connect to the internet
3. Contains any software-related security vulnerabilities

Risk Tier Assessment (per FDA June 2025 Guidance):
- Tier 1 (Higher Cybersecurity Risk): Devices capable of connecting to network or internet,
  OR devices that could be exploited to cause patient harm
- Tier 2 (Standard Cybersecurity Risk): All other cyber devices

References:
- FDA FD&C Act Section 524B (21 U.S.C. 360n-2)
- FDA Cybersecurity in Medical Devices (June 2025)
- 21st Century Cures Act Section 3060

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class ConnectivityType(Enum):
    """Device connectivity capabilities."""

    NONE = "None"
    WIRED_NETWORK = "Wired Network (Ethernet)"
    WIRELESS_NETWORK = "Wireless Network (WiFi)"
    BLUETOOTH = "Bluetooth/BLE"
    CELLULAR = "Cellular (4G/5G)"
    USB = "USB Connection"
    SERIAL = "Serial/RS-232"
    DICOM = "DICOM Network Protocol"
    HL7_FHIR = "HL7/FHIR Integration"
    CLOUD = "Cloud Connectivity"
    OTHER = "Other"


class SoftwareType(Enum):
    """Type of software in the device."""

    EMBEDDED_FIRMWARE = "Embedded Firmware"
    OPERATING_SYSTEM = "Operating System"
    APPLICATION_SOFTWARE = "Application Software"
    MOBILE_APP = "Mobile Application"
    WEB_INTERFACE = "Web Interface"
    CLOUD_SERVICE = "Cloud Service/Backend"
    INTEROPERABILITY = "Interoperability Software"
    AI_ML = "AI/ML Component"


class HarmSeverity(Enum):
    """Potential patient harm severity if device is compromised."""

    DEATH = ("Death", 5)
    SERIOUS_INJURY = ("Serious Injury", 4)
    MODERATE_INJURY = ("Moderate Injury", 3)
    MINOR_INJURY = ("Minor Injury", 2)
    NO_INJURY = ("No Patient Injury", 1)

    @property
    def label(self) -> str:
        """Get the human-readable label for this severity level."""
        return self.value[0]

    @property
    def score(self) -> int:
        """Get the numeric score for this severity level."""
        return self.value[1]


class ExploitProbability(Enum):
    """Probability of successful exploitation."""

    CERTAIN = ("Near Certain", 5)
    LIKELY = ("Likely", 4)
    POSSIBLE = ("Possible", 3)
    UNLIKELY = ("Unlikely", 2)
    RARE = ("Rare", 1)

    @property
    def label(self) -> str:
        """Get the human-readable label for this probability level."""
        return self.value[0]

    @property
    def score(self) -> int:
        """Get the numeric score for this probability level."""
        return self.value[1]


class RiskTier(Enum):
    """FDA Cybersecurity Risk Tier classification."""

    TIER_1 = "Tier 1 - Higher Cybersecurity Risk"
    TIER_2 = "Tier 2 - Standard Cybersecurity Risk"
    NOT_CYBER_DEVICE = "Not a Cyber Device"


@dataclass
class CyberDeviceClassification:
    """Result of cyber device classification assessment."""

    # Device identification
    device_name: str
    device_model: str = ""
    manufacturer: str = ""
    fda_classification: str = ""  # e.g., "Class II 510(k)"

    # Cyber device criteria assessment
    has_software: bool = False
    software_types: list[SoftwareType] = field(default_factory=list)
    has_internet_connectivity: bool = False
    connectivity_types: list[ConnectivityType] = field(default_factory=list)
    has_known_vulnerabilities: bool = False
    vulnerability_count: int = 0

    # Risk factors
    harm_severity: HarmSeverity = HarmSeverity.NO_INJURY
    exploit_probability: ExploitProbability = ExploitProbability.RARE
    can_cause_patient_harm: bool = False

    # Classification results
    is_cyber_device: bool = False
    risk_tier: RiskTier = RiskTier.NOT_CYBER_DEVICE
    classification_rationale: str = ""
    assessment_date: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Additional details
    notes: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """Calculate risk score (harm x probability)."""
        return self.harm_severity.score * self.exploit_probability.score

    @property
    def is_tier_1(self) -> bool:
        """Check if device qualifies as Tier 1 (Higher Risk)."""
        return self.risk_tier == RiskTier.TIER_1


class CyberDeviceClassifier:
    """FDA Section 524B Cyber Device Classification Engine.

    Determines if a medical device qualifies as a "cyber device" and
    assesses its cybersecurity risk tier per FDA guidance.
    """

    # Connectivity types that indicate internet capability
    INTERNET_CONNECTIVITY = {
        ConnectivityType.WIRELESS_NETWORK,
        ConnectivityType.CELLULAR,
        ConnectivityType.CLOUD,
        ConnectivityType.HL7_FHIR,  # Often cloud-based
    }

    # Connectivity types that indicate network capability
    NETWORK_CONNECTIVITY = {
        ConnectivityType.WIRED_NETWORK,
        ConnectivityType.WIRELESS_NETWORK,
        ConnectivityType.CELLULAR,
        ConnectivityType.DICOM,
        ConnectivityType.CLOUD,
        ConnectivityType.HL7_FHIR,
    }

    def __init__(self) -> None:
        self.classification: CyberDeviceClassification | None = None

    def classify(
        self,
        device_name: str,
        device_model: str = "",
        manufacturer: str = "",
        fda_classification: str = "",
        software_types: list[SoftwareType] | None = None,
        connectivity_types: list[ConnectivityType] | None = None,
        known_vulnerabilities: int = 0,
        harm_severity: HarmSeverity = HarmSeverity.NO_INJURY,
        exploit_probability: ExploitProbability = ExploitProbability.RARE,
    ) -> CyberDeviceClassification:
        """Classify a medical device per FDA Section 524B.

        Args:
            device_name: Name of the medical device
            device_model: Model number/identifier
            manufacturer: Device manufacturer name
            fda_classification: FDA device classification (e.g., "Class II 510(k)")
            software_types: Types of software present in the device
            connectivity_types: Device connectivity capabilities
            known_vulnerabilities: Number of known security vulnerabilities
            harm_severity: Potential severity of patient harm if compromised
            exploit_probability: Probability of successful exploitation

        Returns:
            CyberDeviceClassification with assessment results

        """
        software_types = software_types or []
        connectivity_types = connectivity_types or []

        # Create classification object
        self.classification = CyberDeviceClassification(
            device_name=device_name,
            device_model=device_model,
            manufacturer=manufacturer,
            fda_classification=fda_classification,
            has_software=bool(software_types),
            software_types=software_types,
            connectivity_types=connectivity_types,
            vulnerability_count=known_vulnerabilities,
            has_known_vulnerabilities=known_vulnerabilities > 0,
            harm_severity=harm_severity,
            exploit_probability=exploit_probability,
        )

        # Assess cyber device criteria
        self._assess_connectivity()
        self._assess_cyber_device_status()
        self._assess_risk_tier()
        self._generate_rationale()

        return self.classification

    def _assess_connectivity(self) -> None:
        """Assess device connectivity capabilities."""
        if not self.classification:
            return

        conn_types = set(self.classification.connectivity_types)

        # Check for internet connectivity
        self.classification.has_internet_connectivity = bool(
            conn_types & self.INTERNET_CONNECTIVITY
        )

        # Check for any network connectivity
        has_network = bool(conn_types & self.NETWORK_CONNECTIVITY)

        # Assess if device can cause patient harm via cyber attack
        if has_network and self.classification.harm_severity.score >= 2:
            self.classification.can_cause_patient_harm = True

    def _assess_cyber_device_status(self) -> None:
        """Determine if device qualifies as a cyber device per Section 524B."""
        if not self.classification:
            return

        # Cyber device criteria (all must be true):
        # 1. Includes software
        # 2. Has ability to connect to internet
        # 3. Contains software-related security vulnerabilities

        has_software = self.classification.has_software
        has_internet = self.classification.has_internet_connectivity
        has_vulns = self.classification.has_known_vulnerabilities

        # Note: FDA considers ALL networked devices as potentially having vulnerabilities
        # If device has software and internet connectivity, assume vulnerability potential
        if has_software and has_internet:
            self.classification.is_cyber_device = True
            if not has_vulns:
                self.classification.notes.append(
                    "Device classified as cyber device due to internet connectivity "
                    "and software presence. All such devices are assumed to have "
                    "potential security vulnerabilities per FDA guidance."
                )

    def _assess_risk_tier(self) -> None:
        """Determine FDA cybersecurity risk tier."""
        if not self.classification:
            return

        if not self.classification.is_cyber_device:
            self.classification.risk_tier = RiskTier.NOT_CYBER_DEVICE
            return

        # Tier 1 criteria (per FDA June 2025 guidance):
        # - Device is capable of connecting to network or internet, AND
        # - Device could be exploited to cause patient harm

        has_network = bool(
            set(self.classification.connectivity_types) & self.NETWORK_CONNECTIVITY
        )
        can_harm = (
            self.classification.harm_severity.score >= 3  # Moderate or higher
            or self.classification.can_cause_patient_harm
        )

        if has_network and can_harm:
            self.classification.risk_tier = RiskTier.TIER_1
        else:
            self.classification.risk_tier = RiskTier.TIER_2

    def _generate_rationale(self) -> None:
        """Generate classification rationale documentation."""
        if not self.classification:
            return

        rationale_parts = []

        # Cyber device determination
        if self.classification.is_cyber_device:
            rationale_parts.append(
                f"Device '{self.classification.device_name}' qualifies as a "
                "cyber device under FDA FD&C Act Section 524B because it:"
            )
            rationale_parts.append(
                f"  1. Contains software: {', '.join(st.value for st in self.classification.software_types)}"
            )
            rationale_parts.append(
                f"  2. Has internet connectivity: {', '.join(ct.value for ct in self.classification.connectivity_types if ct in self.INTERNET_CONNECTIVITY)}"
            )
            if self.classification.has_known_vulnerabilities:
                rationale_parts.append(
                    f"  3. Has {self.classification.vulnerability_count} known security vulnerabilities"
                )
            else:
                rationale_parts.append(
                    "  3. Has potential for software-related vulnerabilities "
                    "(assumed per FDA guidance for all networked software devices)"
                )
        else:
            rationale_parts.append(
                f"Device '{self.classification.device_name}' does NOT qualify as a "
                "cyber device because it does not meet all Section 524B criteria."
            )
            if not self.classification.has_software:
                rationale_parts.append("  - Device does not contain software")
            if not self.classification.has_internet_connectivity:
                rationale_parts.append("  - Device cannot connect to the internet")

        # Risk tier determination
        rationale_parts.append("")
        if self.classification.risk_tier == RiskTier.TIER_1:
            rationale_parts.append("RISK TIER: Tier 1 (Higher Cybersecurity Risk)")
            rationale_parts.append(
                "Rationale: Device has network connectivity AND could be exploited "
                "to cause patient harm."
            )
            rationale_parts.append(
                f"  - Harm Severity: {self.classification.harm_severity.label}"
            )
            rationale_parts.append(
                f"  - Risk Score: {self.classification.risk_score}/25"
            )
        elif self.classification.risk_tier == RiskTier.TIER_2:
            rationale_parts.append("RISK TIER: Tier 2 (Standard Cybersecurity Risk)")
            rationale_parts.append(
                "Rationale: Device is a cyber device but exploitation would not "
                "likely cause significant patient harm."
            )

        self.classification.classification_rationale = "\n".join(rationale_parts)

    def generate_report(self) -> str:
        """Generate classification report for FDA submission."""
        if not self.classification:
            return "No classification performed."

        c = self.classification
        lines = [
            "# FDA Section 524B Cyber Device Classification Report",
            "",
            f"**Generated:** {c.assessment_date.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Device Information",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Device Name | {c.device_name} |",
            f"| Model | {c.device_model or 'N/A'} |",
            f"| Manufacturer | {c.manufacturer or 'N/A'} |",
            f"| FDA Classification | {c.fda_classification or 'N/A'} |",
            "",
            "## Cyber Device Assessment",
            "",
            "### Section 524B Criteria",
            "",
            "| Criterion | Status | Details |",
            "|-----------|--------|---------|",
            f"| Contains Software | {'[+] YES' if c.has_software else '[-] NO'} | {', '.join(st.value for st in c.software_types) or 'None'} |",
            f"| Internet Connectivity | {'[+] YES' if c.has_internet_connectivity else '[-] NO'} | {', '.join(ct.value for ct in c.connectivity_types) or 'None'} |",
            f"| Known Vulnerabilities | {'[+] YES' if c.has_known_vulnerabilities else '[-] NO'} | {c.vulnerability_count} identified |",
            "",
            "### Classification Result",
            "",
            f"**Is Cyber Device:** {'YES' if c.is_cyber_device else 'NO'}",
            "",
            f"**Risk Tier:** {c.risk_tier.value}",
            "",
            "### Risk Assessment",
            "",
            "| Factor | Assessment |",
            "|--------|------------|",
            f"| Potential Harm Severity | {c.harm_severity.label} |",
            f"| Exploitation Probability | {c.exploit_probability.label} |",
            f"| Risk Score | {c.risk_score}/25 |",
            f"| Can Cause Patient Harm | {'Yes' if c.can_cause_patient_harm else 'No'} |",
            "",
            "## Classification Rationale",
            "",
            "```",
            c.classification_rationale,
            "```",
            "",
        ]

        if c.notes:
            lines.extend(
                [
                    "## Notes",
                    "",
                ]
            )
            for note in c.notes:
                lines.append(f"- {note}")
            lines.append("")

        if c.mitigations:
            lines.extend(
                [
                    "## Recommended Mitigations",
                    "",
                ]
            )
            for mitigation in c.mitigations:
                lines.append(f"- {mitigation}")
            lines.append("")

        # FDA submission requirements based on tier
        lines.extend(
            [
                "## FDA Premarket Submission Requirements",
                "",
            ]
        )

        if c.risk_tier == RiskTier.TIER_1:
            lines.extend(
                [
                    "As a **Tier 1 (Higher Cybersecurity Risk)** device, the following "
                    "documentation is required:",
                    "",
                    "1. **Threat Modeling**: Comprehensive threat model identifying all attack vectors",
                    "2. **Security Risk Assessment**: Detailed risk analysis per ISO 14971",
                    "3. **Security Controls**: Documentation of all cybersecurity controls implemented",
                    "4. **SBOM**: Complete Software Bill of Materials (CycloneDX or SPDX format)",
                    "5. **Vulnerability Testing**: Results of security testing including:",
                    "   - Fuzz testing of all inputs",
                    "   - Penetration testing",
                    "   - Static code analysis",
                    "6. **Patch Management Plan**: Documented procedures for addressing vulnerabilities",
                    "7. **Incident Response Plan**: Process for responding to cybersecurity incidents",
                    "",
                ]
            )
        elif c.risk_tier == RiskTier.TIER_2:
            lines.extend(
                [
                    "As a **Tier 2 (Standard Cybersecurity Risk)** device, the following "
                    "documentation is required:",
                    "",
                    "1. **Security Risk Assessment**: Risk analysis appropriate to device risk",
                    "2. **Security Controls**: Documentation of cybersecurity controls",
                    "3. **SBOM**: Software Bill of Materials",
                    "4. **Vulnerability Management**: Process for identifying and addressing vulnerabilities",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "Device does not qualify as a cyber device. Standard medical device "
                    "submission requirements apply.",
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "",
                "*Classification performed per FDA FD&C Act Section 524B and "
                "FDA Cybersecurity Guidance (June 2025).*",
            ]
        )

        return "\n".join(lines)

    def save_report(self, path: Path | str) -> Path:
        """Save classification report to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_report())
        return path


def classify_cyber_device(
    device_name: str,
    software_types: list[str] | None = None,
    connectivity_types: list[str] | None = None,
    known_vulnerabilities: int = 0,
    harm_severity: str = "No Patient Injury",
    output_path: Path | str | None = None,
) -> CyberDeviceClassification:
    """Convenience function to classify a medical device.

    Args:
        device_name: Name of the medical device
        software_types: List of software type strings (see SoftwareType enum values)
        connectivity_types: List of connectivity type strings (see ConnectivityType enum values)
        known_vulnerabilities: Number of known security vulnerabilities
        harm_severity: Potential harm severity string (see HarmSeverity enum values)
        output_path: Optional path to save classification report

    Returns:
        CyberDeviceClassification result

    Example:
        >>> result = classify_cyber_device(
        ...     device_name="DICOM PACS Viewer",
        ...     software_types=["Application Software", "Web Interface"],
        ...     connectivity_types=["DICOM Network Protocol", "Wireless Network"],
        ...     known_vulnerabilities=3,
        ...     harm_severity="Moderate Injury",
        ... )
        >>> print(f"Is cyber device: {result.is_cyber_device}")
        >>> print(f"Risk tier: {result.risk_tier.value}")

    """
    # Convert string types to enums
    sw_types: list[SoftwareType] = []
    for st in software_types or []:
        for sw_enum in SoftwareType:
            if sw_enum.value.lower() == st.lower():
                sw_types.append(sw_enum)
                break

    conn_types: list[ConnectivityType] = []
    for ct in connectivity_types or []:
        for conn_enum in ConnectivityType:
            if conn_enum.value.lower() == ct.lower():
                conn_types.append(conn_enum)
                break

    harm = HarmSeverity.NO_INJURY
    for harm_enum in HarmSeverity:
        if harm_enum.label.lower() == harm_severity.lower():
            harm = harm_enum
            break

    classifier = CyberDeviceClassifier()
    result = classifier.classify(
        device_name=device_name,
        software_types=sw_types,
        connectivity_types=conn_types,
        known_vulnerabilities=known_vulnerabilities,
        harm_severity=harm,
    )

    if output_path:
        classifier.save_report(output_path)

    return result


if __name__ == "__main__":
    # Example: Classify a DICOM imaging device
    classifier = CyberDeviceClassifier()
    result = classifier.classify(
        device_name="DICOM PACS Workstation",
        device_model="DW-5000",
        manufacturer="Medical Imaging Corp",
        fda_classification="Class II 510(k)",
        software_types=[
            SoftwareType.OPERATING_SYSTEM,
            SoftwareType.APPLICATION_SOFTWARE,
            SoftwareType.WEB_INTERFACE,
        ],
        connectivity_types=[
            ConnectivityType.WIRED_NETWORK,
            ConnectivityType.WIRELESS_NETWORK,
            ConnectivityType.DICOM,
        ],
        known_vulnerabilities=5,
        harm_severity=HarmSeverity.MODERATE_INJURY,
        exploit_probability=ExploitProbability.POSSIBLE,
    )

    print(classifier.generate_report())
    print(f"\n[i] Is Cyber Device: {result.is_cyber_device}")
    print(f"[i] Risk Tier: {result.risk_tier.value}")
    print(f"[i] Risk Score: {result.risk_score}/25")
