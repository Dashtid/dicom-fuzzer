"""Reporting modules for DICOM Fuzzer.

This package provides report generation for various compliance frameworks
and output formats, including:
- FDA Compliance Reports (June 2025 Guidance)
- SBOM Generation (NTIA/CISA 2025 compliant)
- Penetration Test Reports
- SAST/DAST Integration
- CVD Policy Generation
- Threat Modeling
- Security Risk Reports
"""

from dicom_fuzzer.reporting.cvd_policy import (
    CVDPolicyConfig,
    CVDPolicyGenerator,
    generate_cvd_policy,
)
from dicom_fuzzer.reporting.cyber_device import (
    ConnectivityType,
    CyberDeviceClassification,
    CyberDeviceClassifier,
    ExploitProbability,
    HarmSeverity,
    RiskTier,
    SoftwareType,
    classify_cyber_device,
)
from dicom_fuzzer.reporting.fda_compliance import (
    FDAComplianceReport,
    FDAComplianceReporter,
    FuzzingParameters,
    TestCoverage,
    ToolConfiguration,
    VulnerabilityFinding,
)
from dicom_fuzzer.reporting.patch_timeline import (
    PatchStatus,
    PatchTimelineConfig,
    PatchTimelineReportGenerator,
    VulnerabilityPatch,
    generate_patch_timeline_report,
)
from dicom_fuzzer.reporting.patch_timeline import (
    SeverityLevel as PatchSeverityLevel,
)
from dicom_fuzzer.reporting.penetration_test import (
    AffectedComponent,
    AttackVector,
    CVSSScore,
    PenetrationTestReport,
    PenetrationTestReporter,
    PentestVulnerability,
    ProofOfConcept,
    Remediation,
    RemediationStatus,
    TestingMethodology,
    TestingPhase,
    TestScope,
    VulnerabilitySeverity,
)
from dicom_fuzzer.reporting.sast_dast import (
    BanditParser,
    CodeLocation,
    FindingSeverity,
    PipAuditParser,
    SARIFParser,
    SASTDASTReport,
    SASTDASTReporter,
    ScanSummary,
    SecurityFinding,
    SemgrepParser,
    ToolCategory,
    ToolInfo,
)
from dicom_fuzzer.reporting.sbom import (
    SBOM,
    CISA2025Compliance,
    DependencyRelationship,
    GenerationContext,
    NTIACompliance,
    SBOMComponent,
    SBOMGenerator,
    SBOMMetadata,
    generate_sbom,
    validate_sbom_ntia_compliance,
)
from dicom_fuzzer.reporting.security_risk_report import (
    RiskAcceptability,
    RiskControlMeasure,
    RiskLikelihood,
    RiskSeverity,
    SecurityRisk,
    SecurityRiskReportConfig,
    SecurityRiskReportGenerator,
    generate_security_risk_report,
)
from dicom_fuzzer.reporting.threat_model import (
    Threat,
    ThreatModelConfig,
    ThreatModelGenerator,
    generate_threat_model,
)
from dicom_fuzzer.reporting.unresolved_anomaly import (
    AnomalyAssessmentConfig,
    AnomalySeverity,
    AnomalyType,
    SafetyImpact,
    UnresolvedAnomaly,
    UnresolvedAnomalyAssessmentGenerator,
    generate_anomaly_assessment,
)

__all__ = [
    # FDA Compliance
    "FDAComplianceReport",
    "FDAComplianceReporter",
    "FuzzingParameters",
    "TestCoverage",
    "ToolConfiguration",
    "VulnerabilityFinding",
    # SBOM with NTIA/CISA 2025 Compliance
    "SBOM",
    "SBOMComponent",
    "SBOMGenerator",
    "SBOMMetadata",
    "DependencyRelationship",
    "NTIACompliance",
    "CISA2025Compliance",
    "GenerationContext",
    "generate_sbom",
    "validate_sbom_ntia_compliance",
    # Penetration Test Reporting
    "PenetrationTestReport",
    "PenetrationTestReporter",
    "PentestVulnerability",
    "CVSSScore",
    "AffectedComponent",
    "ProofOfConcept",
    "Remediation",
    "RemediationStatus",
    "TestScope",
    "TestingMethodology",
    "TestingPhase",
    "AttackVector",
    "VulnerabilitySeverity",
    # SAST/DAST Integration
    "SASTDASTReport",
    "SASTDASTReporter",
    "SecurityFinding",
    "ScanSummary",
    "ToolInfo",
    "ToolCategory",
    "FindingSeverity",
    "CodeLocation",
    "SemgrepParser",
    "BanditParser",
    "SARIFParser",
    "PipAuditParser",
    # CVD Policy
    "CVDPolicyConfig",
    "CVDPolicyGenerator",
    "generate_cvd_policy",
    # Threat Model
    "Threat",
    "ThreatModelConfig",
    "ThreatModelGenerator",
    "generate_threat_model",
    # Security Risk Report
    "RiskAcceptability",
    "RiskControlMeasure",
    "RiskLikelihood",
    "RiskSeverity",
    "SecurityRisk",
    "SecurityRiskReportConfig",
    "SecurityRiskReportGenerator",
    "generate_security_risk_report",
    # Unresolved Anomaly Assessment
    "AnomalyAssessmentConfig",
    "AnomalySeverity",
    "AnomalyType",
    "SafetyImpact",
    "UnresolvedAnomaly",
    "UnresolvedAnomalyAssessmentGenerator",
    "generate_anomaly_assessment",
    # Patch Timeline Tracking
    "PatchStatus",
    "PatchTimelineConfig",
    "PatchTimelineReportGenerator",
    "PatchSeverityLevel",
    "VulnerabilityPatch",
    "generate_patch_timeline_report",
    # Cyber Device Classification
    "ConnectivityType",
    "CyberDeviceClassification",
    "CyberDeviceClassifier",
    "ExploitProbability",
    "HarmSeverity",
    "RiskTier",
    "SoftwareType",
    "classify_cyber_device",
]
