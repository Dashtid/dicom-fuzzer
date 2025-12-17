"""Reporting modules for DICOM Fuzzer.

This package provides report generation for various compliance frameworks
and output formats.
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
from dicom_fuzzer.reporting.sbom import (
    SBOM,
    DependencyRelationship,
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
    # SBOM with NTIA Compliance
    "SBOM",
    "SBOMComponent",
    "SBOMGenerator",
    "SBOMMetadata",
    "DependencyRelationship",
    "NTIACompliance",
    "generate_sbom",
    "validate_sbom_ntia_compliance",
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
