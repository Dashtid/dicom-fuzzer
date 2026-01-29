"""Core DICOM fuzzing functionality.

This module contains the fundamental components for DICOM parsing, mutation,
generation, validation, and advanced stability features including crash
intelligence and stability tracking.
"""

# Shared fuzzing constants (v1.7.0)
from .config_validator import ConfigValidator, ValidationResult
from .constants import (
    ARITH_MAX,
    INTERESTING_8,
    INTERESTING_8_UNSIGNED,
    INTERESTING_16,
    INTERESTING_16_UNSIGNED,
    INTERESTING_32,
    INTERESTING_32_UNSIGNED,
    MAP_SIZE,
    MAP_SIZE_POW2,
    SEVERITY_SCORES,
    BugSeverity,
    ByteMutationType,
    CoverageType,
    CrashSeverity,
    DICOMState,
    GUIResponseType,
    MutationType,
    ProtocolResponseType,
    ResponseType,
    Severity,
    SeverityLevel,
    StateTransitionType,
)

# Corpus Minimization & Multi-Fuzzer Sync (v1.5.0)
from .corpus_minimizer import (
    CorpusMinimizer,
    CorpusStats,
    CorpusSynchronizer,
    CoverageCollector,
    FuzzerNode,
    MinimizationConfig,
    SimpleCoverageCollector,
    SyncConfig,
    SyncMode,
    TargetCoverageCollector,
    create_sync_node,
    minimize_corpus,
)

# Unified Coverage Types (v1.8.0)
from .coverage_types import (
    CoverageInfo,
    CoverageInsight,
    CoverageMap,
    CoverageSnapshot,
    ExecutionCoverageInfo,
    GUIStateTransition,
    ProtocolStateTransition,
    SeedCoverageInfo,
    StateCoverage,
    StateFingerprint,
    StateTransition,
)
from .crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
)

# Dataset Mutation (v1.7.0)
from .dataset_mutator import DatasetMutator
from .dicom_series import DicomSeries

# Network Protocol Fuzzer (v1.5.0) - moved to strategies/robustness/network/
from dicom_fuzzer.strategies.robustness.network import (
    DICOMNetworkConfig,
    DICOMNetworkFuzzer,
    DICOMProtocolBuilder,
    FuzzingStrategy,
    NetworkFuzzResult,
    PDUFuzzingMixin,
    TLSFuzzingMixin,
)

# DICOM TLS Security Fuzzer (v1.5.0, modularized v1.7.0) - moved to strategies/robustness/network/tls/
from dicom_fuzzer.strategies.robustness.network.tls import (
    COMMON_AE_TITLES,
    INJECTION_PAYLOADS,
    SOP_CLASS_UIDS,
    SSL_VERSIONS,
    WEAK_CIPHERS,
    AuthBypassType,
    DICOMAuthTester,
    DICOMTLSFuzzer,
    DICOMTLSFuzzerConfig,
    PACSQueryInjector,
    QueryInjectionType,
    TLSFuzzResult,
    TLSSecurityTester,
    TLSVulnerability,
)
from dicom_fuzzer.strategies.robustness.network.tls.fuzzer import (
    create_dicom_tls_fuzzer,
    quick_scan,
)


# DIMSE Protocol Types (v1.7.0) - moved to strategies/robustness/network/dimse/
from dicom_fuzzer.strategies.robustness.network.dimse import (
    DICOMElement,
    DIMSEFuzzingConfig,
    DIMSEMessage,
    QueryRetrieveLevel,
    SOPClass,
    UIDGenerator,
)
# Backward compatibility alias
FuzzingConfig = DIMSEFuzzingConfig
from .error_recovery import CampaignRecovery, CampaignStatus, SignalHandler
from .exceptions import DicomFuzzingError, NetworkTimeoutError, ValidationError
from .generator import DICOMGenerator
from .gui_monitor import (
    GUIFuzzer,
    GUIMonitor,
    GUIResponse,
    MonitorConfig,
    ResponseAwareFuzzer,
    StateCoverageTracker,
)
from .lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)

# Multi-Frame Handler (v1.5.0, modularized v1.8.0)
from .multiframe_handler import (
    FrameInfo,
    MultiFrameHandler,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
    create_multiframe_mutator,
)
from .mutator import DicomMutator
from .parser import DicomParser
from .persistent_fuzzer import (
    MOptScheduler,
    PersistentFuzzer,
    PowerSchedule,
    SeedEntry,
)
from .resource_manager import ResourceLimits, ResourceManager
from .series_cache import CacheEntry, SeriesCache
from .series_detector import SeriesDetector
from .series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)
from .series_validator import (
    SeriesValidator,
    ValidationIssue,
    ValidationReport,
    ValidationSeverity,
)
from .series_writer import SeriesMetadata, SeriesWriter
from .stability_tracker import StabilityMetrics, StabilityTracker
# State-Aware Fuzzer (v1.5.0) - moved to strategies/robustness/network/stateful/
from dicom_fuzzer.strategies.robustness.network.stateful.state_aware_fuzzer import (
    MessageSequence,
    ProtocolMessage,
    StateAwareFuzzer,
    StateGuidedHavoc,
    StateInferenceEngine,
    StateMutator,
)
from .synthetic import (
    SyntheticDataGenerator,
    SyntheticDicomGenerator,
    SyntheticPatient,
    SyntheticSeries,
    SyntheticStudy,
    generate_sample_files,
)
from .target_runner import ExecutionStatus, TargetRunner
from .test_minimizer import MinimizationStrategy, TestMinimizer
from .types import DICOMCommand, DIMSECommand, MutationSeverity, PDUType
from .validator import DicomValidator

__all__ = [
    # Shared fuzzing constants (v1.7.0)
    "ARITH_MAX",
    "INTERESTING_8",
    "INTERESTING_8_UNSIGNED",
    "INTERESTING_16",
    "INTERESTING_16_UNSIGNED",
    "INTERESTING_32",
    "INTERESTING_32_UNSIGNED",
    "MAP_SIZE",
    "MAP_SIZE_POW2",
    # Unified Mutation Type Enum (v1.8.0)
    "ByteMutationType",
    "MutationType",
    # Unified Severity and Response Type Enums (v1.8.0)
    "BugSeverity",
    "CrashSeverity",
    "GUIResponseType",
    "ProtocolResponseType",
    "ResponseType",
    "Severity",
    "SeverityLevel",
    "SEVERITY_SCORES",
    # Unified Coverage Types (v1.8.0)
    "CoverageInfo",
    "CoverageInsight",
    "CoverageMap",
    "CoverageSnapshot",
    "CoverageType",
    "ExecutionCoverageInfo",
    "GUIStateTransition",
    "ProtocolStateTransition",
    "SeedCoverageInfo",
    "StateCoverage",
    "StateFingerprint",
    "StateTransition",
    # Core functionality
    "DicomFuzzingError",
    "NetworkTimeoutError",
    "ValidationError",
    "DicomParser",
    "DicomMutator",
    "DICOMGenerator",
    "DicomValidator",
    "MutationSeverity",
    # Protocol types (v1.7.0)
    "DICOMCommand",
    "DIMSECommand",
    "PDUType",
    # Network Protocol Fuzzer (moved to strategies/robustness/network/)
    "DICOMNetworkConfig",
    "DICOMNetworkFuzzer",
    "DICOMProtocolBuilder",
    "FuzzingStrategy",
    "NetworkFuzzResult",
    "PDUFuzzingMixin",
    "TLSFuzzingMixin",
    # DIMSE Protocol Types (v1.7.0)
    "DICOMElement",
    "DIMSEFuzzingConfig",
    "DIMSEMessage",
    "FuzzingConfig",
    "QueryRetrieveLevel",
    "SOPClass",
    "UIDGenerator",
    # Dataset Mutation (v1.7.0)
    "DatasetMutator",
    # Target testing
    "TargetRunner",
    "ExecutionStatus",
    # Stability features (v1.1.0)
    "ResourceManager",
    "ResourceLimits",
    "CampaignRecovery",
    "CampaignStatus",
    "SignalHandler",
    "ConfigValidator",
    "ValidationResult",
    # Crash intelligence (v1.2.0)
    "CrashTriageEngine",
    "CrashTriage",
    "ExploitabilityRating",
    "TestMinimizer",
    "MinimizationStrategy",
    # Stability tracking (v1.2.0)
    "StabilityTracker",
    "StabilityMetrics",
    # 3D Series support (v2.0.0-alpha)
    "DicomSeries",
    "SeriesDetector",
    "SeriesValidator",
    "ValidationIssue",
    "ValidationReport",
    "ValidationSeverity",
    "SeriesWriter",
    "SeriesMetadata",
    # Performance optimization (v2.0.0-alpha Phase 4)
    "LazyDicomLoader",
    "create_metadata_loader",
    "create_deferred_loader",
    "SeriesCache",
    "CacheEntry",
    # Enhanced Reporting & Analytics (v2.0.0-alpha Phase 5)
    "Series3DReport",
    "Series3DReportGenerator",
    "SeriesMutationSummary",
    # Synthetic DICOM Generation
    "SyntheticDicomGenerator",
    "SyntheticDataGenerator",
    "SyntheticPatient",
    "SyntheticStudy",
    "SyntheticSeries",
    "generate_sample_files",
    # Response-Aware Fuzzing with State Coverage (v1.5.0, modularized v1.8.0)
    "GUIFuzzer",
    "GUIMonitor",
    "GUIResponse",
    "MonitorConfig",
    "ResponseAwareFuzzer",  # Backward compatibility alias for GUIFuzzer
    "StateCoverageTracker",
    # Advanced Fuzzing Engines (v1.5.0)
    # State-Aware Protocol Fuzzing
    "DICOMState",
    "StateTransitionType",
    "MessageSequence",
    "ProtocolMessage",
    "StateAwareFuzzer",
    "StateGuidedHavoc",
    "StateInferenceEngine",
    "StateMutator",
    # Persistent Mode Fuzzing
    "MOptScheduler",
    "PersistentFuzzer",
    "PowerSchedule",
    "SeedEntry",
    # DICOM TLS Security Fuzzer (v1.5.0, modularized v1.7.0)
    "COMMON_AE_TITLES",
    "INJECTION_PAYLOADS",
    "SOP_CLASS_UIDS",
    "SSL_VERSIONS",
    "WEAK_CIPHERS",
    "AuthBypassType",
    "DICOMAuthTester",
    "DICOMTLSFuzzer",
    "DICOMTLSFuzzerConfig",
    "PACSQueryInjector",
    "PDUType",
    "QueryInjectionType",
    "TLSFuzzResult",
    "TLSSecurityTester",
    "TLSVulnerability",
    "create_dicom_tls_fuzzer",
    "quick_scan",
    # Corpus Minimization & Multi-Fuzzer Sync (v1.5.0)
    "CorpusMinimizer",
    "CorpusStats",
    "CorpusSynchronizer",
    "CoverageCollector",
    "FuzzerNode",
    "MinimizationConfig",
    "SimpleCoverageCollector",
    "SyncConfig",
    "SyncMode",
    "TargetCoverageCollector",
    "create_sync_node",
    "minimize_corpus",
    # Multi-Frame Handler (v1.5.0, modularized v1.8.0)
    "FrameInfo",
    "MultiFrameHandler",
    "MultiFrameMutationRecord",
    "MultiFrameMutationStrategy",
    "create_multiframe_mutator",
]
