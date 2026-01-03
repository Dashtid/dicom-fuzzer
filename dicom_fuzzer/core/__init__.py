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
)

# Corpus Minimization & Multi-Fuzzer Sync (v1.5.0)
from .corpus_minimizer import (
    CorpusMinimizer,
    CorpusStats,
    CorpusSynchronizer,
    CoverageCollector,
    CoverageInfo,
    CoverageType,
    FuzzerNode,
    MinimizationConfig,
    SimpleCoverageCollector,
    SyncConfig,
    SyncMode,
    TargetCoverageCollector,
    create_sync_node,
    minimize_corpus,
)
from .crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
    Severity,
)

# Dataset Mutation (v1.7.0)
from .dataset_mutator import DatasetMutator
from .dicom_series import DicomSeries

# DICOM TLS Security Fuzzer (v1.5.0)
from .dicom_tls_fuzzer import (
    AuthBypassType,
    DICOMAuthTester,
    DICOMTLSFuzzer,
    DICOMTLSFuzzerConfig,
    PACSQueryInjector,
    QueryInjectionType,
    TLSFuzzResult,
    TLSSecurityTester,
    TLSVulnerability,
    create_dicom_tls_fuzzer,
    quick_scan,
)

# Advanced Fuzzing Engines (v1.5.0)
from .differential_fuzzer import (
    DCMTKParser,
    DICOMParser,
    Difference,
    DifferenceType,
    DifferentialAnalyzer,
    DifferentialFuzzer,
    DifferentialResult,
    GDCMParser,
    ImplementationType,
    ParseResult,
    PydicomParser,
)

# DIMSE Protocol Types (v1.7.0)
from .dimse_types import (
    DICOMElement,
    DIMSEFuzzingConfig,
    DIMSEMessage,
    FuzzingConfig,
    QueryRetrieveLevel,
    SOPClass,
    UIDGenerator,
)
from .error_recovery import CampaignRecovery, CampaignStatus, SignalHandler
from .exceptions import DicomFuzzingError, NetworkTimeoutError, ValidationError
from .generator import DICOMGenerator
from .gui_monitor import (
    GUIMonitor,
    GUIResponse,
    MonitorConfig,
    ResponseAwareFuzzer,
    ResponseType,
    SeverityLevel,
    StateCoverageTracker,
    StateTransition,
)
from .lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)
from .mutator import DicomMutator
from .parser import DicomParser
from .persistent_fuzzer import (
    CoverageMap,
    MOptScheduler,
    MutationType,
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
from .state_aware_fuzzer import (
    DICOMState,
    MessageSequence,
    ProtocolMessage,
    StateAwareFuzzer,
    StateCoverage,
    StateFingerprint,
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
    "Severity",
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
    # Response-Aware Fuzzing with State Coverage (v1.5.0)
    "GUIMonitor",
    "GUIResponse",
    "MonitorConfig",
    "ResponseAwareFuzzer",
    "ResponseType",
    "SeverityLevel",
    "StateCoverageTracker",
    "StateTransition",
    # Advanced Fuzzing Engines (v1.5.0)
    # State-Aware Protocol Fuzzing
    "DICOMState",
    "MessageSequence",
    "ProtocolMessage",
    "StateAwareFuzzer",
    "StateCoverage",
    "StateFingerprint",
    "StateGuidedHavoc",
    "StateInferenceEngine",
    "StateMutator",
    # Differential Fuzzing
    "DCMTKParser",
    "Difference",
    "DifferenceType",
    "DifferentialAnalyzer",
    "DifferentialFuzzer",
    "DifferentialResult",
    "DICOMParser",
    "GDCMParser",
    "ImplementationType",
    "ParseResult",
    "PydicomParser",
    # Persistent Mode Fuzzing
    "CoverageMap",
    "MOptScheduler",
    "MutationType",
    "PersistentFuzzer",
    "PowerSchedule",
    "SeedEntry",
    # DICOM TLS Security Fuzzer (v1.5.0)
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
    "CoverageInfo",
    "CoverageType",
    "FuzzerNode",
    "MinimizationConfig",
    "SimpleCoverageCollector",
    "SyncConfig",
    "SyncMode",
    "TargetCoverageCollector",
    "create_sync_node",
    "minimize_corpus",
]
