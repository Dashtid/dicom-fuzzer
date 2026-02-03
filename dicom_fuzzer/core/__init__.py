"""Core DICOM fuzzing functionality.

This module contains the fundamental components for DICOM parsing, mutation,
generation, validation, and advanced stability features including crash
intelligence and stability tracking.

Subpackages:
- coverage/: Coverage tracking, corpus management, stability metrics
- crash/: Crash detection, triage, and analysis
- dicom/: DICOM file I/O -- parsing, validation, lazy loading
- engine/: Fuzzing engines and orchestrators
- harness/: Target execution and monitoring
- mutation/: Mutation primitives -- byte, dataset, multiframe
- reporting/: Reports, analytics, templates
- series/: 3D series management
- session/: Runtime and session management
"""

# Shared fuzzing constants (v1.7.0)
# Network re-exports (backward compatibility -- canonical location is strategies.network)
from dicom_fuzzer.strategies.network import (
    DICOMNetworkConfig,
    DICOMNetworkFuzzer,
    DICOMProtocolBuilder,
    FuzzingStrategy,
    NetworkFuzzResult,
    PDUFuzzingMixin,
    TLSFuzzingMixin,
)
from dicom_fuzzer.strategies.network.dimse import (
    DICOMElement,
    DIMSEFuzzingConfig,
    DIMSEMessage,
    QueryRetrieveLevel,
    SOPClass,
    UIDGenerator,
)

# State-Aware Fuzzer (moved to strategies/network/stateful/)
from dicom_fuzzer.strategies.network.stateful.state_aware_fuzzer import (
    MessageSequence,
    ProtocolMessage,
    StateAwareFuzzer,
    StateGuidedHavoc,
    StateInferenceEngine,
    StateMutator,
)
from dicom_fuzzer.strategies.network.tls import (
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
from dicom_fuzzer.strategies.network.tls.fuzzer import (
    create_dicom_tls_fuzzer,
    quick_scan,
)

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

# Coverage tracking & corpus management
from .coverage.corpus_minimizer import (
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
from .coverage.coverage_types import (
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
from .coverage.stability_tracker import StabilityMetrics, StabilityTracker

# Crash intelligence
from .crash.crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
)

# DICOM I/O
from .dicom.dicom_series import DicomSeries
from .dicom.lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)
from .dicom.parser import DicomParser
from .dicom.validator import DicomValidator

# Fuzzing engines
from .engine.generator import DICOMGenerator
from .engine.gui_monitor import (
    GUIFuzzer,
    GUIMonitor,
    GUIResponse,
    MonitorConfig,
    ResponseAwareFuzzer,
    StateCoverageTracker,
)
from .engine.persistent_fuzzer import (
    MOptScheduler,
    PersistentFuzzer,
    PowerSchedule,
    SeedEntry,
)
from .engine.synthetic import (
    SyntheticDataGenerator,
    SyntheticDicomGenerator,
    SyntheticPatient,
    SyntheticSeries,
    SyntheticStudy,
    generate_sample_files,
)

# Exceptions
from .exceptions import DicomFuzzingError, NetworkTimeoutError, ValidationError

# Target harness
from .harness.target_runner import ExecutionStatus, TargetRunner

# Mutation primitives
from .mutation.dataset_mutator import DatasetMutator
from .mutation.multiframe_handler import (
    FrameInfo,
    MultiFrameHandler,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
    create_multiframe_mutator,
)
from .mutation.mutator import DicomMutator
from .mutation.test_minimizer import MinimizationStrategy, TestMinimizer

# Reporting
from .reporting.series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)

# Series management
from .series.series_cache import CacheEntry, SeriesCache
from .series.series_detector import SeriesDetector
from .series.series_validator import (
    SeriesValidator,
    ValidationIssue,
    ValidationReport,
    ValidationSeverity,
)
from .series.series_writer import SeriesMetadata, SeriesWriter

# Session management
from .session.config_validator import ConfigValidator, ValidationResult
from .session.error_recovery import CampaignRecovery, CampaignStatus, SignalHandler
from .session.resource_manager import ResourceLimits, ResourceManager

# Protocol types
from .types import DICOMCommand, DIMSECommand, MutationSeverity, PDUType

# Backward compatibility alias
FuzzingConfig = DIMSEFuzzingConfig

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
    # Network Protocol Fuzzer (canonical: strategies.network)
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
    # Session management
    "ResourceManager",
    "ResourceLimits",
    "CampaignRecovery",
    "CampaignStatus",
    "SignalHandler",
    "ConfigValidator",
    "ValidationResult",
    # Crash intelligence
    "CrashTriageEngine",
    "CrashTriage",
    "ExploitabilityRating",
    "TestMinimizer",
    "MinimizationStrategy",
    # Stability tracking
    "StabilityTracker",
    "StabilityMetrics",
    # 3D Series support
    "DicomSeries",
    "SeriesDetector",
    "SeriesValidator",
    "ValidationIssue",
    "ValidationReport",
    "ValidationSeverity",
    "SeriesWriter",
    "SeriesMetadata",
    # Performance optimization
    "LazyDicomLoader",
    "create_metadata_loader",
    "create_deferred_loader",
    "SeriesCache",
    "CacheEntry",
    # Enhanced Reporting & Analytics
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
    # Response-Aware Fuzzing with State Coverage
    "GUIFuzzer",
    "GUIMonitor",
    "GUIResponse",
    "MonitorConfig",
    "ResponseAwareFuzzer",
    "StateCoverageTracker",
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
    # DICOM TLS Security Fuzzer
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
    # Corpus Minimization & Multi-Fuzzer Sync
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
    # Multi-Frame Handler
    "FrameInfo",
    "MultiFrameHandler",
    "MultiFrameMutationRecord",
    "MultiFrameMutationStrategy",
    "create_multiframe_mutator",
]
