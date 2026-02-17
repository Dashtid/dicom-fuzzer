"""Core DICOM fuzzing functionality.

This module contains the fundamental components for DICOM parsing, mutation,
generation, validation, and advanced stability features including crash
intelligence and stability tracking.

Subpackages:
- corpus/: Corpus management and minimization
- crash/: Crash detection, triage, and analysis
- dicom/: DICOM file I/O -- parsing, validation, series
- engine/: Fuzzing engines and orchestrators
- harness/: Target execution and monitoring
- mutation/: Mutation primitives -- byte, multiframe, orchestration
- reporting/: Reports, analytics, templates
- session/: Runtime and session management
"""

from .constants import (
    ARITH_MAX,
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    BugSeverity,
    ByteMutationType,
    CrashSeverity,
    DICOMState,
    MutationType,
    Severity,
    SeverityLevel,
    StateTransitionType,
)

# Corpus management & minimization
from .corpus.corpus_minimizer import (
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
from .corpus.coverage_types import (
    GUIStateTransition,
    ProtocolStateTransition,
    StateCoverage,
    StateFingerprint,
    StateTransition,
)

# Crash intelligence
from .crash.crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
)

# DICOM I/O
from .dicom.dicom_series import DicomSeries
from .dicom.parser import DicomParser

# Series detection & writing (in core/dicom/)
from .dicom.series_detector import SeriesDetector
from .dicom.series_writer import SeriesMetadata, SeriesWriter
from .dicom.validator import DicomValidator

# Fuzzing engines
from .engine import DICOMGenerator

# Exceptions
from .exceptions import DicomFuzzingError, NetworkTimeoutError, ValidationError

# Target harness
from .harness.target_runner import ExecutionStatus, TargetRunner

# Mutation primitives
from .mutation.multiframe_handler import (
    FrameInfo,
    MultiFrameHandler,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
    create_multiframe_mutator,
)
from .mutation.mutator import DicomMutator

# Reporting
from .reporting.series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)

# Session management
from .session.resource_manager import ResourceLimits, ResourceManager

# Protocol types
from .types import DICOMCommand, DIMSECommand, PDUType

__all__ = [
    # Fuzzing constants (AFL-inspired boundary values)
    "ARITH_MAX",
    "INTERESTING_8",
    "INTERESTING_16",
    "INTERESTING_32",
    # Enums
    "ByteMutationType",
    "MutationType",
    "BugSeverity",
    "CrashSeverity",
    "DICOMState",
    "Severity",
    "SeverityLevel",
    "StateTransitionType",
    # Core functionality
    "DICOMGenerator",
    "DicomFuzzingError",
    "DicomMutator",
    "DicomParser",
    "DicomValidator",
    "NetworkTimeoutError",
    "ValidationError",
    # Protocol types
    "DICOMCommand",
    "DIMSECommand",
    "PDUType",
    # Target harness
    "ExecutionStatus",
    "TargetRunner",
    # Session management
    "ResourceLimits",
    "ResourceManager",
    # Crash intelligence
    "CrashTriage",
    "CrashTriageEngine",
    "ExploitabilityRating",
    # DICOM series
    "DicomSeries",
    "SeriesDetector",
    "SeriesMetadata",
    "SeriesWriter",
    # Reporting
    "Series3DReport",
    "Series3DReportGenerator",
    "SeriesMutationSummary",
    # Coverage types
    "GUIStateTransition",
    "ProtocolStateTransition",
    "StateCoverage",
    "StateFingerprint",
    "StateTransition",
    # Corpus management
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
    # Multi-frame handler
    "FrameInfo",
    "MultiFrameHandler",
    "MultiFrameMutationRecord",
    "MultiFrameMutationStrategy",
    "create_multiframe_mutator",
]
