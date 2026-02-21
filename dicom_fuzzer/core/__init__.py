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
- mutation/: Mutation primitives -- multiframe and orchestration
- reporting/: Reports, analytics, templates
- session/: Runtime and session management
"""

from .constants import (
    BugSeverity,
    CrashSeverity,
    DICOMState,
    Severity,
    SeverityLevel,
    StateTransitionType,
)

# Coverage & state types (used by network/stateful fuzzing)
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
from .exceptions import DicomFuzzingError, ValidationError

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
    # Enums
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
    # Coverage & state types
    "GUIStateTransition",
    "ProtocolStateTransition",
    "StateCoverage",
    "StateFingerprint",
    "StateTransition",
    # Multi-frame handler
    "FrameInfo",
    "MultiFrameHandler",
    "MultiFrameMutationRecord",
    "MultiFrameMutationStrategy",
    "create_multiframe_mutator",
]
