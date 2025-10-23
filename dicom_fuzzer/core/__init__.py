"""Core DICOM fuzzing functionality.

This module contains the fundamental components for DICOM parsing, mutation,
generation, validation, and advanced stability features including crash
intelligence and stability tracking.
"""

from .config_validator import ConfigValidator, ValidationResult
from .crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
    Severity,
)
from .dicom_series import DicomSeries
from .error_recovery import CampaignRecovery, CampaignStatus, SignalHandler
from .exceptions import DicomFuzzingError, NetworkTimeoutError, ValidationError
from .generator import DICOMGenerator
from .lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)
from .mutator import DicomMutator
from .parser import DicomParser
from .resource_manager import ResourceLimits, ResourceManager
from .series_cache import CacheEntry, SeriesCache
from .series_detector import SeriesDetector
from .series_validator import (
    SeriesValidator,
    ValidationIssue,
    ValidationReport,
    ValidationSeverity,
)
from .series_writer import SeriesMetadata, SeriesWriter
from .stability_tracker import StabilityMetrics, StabilityTracker
from .target_runner import ExecutionStatus, TargetRunner
from .test_minimizer import MinimizationStrategy, TestMinimizer
from .types import MutationSeverity
from .validator import DicomValidator

__all__ = [
    # Core functionality
    "DicomFuzzingError",
    "NetworkTimeoutError",
    "ValidationError",
    "DicomParser",
    "DicomMutator",
    "DICOMGenerator",
    "DicomValidator",
    "MutationSeverity",
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
]
