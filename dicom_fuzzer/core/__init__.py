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
from .error_recovery import CampaignRecovery, CampaignStatus, SignalHandler
from .exceptions import DicomFuzzingError, NetworkTimeoutError, ValidationError
from .generator import DICOMGenerator
from .mutator import DicomMutator
from .parser import DicomParser
from .resource_manager import ResourceLimits, ResourceManager
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
]
