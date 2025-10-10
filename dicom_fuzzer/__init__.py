"""
DICOM Fuzzer - A professional-grade DICOM fuzzing framework.

This package provides comprehensive fuzzing capabilities for DICOM medical imaging systems,
including mutation-based fuzzing, crash analysis, and reporting.
"""

__version__ = "1.0.0"
__author__ = "David Dashti"
__license__ = "MIT"

# Core components
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.validator import DicomValidator
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.reporter import ReportGenerator
from dicom_fuzzer.core.statistics import StatisticsCollector

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "DicomParser",
    "DICOMGenerator",
    "DicomMutator",
    "DicomValidator",
    "FuzzingSession",
    "CrashAnalyzer",
    "ReportGenerator",
    "StatisticsCollector",
]
