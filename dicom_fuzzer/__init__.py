"""DICOM Fuzzer - A professional-grade DICOM fuzzing framework.

This package provides comprehensive fuzzing capabilities for DICOM medical imaging systems,
including mutation-based fuzzing, crash analysis, and reporting.
"""

__version__ = "1.0.0"
__author__ = "David Dashti"
__license__ = "MIT"

# Core components
# Phase 5 imports (optional dependencies)
try:
    from dicom_fuzzer.analytics.campaign_analytics import (
        CampaignAnalyzer,
        CoverageCorrelation,
        PerformanceMetrics,
        TrendAnalysis,
    )
    from dicom_fuzzer.analytics.visualization import FuzzingVisualizer
except ImportError:
    # Phase 5 dependencies not installed (matplotlib, plotly, seaborn)
    pass
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.reporter import ReportGenerator

# Phase 5 - Enhanced Reporting & Analytics (optional imports)
try:
    from dicom_fuzzer.core.series_reporter import (
        Series3DReport,
        Series3DReportGenerator,
        SeriesMutationSummary,
    )
except ImportError:
    pass
from dicom_fuzzer.core.statistics import StatisticsCollector
from dicom_fuzzer.core.validator import DicomValidator

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
    # Phase 5 - Enhanced Reporting & Analytics
    "Series3DReport",
    "Series3DReportGenerator",
    "SeriesMutationSummary",
    "CampaignAnalyzer",
    "CoverageCorrelation",
    "TrendAnalysis",
    "PerformanceMetrics",
    "FuzzingVisualizer",
]
