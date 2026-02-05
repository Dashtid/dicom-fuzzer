"""DICOM Fuzzer - A professional-grade DICOM fuzzing framework.

This package provides comprehensive fuzzing capabilities for DICOM medical imaging systems,
including mutation-based fuzzing, crash analysis, and reporting.
"""

__version__ = "1.7.2"
__author__ = "David Dashti"
__license__ = "MIT"

# Core components
# Phase 5 imports (optional dependencies)
try:
    from dicom_fuzzer.core.analytics.campaign_analytics import (
        CampaignAnalyzer,
        CoverageCorrelation,
        PerformanceMetrics,
        TrendAnalysis,
    )
    from dicom_fuzzer.core.analytics.visualization import FuzzingVisualizer
except ImportError as _import_err:
    # Phase 5 dependencies not installed (matplotlib, plotly, seaborn)
    CampaignAnalyzer = None  # type: ignore[misc,assignment]
    CoverageCorrelation = None  # type: ignore[misc,assignment]
    PerformanceMetrics = None  # type: ignore[misc,assignment]
    TrendAnalysis = None  # type: ignore[misc,assignment]
    FuzzingVisualizer = None  # type: ignore[misc,assignment]
    del _import_err  # Avoid unused variable warning
from dicom_fuzzer.core.crash import CrashAnalyzer
from dicom_fuzzer.core.dicom.parser import DicomParser
from dicom_fuzzer.core.engine.generator import DICOMGenerator
from dicom_fuzzer.core.mutation.mutator import DicomMutator
from dicom_fuzzer.core.reporting.reporter import ReportGenerator
from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

# Phase 5 - Enhanced Reporting & Analytics (optional imports)
try:
    from dicom_fuzzer.core.reporting.series_reporter import (
        Series3DReport,
        Series3DReportGenerator,
        SeriesMutationSummary,
    )
except ImportError as _import_err:
    Series3DReport = None  # type: ignore[misc,assignment]
    Series3DReportGenerator = None  # type: ignore[misc,assignment]
    SeriesMutationSummary = None  # type: ignore[misc,assignment]
    del _import_err  # Avoid unused variable warning
from dicom_fuzzer.core.dicom.validator import DicomValidator
from dicom_fuzzer.core.reporting.statistics import StatisticsCollector

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
