"""Reporting -- report generation, analytics, and templates."""

from dicom_fuzzer.core.reporting.compliance import ComplianceFormatter
from dicom_fuzzer.core.reporting.enhanced_reporter import EnhancedReportGenerator
from dicom_fuzzer.core.reporting.enrichers import CrashTriageEnricher
from dicom_fuzzer.core.reporting.formatters import HTMLSectionFormatter
from dicom_fuzzer.core.reporting.report_analytics import ReportAnalytics
from dicom_fuzzer.core.reporting.series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)
from dicom_fuzzer.core.reporting.statistics import IterationData, MutationStatistics

__all__ = [
    "ComplianceFormatter",
    "CrashTriageEnricher",
    "EnhancedReportGenerator",
    "HTMLSectionFormatter",
    "IterationData",
    "MutationStatistics",
    "ReportAnalytics",
    "Series3DReport",
    "Series3DReportGenerator",
    "SeriesMutationSummary",
]
