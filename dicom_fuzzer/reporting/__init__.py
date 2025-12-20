"""Reporting modules for DICOM Fuzzer.

Core crash reporting functionality is available in dicom_fuzzer.core:
- crash_analyzer: Crash detection and analysis
- crash_triage: Severity and exploitability classification
- crash_deduplication: Crash clustering
- reporter: Report generation
- enhanced_reporter: Enhanced report generation

HTML report generation is available via CLI:
- dicom-fuzzer generate-report
"""

__all__: list[str] = []
