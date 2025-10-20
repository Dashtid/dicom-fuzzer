"""Comprehensive tests for crash_analyzer module.

Tests crash detection, classification, reporting, and deduplication.
"""

from datetime import datetime


from dicom_fuzzer.core.crash_analyzer import (
    CrashAnalyzer,
    CrashReport,
    CrashSeverity,
    CrashType,
)


class TestCrashSeverity:
    """Test CrashSeverity enum."""

    def test_all_severities_defined(self):
        """Test all severity levels are defined."""
        assert CrashSeverity.CRITICAL
        assert CrashSeverity.HIGH
        assert CrashSeverity.MEDIUM
        assert CrashSeverity.LOW
        assert CrashSeverity.UNKNOWN

    def test_severity_values(self):
        """Test severity values are correct."""
        assert CrashSeverity.CRITICAL.value == "critical"
        assert CrashSeverity.HIGH.value == "high"
        assert CrashSeverity.MEDIUM.value == "medium"
        assert CrashSeverity.LOW.value == "low"
        assert CrashSeverity.UNKNOWN.value == "unknown"


class TestCrashType:
    """Test CrashType enum."""

    def test_all_types_defined(self):
        """Test all crash types are defined."""
        assert CrashType.SEGFAULT
        assert CrashType.ASSERTION_FAILURE
        assert CrashType.UNCAUGHT_EXCEPTION
        assert CrashType.TIMEOUT
        assert CrashType.OUT_OF_MEMORY
        assert CrashType.STACK_OVERFLOW
        assert CrashType.UNKNOWN

    def test_type_values(self):
        """Test crash type values."""
        assert CrashType.SEGFAULT.value == "segmentation_fault"
        assert CrashType.ASSERTION_FAILURE.value == "assertion_failure"
        assert CrashType.TIMEOUT.value == "timeout"


class TestCrashReport:
    """Test CrashReport dataclass."""

    def test_initialization(self):
        """Test crash report initialization."""
        report = CrashReport(
            crash_id="crash-001",
            timestamp=datetime.now(),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/path/to/test.dcm",
            stack_trace="Stack trace here",
            exception_message="Segmentation fault",
            crash_hash="abc123",
            additional_info={"signal": "11"},
        )

        assert report.crash_id == "crash-001"
        assert report.crash_type == CrashType.SEGFAULT
        assert report.severity == CrashSeverity.CRITICAL
        assert report.test_case_path == "/path/to/test.dcm"

    def test_report_with_none_values(self):
        """Test crash report with optional None values."""
        report = CrashReport(
            crash_id="crash-002",
            timestamp=datetime.now(),
            crash_type=CrashType.UNKNOWN,
            severity=CrashSeverity.UNKNOWN,
            test_case_path="/test.dcm",
            stack_trace=None,
            exception_message=None,
            crash_hash="def456",
            additional_info={},
        )

        assert report.stack_trace is None
        assert report.exception_message is None
        assert report.additional_info == {}

    def test_report_with_additional_info(self):
        """Test crash report with additional information."""
        additional = {
            "exit_code": "-11",
            "signal": "SIGSEGV",
            "memory_usage": "2GB",
        }

        report = CrashReport(
            crash_id="crash-003",
            timestamp=datetime.now(),
            crash_type=CrashType.OUT_OF_MEMORY,
            severity=CrashSeverity.HIGH,
            test_case_path="/mem.dcm",
            stack_trace="OOM trace",
            exception_message="Out of memory",
            crash_hash="mem123",
            additional_info=additional,
        )

        assert report.additional_info["exit_code"] == "-11"
        assert report.additional_info["signal"] == "SIGSEGV"
        assert len(report.additional_info) == 3


class TestCrashAnalyzerInitialization:
    """Test CrashAnalyzer initialization."""

    def test_default_initialization(self):
        """Test analyzer with default parameters."""
        analyzer = CrashAnalyzer()

        assert analyzer.crash_dir is not None
        assert analyzer.crashes == []

    def test_custom_crash_directory(self, tmp_path):
        """Test analyzer with custom crash directory."""
        crash_dir = tmp_path / "crashes"
        CrashAnalyzer(crash_dir=str(crash_dir))

        assert crash_dir.exists()

    def test_crash_directory_creation(self, tmp_path):
        """Test crash directory is created."""
        crash_dir = tmp_path / "custom_crashes"
        CrashAnalyzer(crash_dir=str(crash_dir))

        assert crash_dir.exists()
        assert crash_dir.is_dir()


class TestCrashDetection:
    """Test crash detection logic."""

    def test_detect_exception_crash(self):
        """Test detecting exception-based crash."""
        analyzer = CrashAnalyzer()

        try:
            raise ValueError("Test crash")
        except ValueError as e:
            crash_type = analyzer._classify_exception(e)

            assert crash_type == CrashType.UNCAUGHT_EXCEPTION

    def test_classify_timeout(self):
        """Test classifying timeout crashes."""
        analyzer = CrashAnalyzer()

        try:
            raise TimeoutError("Test timeout")
        except TimeoutError as e:
            crash_type = analyzer._classify_exception(e)

            assert crash_type == CrashType.TIMEOUT

    def test_classify_segfault(self):
        """Test classifying segmentation faults."""
        analyzer = CrashAnalyzer()

        # Segfaults can't be directly raised in Python, so test severity classification instead
        severity = analyzer._determine_severity(CrashType.SEGFAULT, Exception())

        assert severity == CrashSeverity.CRITICAL


class TestSeverityClassification:
    """Test severity classification logic."""

    def test_segfault_is_critical(self):
        """Test segfaults are classified as critical."""
        analyzer = CrashAnalyzer()

        severity = analyzer._determine_severity(CrashType.SEGFAULT, Exception())

        assert severity == CrashSeverity.CRITICAL

    def test_timeout_is_high(self):
        """Test timeouts are classified as high severity."""
        analyzer = CrashAnalyzer()

        severity = analyzer._determine_severity(CrashType.TIMEOUT, Exception())

        assert severity == CrashSeverity.HIGH

    def test_unknown_crash_severity(self):
        """Test unknown crashes have medium severity by default."""
        analyzer = CrashAnalyzer()

        severity = analyzer._determine_severity(CrashType.UNKNOWN, Exception())

        assert severity == CrashSeverity.MEDIUM


class TestCrashReporting:
    """Test crash report generation."""

    def test_generate_crash_id(self):
        """Test crash ID generation via analyze_exception."""
        analyzer = CrashAnalyzer()

        try:
            raise ValueError("Test exception")
        except ValueError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert isinstance(report.crash_id, str)
        assert len(report.crash_id) > 0

    def test_unique_crash_ids(self):
        """Test crash IDs are unique."""
        analyzer = CrashAnalyzer()

        try:
            raise ValueError("Test exception 1")
        except ValueError as e:
            report1 = analyzer.analyze_exception(e, "/test1.dcm")

        try:
            raise ValueError("Test exception 2")
        except ValueError as e:
            report2 = analyzer.analyze_exception(e, "/test2.dcm")

        assert report1.crash_id != report2.crash_id

    def test_generate_crash_hash(self):
        """Test crash hash generation for deduplication."""
        analyzer = CrashAnalyzer()

        hash1 = analyzer._generate_crash_hash("stack trace 1", "error message 1")
        hash2 = analyzer._generate_crash_hash("stack trace 2", "error message 2")

        assert isinstance(hash1, str)
        assert isinstance(hash2, str)
        assert hash1 != hash2

    def test_same_crash_same_hash(self):
        """Test identical crashes generate same hash."""
        analyzer = CrashAnalyzer()

        hash1 = analyzer._generate_crash_hash("trace", "message")
        hash2 = analyzer._generate_crash_hash("trace", "message")

        assert hash1 == hash2


class TestCrashStorage:
    """Test crash storage and retrieval."""

    def test_store_crash_report(self, tmp_path):
        """Test storing crash report via record_crash."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = analyzer.record_crash(e, "/test.dcm")

        assert len(analyzer.crashes) == 1
        assert report is not None

    def test_get_crash_count(self, tmp_path):
        """Test getting crash count."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add multiple crashes using record_crash
        for i in range(5):
            try:
                raise ValueError(f"Test error {i}")
            except ValueError as e:
                analyzer.record_crash(e, f"/test{i}.dcm")

        assert len(analyzer.crashes) == 5


class TestIntegrationScenarios:
    """Test integration scenarios."""

    def test_complete_crash_analysis_workflow(self, tmp_path):
        """Test complete crash analysis workflow."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Simulate crash via exception
        try:
            raise MemoryError("Out of memory")
        except MemoryError as e:
            report = analyzer.record_crash(e, "/test.dcm")

        # Verify workflow
        assert len(analyzer.crashes) == 1
        assert report is not None
        assert report.crash_type == CrashType.OUT_OF_MEMORY
        assert report.severity == CrashSeverity.HIGH

    def test_multiple_crashes_different_types(self, tmp_path):
        """Test analyzing multiple different crash types."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Simulate different crash types
        exceptions = [
            MemoryError("OOM"),
            RecursionError("Stack overflow"),
            TimeoutError("Timeout"),
        ]

        for exc in exceptions:
            try:
                raise exc
            except Exception as e:
                analyzer.record_crash(e, "/test.dcm")

        assert len(analyzer.crashes) == 3
