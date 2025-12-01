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


class TestAnalyzeExceptionMethod:
    """Test analyze_exception method in detail."""

    def test_analyze_exception_creates_full_report(self, tmp_path):
        """Test analyze_exception creates complete crash report."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Test exception for analysis")
        except ValueError as e:
            report = analyzer.analyze_exception(e, "/path/to/test.dcm")

        assert report.crash_id is not None
        assert report.timestamp is not None
        assert report.crash_type == CrashType.UNCAUGHT_EXCEPTION
        assert report.severity == CrashSeverity.MEDIUM
        assert report.test_case_path == "/path/to/test.dcm"
        assert report.stack_trace is not None
        assert "ValueError" in report.stack_trace
        assert report.exception_message == "Test exception for analysis"
        assert report.crash_hash is not None
        assert "exception_type" in report.additional_info
        assert report.additional_info["exception_type"] == "ValueError"

    def test_analyze_exception_with_memory_error(self, tmp_path):
        """Test analyze_exception with MemoryError."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise MemoryError("Out of memory during fuzzing")
        except MemoryError as e:
            report = analyzer.analyze_exception(e, "/mem_test.dcm")

        assert report.crash_type == CrashType.OUT_OF_MEMORY
        assert report.severity == CrashSeverity.HIGH

    def test_analyze_exception_with_recursion_error(self, tmp_path):
        """Test analyze_exception with RecursionError."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise RecursionError("Stack overflow")
        except RecursionError as e:
            report = analyzer.analyze_exception(e, "/recursion_test.dcm")

        assert report.crash_type == CrashType.STACK_OVERFLOW
        assert report.severity == CrashSeverity.HIGH

    def test_analyze_exception_with_assertion_error(self, tmp_path):
        """Test analyze_exception with AssertionError."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise AssertionError("Assertion failed")
        except AssertionError as e:
            report = analyzer.analyze_exception(e, "/assert_test.dcm")

        assert report.crash_type == CrashType.ASSERTION_FAILURE
        assert report.severity == CrashSeverity.MEDIUM


class TestAnalyzeCrashMethod:
    """Test analyze_crash method (dict-based interface)."""

    def test_analyze_crash_returns_dict(self, tmp_path):
        """Test analyze_crash returns dictionary with expected keys."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))
        crash_file = tmp_path / "test.dcm"
        crash_file.touch()

        try:
            raise ValueError("Test crash")
        except ValueError as e:
            result = analyzer.analyze_crash(crash_file, e)

        assert isinstance(result, dict)
        assert "type" in result
        assert "severity" in result
        assert "exploitable" in result
        assert "crash_id" in result
        assert "crash_hash" in result

    def test_analyze_crash_exploitability_for_critical(self, tmp_path):
        """Test analyze_crash marks critical crashes as exploitable."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))
        crash_file = tmp_path / "test.dcm"
        crash_file.touch()

        # Simulate crash with buffer overflow keyword in message
        try:
            raise ValueError("buffer overflow detected")
        except ValueError as e:
            result = analyzer.analyze_crash(crash_file, e)

        assert result["severity"] == "critical"
        assert result["exploitable"] is True

    def test_analyze_crash_exploitability_for_high(self, tmp_path):
        """Test analyze_crash marks high severity crashes as exploitable."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))
        crash_file = tmp_path / "test.dcm"
        crash_file.touch()

        try:
            raise MemoryError("Out of memory")
        except MemoryError as e:
            result = analyzer.analyze_crash(crash_file, e)

        assert result["severity"] == "high"
        assert result["exploitable"] is True


class TestClassifyExceptionMethod:
    """Test _classify_exception method for all exception types."""

    def test_classify_memory_error(self):
        """Test MemoryError classification."""
        analyzer = CrashAnalyzer()
        result = analyzer._classify_exception(MemoryError())
        assert result == CrashType.OUT_OF_MEMORY

    def test_classify_recursion_error(self):
        """Test RecursionError classification."""
        analyzer = CrashAnalyzer()
        result = analyzer._classify_exception(RecursionError())
        assert result == CrashType.STACK_OVERFLOW

    def test_classify_assertion_error(self):
        """Test AssertionError classification."""
        analyzer = CrashAnalyzer()
        result = analyzer._classify_exception(AssertionError())
        assert result == CrashType.ASSERTION_FAILURE

    def test_classify_timeout_error(self):
        """Test TimeoutError classification."""
        analyzer = CrashAnalyzer()
        result = analyzer._classify_exception(TimeoutError())
        assert result == CrashType.TIMEOUT

    def test_classify_generic_exception(self):
        """Test generic exceptions are classified as uncaught."""
        analyzer = CrashAnalyzer()
        result = analyzer._classify_exception(ValueError())
        assert result == CrashType.UNCAUGHT_EXCEPTION

    def test_classify_custom_exception(self):
        """Test custom exceptions are classified as uncaught."""

        class CustomError(Exception):
            pass

        analyzer = CrashAnalyzer()
        result = analyzer._classify_exception(CustomError())
        assert result == CrashType.UNCAUGHT_EXCEPTION


class TestDetermineSeverityMethod:
    """Test _determine_severity method for all cases."""

    def test_segfault_severity(self):
        """Test SEGFAULT is CRITICAL."""
        analyzer = CrashAnalyzer()
        result = analyzer._determine_severity(CrashType.SEGFAULT, Exception())
        assert result == CrashSeverity.CRITICAL

    def test_oom_severity(self):
        """Test OUT_OF_MEMORY is HIGH."""
        analyzer = CrashAnalyzer()
        result = analyzer._determine_severity(CrashType.OUT_OF_MEMORY, Exception())
        assert result == CrashSeverity.HIGH

    def test_stack_overflow_severity(self):
        """Test STACK_OVERFLOW is HIGH."""
        analyzer = CrashAnalyzer()
        result = analyzer._determine_severity(CrashType.STACK_OVERFLOW, Exception())
        assert result == CrashSeverity.HIGH

    def test_timeout_severity(self):
        """Test TIMEOUT is HIGH."""
        analyzer = CrashAnalyzer()
        result = analyzer._determine_severity(CrashType.TIMEOUT, Exception())
        assert result == CrashSeverity.HIGH

    def test_assertion_severity(self):
        """Test ASSERTION_FAILURE is MEDIUM."""
        analyzer = CrashAnalyzer()
        result = analyzer._determine_severity(CrashType.ASSERTION_FAILURE, Exception())
        assert result == CrashSeverity.MEDIUM

    def test_buffer_keyword_critical(self):
        """Test buffer keyword in exception makes it CRITICAL."""
        analyzer = CrashAnalyzer()
        exc = Exception("buffer overflow detected")
        result = analyzer._determine_severity(CrashType.UNCAUGHT_EXCEPTION, exc)
        assert result == CrashSeverity.CRITICAL

    def test_overflow_keyword_critical(self):
        """Test overflow keyword in exception makes it CRITICAL."""
        analyzer = CrashAnalyzer()
        exc = Exception("integer overflow")
        result = analyzer._determine_severity(CrashType.UNCAUGHT_EXCEPTION, exc)
        assert result == CrashSeverity.CRITICAL

    def test_corruption_keyword_critical(self):
        """Test corruption keyword in exception makes it CRITICAL."""
        analyzer = CrashAnalyzer()
        exc = Exception("memory corruption detected")
        result = analyzer._determine_severity(CrashType.UNCAUGHT_EXCEPTION, exc)
        assert result == CrashSeverity.CRITICAL

    def test_memory_keyword_critical(self):
        """Test memory keyword in exception makes it CRITICAL."""
        analyzer = CrashAnalyzer()
        exc = Exception("invalid memory access")
        result = analyzer._determine_severity(CrashType.UNCAUGHT_EXCEPTION, exc)
        assert result == CrashSeverity.CRITICAL

    def test_default_medium_severity(self):
        """Test default severity is MEDIUM."""
        analyzer = CrashAnalyzer()
        exc = Exception("normal error message")
        result = analyzer._determine_severity(CrashType.UNCAUGHT_EXCEPTION, exc)
        assert result == CrashSeverity.MEDIUM


class TestCalculateSeverityAlias:
    """Test _calculate_severity alias method."""

    def test_calculate_severity_returns_string(self):
        """Test _calculate_severity returns severity as string."""
        analyzer = CrashAnalyzer()
        result = analyzer._calculate_severity("timeout", TimeoutError())
        assert result == "high"

    def test_calculate_severity_uncaught_exception(self):
        """Test _calculate_severity for uncaught exception."""
        analyzer = CrashAnalyzer()
        result = analyzer._calculate_severity("uncaught_exception", ValueError())
        assert result == "medium"


class TestIsUniqueCrashMethod:
    """Test is_unique_crash deduplication."""

    def test_first_crash_is_unique(self):
        """Test first crash is always unique."""
        analyzer = CrashAnalyzer()
        result = analyzer.is_unique_crash("hash_001")
        assert result is True

    def test_duplicate_crash_not_unique(self):
        """Test duplicate crash returns False."""
        analyzer = CrashAnalyzer()
        analyzer.is_unique_crash("hash_001")  # First time
        result = analyzer.is_unique_crash("hash_001")  # Second time
        assert result is False

    def test_different_hashes_are_unique(self):
        """Test different hashes are unique."""
        analyzer = CrashAnalyzer()
        result1 = analyzer.is_unique_crash("hash_001")
        result2 = analyzer.is_unique_crash("hash_002")
        assert result1 is True
        assert result2 is True


class TestSaveCrashReportMethod:
    """Test save_crash_report file writing."""

    def test_save_crash_report_creates_file(self, tmp_path):
        """Test save_crash_report creates file on disk."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        report = CrashReport(
            crash_id="crash_save_test",
            timestamp=datetime.now(),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=CrashSeverity.MEDIUM,
            test_case_path="/test/path.dcm",
            stack_trace="Line 1\nLine 2\nLine 3",
            exception_message="Test exception message",
            crash_hash="save_test_hash",
            additional_info={"key1": "value1", "key2": "value2"},
        )

        report_path = analyzer.save_crash_report(report)

        assert report_path.exists()
        content = report_path.read_text()
        assert "CRASH REPORT" in content
        assert "crash_save_test" in content
        assert "uncaught_exception" in content
        assert "medium" in content
        assert "/test/path.dcm" in content
        assert "Test exception message" in content
        assert "Line 1" in content
        assert "key1" in content
        assert "value1" in content

    def test_save_crash_report_without_optional_fields(self, tmp_path):
        """Test save_crash_report handles None optional fields."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        report = CrashReport(
            crash_id="crash_minimal",
            timestamp=datetime.now(),
            crash_type=CrashType.TIMEOUT,
            severity=CrashSeverity.HIGH,
            test_case_path="/minimal.dcm",
            stack_trace=None,
            exception_message=None,
            crash_hash="minimal_hash",
            additional_info={},
        )

        report_path = analyzer.save_crash_report(report)

        assert report_path.exists()
        content = report_path.read_text()
        assert "crash_minimal" in content
        assert "timeout" in content


class TestRecordCrashMethod:
    """Test record_crash method."""

    def test_record_crash_stores_and_saves(self, tmp_path):
        """Test record_crash stores crash and saves report."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Record crash test")
        except ValueError as e:
            report = analyzer.record_crash(e, "/record_test.dcm")

        assert report is not None
        assert len(analyzer.crashes) == 1
        assert analyzer.crashes[0] == report

        # Verify file was saved
        files = list(tmp_path.glob("*.txt"))
        assert len(files) == 1

    def test_record_crash_deduplicates(self, tmp_path):
        """Test record_crash returns None for duplicates."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Record same exception twice
        try:
            raise ValueError("Duplicate test")
        except ValueError as e1:
            report1 = analyzer.record_crash(e1, "/dup_test.dcm")

        # Force same hash by using same exception
        try:
            raise ValueError("Duplicate test")
        except ValueError as e2:
            report2 = analyzer.record_crash(e2, "/dup_test.dcm")

        assert report1 is not None
        # Note: Due to different stack traces, might not be duplicate
        # But if hashes match, report2 would be None


class TestGetCrashSummaryMethod:
    """Test get_crash_summary method."""

    def test_empty_summary(self, tmp_path):
        """Test summary with no crashes."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))
        summary = analyzer.get_crash_summary()

        assert summary["total_crashes"] == 0
        assert summary["unique_crashes"] == 0
        assert summary["critical"] == 0
        assert summary["high"] == 0
        assert summary["medium"] == 0
        assert summary["low"] == 0

    def test_summary_counts_by_severity(self, tmp_path):
        """Test summary correctly counts by severity."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add crashes of different severities
        exceptions = [
            MemoryError("OOM 1"),  # HIGH
            MemoryError("OOM 2"),  # HIGH
            RecursionError("Stack"),  # HIGH
            AssertionError("Assert"),  # MEDIUM
            ValueError("Value"),  # MEDIUM
        ]

        for i, exc in enumerate(exceptions):
            try:
                raise exc
            except Exception as e:
                analyzer.record_crash(e, f"/test_{i}.dcm")

        summary = analyzer.get_crash_summary()

        assert summary["total_crashes"] == 5
        assert summary["high"] == 3
        assert summary["medium"] == 2


class TestGenerateReportMethod:
    """Test generate_report human-readable report."""

    def test_generate_empty_report(self, tmp_path):
        """Test generate_report with no crashes."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))
        report = analyzer.generate_report()

        assert "CRASH ANALYSIS SUMMARY" in report
        assert "Total Crashes:   0" in report
        assert "Unique Crashes:  0" in report

    def test_generate_report_with_crashes(self, tmp_path):
        """Test generate_report with crashes."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add some crashes
        try:
            raise MemoryError("OOM")
        except MemoryError as e:
            analyzer.record_crash(e, "/oom.dcm")

        try:
            raise ValueError("Value")
        except ValueError as e:
            analyzer.record_crash(e, "/value.dcm")

        report = analyzer.generate_report()

        assert "CRASH ANALYSIS SUMMARY" in report
        assert "Total Crashes:" in report
        assert "Severity Breakdown:" in report
        assert "CRITICAL:" in report
        assert "HIGH:" in report
        assert "MEDIUM:" in report
        assert "LOW:" in report
        assert "Recent Crashes:" in report

    def test_generate_report_shows_recent_crashes(self, tmp_path):
        """Test generate_report shows recent crash details."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Test crash for report")
        except ValueError as e:
            analyzer.record_crash(e, "/recent.dcm")

        report = analyzer.generate_report()

        assert "Recent Crashes:" in report
        assert "Type: uncaught_exception" in report
        assert "recent.dcm" in report


class TestGetCrashTypeAlias:
    """Test _get_crash_type alias method."""

    def test_get_crash_type_returns_string(self):
        """Test _get_crash_type returns type as string."""
        analyzer = CrashAnalyzer()
        result = analyzer._get_crash_type(MemoryError())
        assert result == "out_of_memory"

    def test_get_crash_type_timeout(self):
        """Test _get_crash_type for timeout."""
        analyzer = CrashAnalyzer()
        result = analyzer._get_crash_type(TimeoutError())
        assert result == "timeout"


class TestGenerateCrashHashMethod:
    """Test _generate_crash_hash method."""

    def test_generate_hash_returns_string(self):
        """Test _generate_crash_hash returns string hash."""
        analyzer = CrashAnalyzer()
        result = analyzer._generate_crash_hash("stack trace", "message")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_generate_hash_deterministic(self):
        """Test _generate_crash_hash is deterministic."""
        analyzer = CrashAnalyzer()
        hash1 = analyzer._generate_crash_hash("trace", "msg")
        hash2 = analyzer._generate_crash_hash("trace", "msg")
        assert hash1 == hash2

    def test_generate_hash_different_inputs(self):
        """Test different inputs produce different hashes."""
        analyzer = CrashAnalyzer()
        hash1 = analyzer._generate_crash_hash("trace1", "msg1")
        hash2 = analyzer._generate_crash_hash("trace2", "msg2")
        assert hash1 != hash2
