"""Tests for crash_analyzer module using real exceptions.

Targets uncovered code paths to increase coverage.
"""

from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.constants import Severity
from dicom_fuzzer.core.crash.crash_analyzer import (
    CrashAnalyzer,
    CrashReport,
    CrashType,
)


class TestCrashAnalyzerInit:
    """Test CrashAnalyzer initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        analyzer = CrashAnalyzer()

        assert analyzer.crash_dir == Path("./artifacts/crashes")
        assert analyzer.crashes == []
        assert isinstance(analyzer.crash_hashes, set)
        assert len(analyzer.crash_hashes) == 0

    def test_custom_crash_directory(self, tmp_path):
        """Test custom crash directory."""
        custom_dir = tmp_path / "custom_crashes"
        analyzer = CrashAnalyzer(crash_dir=str(custom_dir))

        assert analyzer.crash_dir == custom_dir
        assert custom_dir.exists()


class TestAnalyzeException:
    """Test exception analysis."""

    def test_analyze_value_error(self):
        """Test analyzing ValueError."""
        analyzer = CrashAnalyzer()

        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.crash_type == CrashType.UNCAUGHT_EXCEPTION
        assert report.exception_message == "Test error"
        assert report.additional_info["exception_type"] == "ValueError"
        assert report.stack_trace is not None

    def test_analyze_memory_error(self):
        """Test analyzing MemoryError."""
        analyzer = CrashAnalyzer()

        try:
            raise MemoryError("Out of memory")
        except MemoryError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.crash_type == CrashType.OUT_OF_MEMORY
        assert report.severity == Severity.HIGH

    def test_analyze_recursion_error(self):
        """Test analyzing RecursionError."""
        analyzer = CrashAnalyzer()

        try:
            raise RecursionError("Stack overflow")
        except RecursionError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.crash_type == CrashType.STACK_OVERFLOW
        assert report.severity == Severity.HIGH

    def test_analyze_assertion_error(self):
        """Test analyzing AssertionError."""
        analyzer = CrashAnalyzer()

        try:
            raise AssertionError("Assertion failed")
        except AssertionError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.crash_type == CrashType.ASSERTION_FAILURE
        assert report.severity == Severity.MEDIUM

    def test_analyze_timeout_error(self):
        """Test analyzing TimeoutError."""
        analyzer = CrashAnalyzer()

        try:
            raise TimeoutError("Operation timed out")
        except TimeoutError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.crash_type == CrashType.TIMEOUT
        assert report.severity == Severity.HIGH


class TestCrashHashGeneration:
    """Test crash hash generation."""

    def test_hash_generation(self):
        """Test crash hash is generated."""
        analyzer = CrashAnalyzer()

        hash1 = analyzer._generate_crash_hash("stack trace 1", "error msg 1")
        hash2 = analyzer._generate_crash_hash("stack trace 2", "error msg 2")

        assert hash1 != hash2
        assert len(hash1) == 64  # SHA256 hex digest length

    def test_identical_crashes_same_hash(self):
        """Test identical crashes produce same hash."""
        analyzer = CrashAnalyzer()

        hash1 = analyzer._generate_crash_hash("same trace", "same message")
        hash2 = analyzer._generate_crash_hash("same trace", "same message")

        assert hash1 == hash2

    def test_hash_is_deterministic(self):
        """Test hash generation is deterministic."""
        analyzer = CrashAnalyzer()

        # Generate hash multiple times
        hashes = [analyzer._generate_crash_hash("trace", "msg") for _ in range(5)]

        # All should be identical
        assert len(set(hashes)) == 1


class TestUniqueCrashDetection:
    """Test unique crash detection."""

    def test_first_crash_is_unique(self):
        """Test first crash is always unique."""
        analyzer = CrashAnalyzer()

        is_unique = analyzer.is_unique_crash("hash123")

        assert is_unique is True
        assert "hash123" in analyzer.crash_hashes

    def test_duplicate_crash_detected(self):
        """Test duplicate crash is detected."""
        analyzer = CrashAnalyzer()

        # First occurrence
        is_unique1 = analyzer.is_unique_crash("hash456")
        # Second occurrence
        is_unique2 = analyzer.is_unique_crash("hash456")

        assert is_unique1 is True
        assert is_unique2 is False

    def test_multiple_unique_crashes(self):
        """Test multiple unique crashes are tracked."""
        analyzer = CrashAnalyzer()

        unique1 = analyzer.is_unique_crash("hash1")
        unique2 = analyzer.is_unique_crash("hash2")
        unique3 = analyzer.is_unique_crash("hash3")

        assert unique1 and unique2 and unique3
        assert len(analyzer.crash_hashes) == 3


class TestSaveCrashReport:
    """Test crash report saving."""

    def test_save_report(self, tmp_path):
        """Test saving crash report to disk."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        report = CrashReport(
            crash_id="test_crash_001",
            timestamp=datetime.now(),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=Severity.MEDIUM,
            test_case_path="/test.dcm",
            stack_trace="Stack trace here",
            exception_message="Error message",
            crash_hash="abc123",
            additional_info={"key": "value"},
        )

        report_path = analyzer.save_crash_report(report)

        assert report_path.exists()
        assert report_path.name == "test_crash_001.txt"

    def test_report_content(self, tmp_path):
        """Test crash report file content."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        report = CrashReport(
            crash_id="test_002",
            timestamp=datetime.now(),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=Severity.CRITICAL,
            test_case_path="/seg.dcm",
            stack_trace="Error in processing",
            exception_message="Processing error",
            crash_hash="def456",
            additional_info={},
        )

        report_path = analyzer.save_crash_report(report)

        # Read and verify content
        content = report_path.read_text(encoding="utf-8")
        assert "test_002" in content
        assert "CRITICAL" in content or "critical" in content
        assert "Processing error" in content


class TestRecordCrash:
    """Test crash recording."""

    def test_record_unique_crash(self, tmp_path):
        """Test recording a unique crash."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Unique error")
        except ValueError as e:
            report = analyzer.record_crash(e, "/test.dcm")

        assert report is not None
        assert len(analyzer.crashes) == 1

    def test_record_duplicate_crash(self, tmp_path):
        """Test recording duplicate crash returns None."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Create a single exception to record twice
        # This simulates finding the same crash from different test cases
        exception = None
        try:
            raise ValueError("Same error")
        except ValueError as e:
            exception = e

        # First crash - record the exception
        report1 = analyzer.record_crash(exception, "/test1.dcm")

        # Second crash - same exception (duplicate)
        report2 = analyzer.record_crash(exception, "/test2.dcm")

        assert report1 is not None
        assert report2 is None  # Duplicate - same crash hash
        assert len(analyzer.crashes) == 1  # Only unique crashes stored

    def test_multiple_unique_crashes_recorded(self, tmp_path):
        """Test multiple unique crashes are all recorded."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Different exception types
        exceptions = [
            ValueError("Error 1"),
            TypeError("Error 2"),
            RuntimeError("Error 3"),
        ]

        for exc in exceptions:
            try:
                raise exc
            except Exception as e:
                analyzer.record_crash(e, "/test.dcm")

        assert len(analyzer.crashes) == 3


class TestCrashSummary:
    """Test crash summary generation."""

    def test_get_crash_summary_empty(self):
        """Test summary with no crashes."""
        analyzer = CrashAnalyzer()

        summary = analyzer.get_crash_summary()

        assert summary["total_crashes"] == 0
        assert summary["unique_crashes"] == 0
        assert summary["critical"] == 0

    def test_get_crash_summary_with_crashes(self, tmp_path):
        """Test summary with crashes."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add different severity crashes
        try:
            raise MemoryError("OOM")
        except MemoryError as e:
            analyzer.record_crash(e, "/test1.dcm")

        try:
            raise ValueError("Error")
        except ValueError as e:
            analyzer.record_crash(e, "/test2.dcm")

        summary = analyzer.get_crash_summary()

        assert summary["total_crashes"] == 2
        assert summary["unique_crashes"] == 2
        assert summary["high"] >= 1  # MemoryError is HIGH

    def test_summary_severity_counts(self, tmp_path):
        """Test severity counts in summary."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add crashes of different severities
        try:
            raise AssertionError("Assert")  # MEDIUM
        except AssertionError as e:
            analyzer.record_crash(e, "/test1.dcm")

        try:
            raise MemoryError("OOM")  # HIGH
        except MemoryError as e:
            analyzer.record_crash(e, "/test2.dcm")

        summary = analyzer.get_crash_summary()

        assert summary["medium"] >= 1
        assert summary["high"] >= 1


class TestGenerateReport:
    """Test report generation."""

    def test_generate_empty_report(self):
        """Test generating report with no crashes."""
        analyzer = CrashAnalyzer()

        report = analyzer.generate_report()

        assert "CRASH ANALYSIS SUMMARY" in report
        assert "Total Crashes:   0" in report

    def test_generate_report_with_crashes(self, tmp_path):
        """Test generating report with crashes."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Test")
        except ValueError as e:
            analyzer.record_crash(e, "/test.dcm")

        report = analyzer.generate_report()

        assert "Total Crashes:" in report
        assert "Unique Crashes:" in report
        assert "Severity Breakdown:" in report

    def test_report_shows_recent_crashes(self, tmp_path):
        """Test report shows recent crashes."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add a crash
        try:
            raise TypeError("Type error")
        except TypeError as e:
            analyzer.record_crash(e, "/test.dcm")

        report = analyzer.generate_report()

        assert "Recent Crashes:" in report


class TestSeverityDetermination:
    """Test severity determination logic."""

    def test_buffer_keyword_increases_severity(self):
        """Test buffer-related exceptions are CRITICAL."""
        analyzer = CrashAnalyzer()

        class BufferError(Exception):
            def __str__(self):
                return "buffer overflow detected"

        try:
            raise BufferError()
        except BufferError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.severity == Severity.CRITICAL

    def test_memory_keyword_increases_severity(self):
        """Test memory-related exceptions are CRITICAL."""
        analyzer = CrashAnalyzer()

        class MemoryCorruption(Exception):
            def __str__(self):
                return "memory corruption detected"

        try:
            raise MemoryCorruption()
        except MemoryCorruption as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert report.severity == Severity.CRITICAL


class TestAdditionalInfo:
    """Test additional info tracking."""

    def test_exception_type_in_additional_info(self):
        """Test exception type is recorded in additional info."""
        analyzer = CrashAnalyzer()

        try:
            raise ValueError("Test")
        except ValueError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert "exception_type" in report.additional_info
        assert report.additional_info["exception_type"] == "ValueError"

    def test_exception_module_in_additional_info(self):
        """Test exception module is recorded."""
        analyzer = CrashAnalyzer()

        try:
            raise ValueError("Test")
        except ValueError as e:
            report = analyzer.analyze_exception(e, "/test.dcm")

        assert "exception_module" in report.additional_info
