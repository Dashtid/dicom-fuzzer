"""
Comprehensive tests for crash analysis framework.

Tests cover:
- Crash detection and classification
- Severity determination
- Crash deduplication
- Report generation and persistence
- Integration with fuzzing workflows
"""

import os
import tempfile
from pathlib import Path

import pytest

from core.crash_analyzer import CrashAnalyzer, CrashReport, CrashSeverity, CrashType


class TestCrashClassification:
    """Test crash type classification."""

    def test_memory_error_classification(self):
        """Test MemoryError is classified as OUT_OF_MEMORY."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise MemoryError("Out of memory")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            assert crash_type == CrashType.OUT_OF_MEMORY

    def test_recursion_error_classification(self):
        """Test RecursionError is classified as STACK_OVERFLOW."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise RecursionError("Maximum recursion depth exceeded")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            assert crash_type == CrashType.STACK_OVERFLOW

    def test_assertion_error_classification(self):
        """Test AssertionError is classified as ASSERTION_FAILURE."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise AssertionError("Assertion failed")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            assert crash_type == CrashType.ASSERTION_FAILURE

    def test_timeout_error_classification(self):
        """Test TimeoutError is classified as TIMEOUT."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise TimeoutError("Operation timed out")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            assert crash_type == CrashType.TIMEOUT

    def test_generic_exception_classification(self):
        """Test generic exceptions are classified as UNCAUGHT_EXCEPTION."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise ValueError("Invalid value")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            assert crash_type == CrashType.UNCAUGHT_EXCEPTION


class TestSeverityDetermination:
    """Test crash severity determination."""

    def test_memory_error_severity(self):
        """Test MemoryError has HIGH severity."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise MemoryError("Out of memory")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            severity = analyzer._determine_severity(crash_type, e)
            assert severity == CrashSeverity.HIGH

    def test_stack_overflow_severity(self):
        """Test RecursionError has HIGH severity."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise RecursionError("Stack overflow")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            severity = analyzer._determine_severity(crash_type, e)
            assert severity == CrashSeverity.HIGH

    def test_assertion_failure_severity(self):
        """Test AssertionError has MEDIUM severity."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise AssertionError("Assertion failed")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            severity = analyzer._determine_severity(crash_type, e)
            assert severity == CrashSeverity.MEDIUM

    def test_memory_corruption_keywords(self):
        """Test exceptions with memory corruption keywords are CRITICAL."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise ValueError("Buffer overflow detected")
        except Exception as e:
            crash_type = analyzer._classify_exception(e)
            severity = analyzer._determine_severity(crash_type, e)
            assert severity == CrashSeverity.CRITICAL

    def test_segfault_severity(self):
        """Test SEGFAULT crash type is CRITICAL (line 219)."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        # Directly test _determine_severity with SEGFAULT type
        severity = analyzer._determine_severity(CrashType.SEGFAULT, ValueError("test"))
        assert severity == CrashSeverity.CRITICAL


class TestCrashDeduplication:
    """Test crash deduplication via hashing."""

    def test_crash_hash_generation(self):
        """Test crash hash is generated correctly."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        stack_trace = "Traceback (most recent call last):\n  File test.py"
        exception_msg = "ValueError: Invalid value"

        hash1 = analyzer._generate_crash_hash(stack_trace, exception_msg)
        hash2 = analyzer._generate_crash_hash(stack_trace, exception_msg)

        # Same input should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 hex chars

    def test_different_crashes_different_hashes(self):
        """Test different crashes produce different hashes."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        hash1 = analyzer._generate_crash_hash("trace1", "msg1")
        hash2 = analyzer._generate_crash_hash("trace2", "msg2")

        assert hash1 != hash2

    def test_is_unique_crash(self):
        """Test unique crash detection."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        hash1 = "abc123"
        hash2 = "def456"

        # First time should be unique
        assert analyzer.is_unique_crash(hash1) is True

        # Second time same hash should not be unique
        assert analyzer.is_unique_crash(hash1) is False

        # Different hash should be unique
        assert analyzer.is_unique_crash(hash2) is True


class TestCrashReportGeneration:
    """Test crash report generation and structure."""

    def test_analyze_exception_creates_report(self):
        """Test analyzing exception creates complete report."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise ValueError("Test error")
        except Exception as e:
            report = analyzer.analyze_exception(e, "test_file.dcm")

            assert isinstance(report, CrashReport)
            assert report.crash_id.startswith("crash_")
            assert report.crash_type == CrashType.UNCAUGHT_EXCEPTION
            assert report.test_case_path == "test_file.dcm"
            assert "Test error" in report.exception_message
            assert report.stack_trace is not None
            assert len(report.crash_hash) == 64

    def test_report_contains_exception_details(self):
        """Test report contains exception type details."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise MemoryError("Out of memory")
        except Exception as e:
            report = analyzer.analyze_exception(e, "test.dcm")

            assert report.additional_info["exception_type"] == "MemoryError"
            assert report.additional_info["exception_module"] == "builtins"

    def test_report_timestamp(self):
        """Test report includes timestamp."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        try:
            raise ValueError("Error")
        except Exception as e:
            report = analyzer.analyze_exception(e, "test.dcm")

            assert report.timestamp is not None
            # Should be recent (within last minute)
            from datetime import datetime, timedelta

            assert report.timestamp > datetime.now() - timedelta(minutes=1)


class TestCrashReportPersistence:
    """Test crash report saving and persistence."""

    def test_save_crash_report(self):
        """Test saving crash report to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise ValueError("Test error")
            except Exception as e:
                report = analyzer.analyze_exception(e, "test.dcm")
                report_path = analyzer.save_crash_report(report)

                # Check file exists
                assert os.path.exists(report_path)
                assert report_path.suffix == ".txt"

                # Check content
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    assert "CRASH REPORT" in content
                    assert report.crash_id in content
                    assert "Test error" in content

    def test_crash_report_format(self):
        """Test crash report has correct format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise MemoryError("Out of memory")
            except Exception as e:
                report = analyzer.analyze_exception(e, "test.dcm")
                report_path = analyzer.save_crash_report(report)

                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()

                    # Check required sections
                    assert "Timestamp:" in content
                    assert "Crash Type:" in content
                    assert "Severity:" in content
                    assert "Test Case:" in content
                    assert "Crash Hash:" in content
                    assert "Exception Message:" in content
                    assert "Stack Trace:" in content


class TestCrashRecording:
    """Test crash recording workflow."""

    def test_record_crash_unique(self):
        """Test recording unique crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise ValueError("Unique error")
            except Exception as e:
                report = analyzer.record_crash(e, "test.dcm")

                assert report is not None
                assert len(analyzer.crashes) == 1
                assert len(analyzer.crash_hashes) == 1

    def test_record_crash_duplicate(self):
        """Test recording duplicate crash returns None (line 346)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            # Record first crash
            try:
                raise ValueError("Error")
            except Exception as e:
                report1 = analyzer.record_crash(e, "test1.dcm")
                assert report1 is not None

            # Manually add crash hash to ensure duplicate detection
            first_hash = report1.crash_hash
            analyzer.crash_hashes.add(first_hash)

            # Mock is_unique_crash to return False
            original_is_unique = analyzer.is_unique_crash

            def mock_is_unique(crash_hash):
                return False  # Force duplicate

            analyzer.is_unique_crash = mock_is_unique

            # Record same crash again (will be detected as duplicate)
            try:
                raise ValueError("Error")
            except Exception as e:
                report2 = analyzer.record_crash(e, "test2.dcm")
                # Should be None (duplicate)
                assert report2 is None

            # Restore original method
            analyzer.is_unique_crash = original_is_unique

    def test_record_multiple_unique_crashes(self):
        """Test recording multiple unique crashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            # Record different crashes
            exceptions = [
                ValueError("Error 1"),
                TypeError("Error 2"),
                MemoryError("Error 3"),
            ]

            for exc in exceptions:
                try:
                    raise exc
                except Exception as e:
                    analyzer.record_crash(e, "test.dcm")

            # Should have recorded crashes
            assert len(analyzer.crashes) >= 1


class TestCrashSummary:
    """Test crash summary and reporting."""

    def test_get_crash_summary(self):
        """Test getting crash summary statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            # Record crashes of different severities
            try:
                raise MemoryError("OOM")  # HIGH
            except Exception as e:
                analyzer.record_crash(e, "test1.dcm")

            try:
                raise ValueError("Invalid")  # MEDIUM
            except Exception as e:
                analyzer.record_crash(e, "test2.dcm")

            summary = analyzer.get_crash_summary()

            assert "total_crashes" in summary
            assert "unique_crashes" in summary
            assert "critical" in summary
            assert "high" in summary
            assert "medium" in summary
            assert "low" in summary

            assert summary["total_crashes"] >= 1

    def test_generate_report(self):
        """Test generating human-readable crash report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise ValueError("Test error")
            except Exception as e:
                analyzer.record_crash(e, "test.dcm")

            report = analyzer.generate_report()

            assert "CRASH ANALYSIS SUMMARY" in report
            assert "Total Crashes:" in report
            assert "Unique Crashes:" in report
            assert "Severity Breakdown:" in report

    def test_empty_crash_summary(self):
        """Test summary with no crashes."""
        analyzer = CrashAnalyzer(crash_dir=tempfile.mkdtemp())

        summary = analyzer.get_crash_summary()

        assert summary["total_crashes"] == 0
        assert summary["unique_crashes"] == 0
        assert summary["critical"] == 0


class TestIntegration:
    """Integration tests for crash analyzer."""

    def test_crash_analyzer_with_fuzzer(self, sample_dicom_dataset):
        """Test crash analyzer in fuzzing workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            # Simulate fuzzing loop that finds crashes
            try:
                # Simulate a crash during fuzzing
                if sample_dicom_dataset is not None:
                    raise ValueError("Fuzzing triggered crash")
            except Exception as e:
                analyzer.record_crash(e, "fuzzed_file.dcm")

            assert len(analyzer.crashes) >= 1

    def test_crash_directory_creation(self):
        """Test crash directory is created automatically."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crash_dir = Path(tmpdir) / "nested" / "crashes"
            CrashAnalyzer(crash_dir=str(crash_dir))

            assert crash_dir.exists()
            assert crash_dir.is_dir()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
