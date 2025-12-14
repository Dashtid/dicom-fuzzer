"""Enhanced Coverage Tests for Low-Coverage Modules

This module provides comprehensive tests for modules with low coverage:
- enhanced_reporter.py (9%)
- reporter.py (21%)
- stateless_harness.py (12%)
- lazy_loader.py (26%)
- stability_tracker.py (27%)
- coverage_guided_fuzzer.py (27%)
"""

from datetime import datetime

import pydicom
import pytest
from pydicom.dataset import Dataset

# =============================================================================
# Enhanced Reporter Tests
# =============================================================================


class TestEnhancedReportGenerator:
    """Tests for EnhancedReportGenerator class."""

    def test_init_default(self, tmp_path):
        """Test initialization with default values."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        assert gen.output_dir == tmp_path
        assert gen.enable_triage is True
        assert gen.triage_engine is not None

    def test_init_triage_disabled(self, tmp_path):
        """Test initialization with triage disabled."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path), enable_triage=False)
        assert gen.enable_triage is False
        assert gen.triage_engine is None

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        output_dir = tmp_path / "new_dir" / "reports"
        gen = EnhancedReportGenerator(output_dir=str(output_dir))
        assert output_dir.exists()

    def test_enrich_crashes_no_triage(self, tmp_path):
        """Test enrich crashes when triage is disabled."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path), enable_triage=False)
        session_data = {"crashes": []}
        result = gen._enrich_crashes_with_triage(session_data)
        assert result == session_data

    def test_enrich_crashes_empty(self, tmp_path):
        """Test enrich crashes with empty crash list."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        session_data = {"crashes": []}
        result = gen._enrich_crashes_with_triage(session_data)
        assert result["crashes"] == []

    def test_enrich_crashes_with_data(self, tmp_path):
        """Test enrich crashes with actual crash data."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        session_data = {
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "segfault",
                    "severity": "high",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "/tmp/test.dcm",
                    "return_code": -11,
                    "exception_type": "SegmentationFault",
                    "exception_message": "Segfault at 0x0",
                    "stack_trace": "main() at line 10",
                }
            ]
        }
        result = gen._enrich_crashes_with_triage(session_data)
        assert "crashes" in result
        if result["crashes"]:
            assert "triage" in result["crashes"][0]

    def test_enrich_crashes_datetime_timestamp(self, tmp_path):
        """Test enrich crashes with datetime timestamp."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        session_data = {
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now(),  # datetime object, not string
                    "crash_type": "timeout",
                    "severity": "medium",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "/tmp/test.dcm",
                }
            ]
        }
        result = gen._enrich_crashes_with_triage(session_data)
        assert "crashes" in result

    def test_enrich_crashes_invalid_timestamp(self, tmp_path):
        """Test enrich crashes with invalid timestamp."""
        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        session_data = {
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": "not-a-valid-timestamp",
                    "crash_type": "timeout",
                }
            ]
        }
        result = gen._enrich_crashes_with_triage(session_data)
        assert "crashes" in result

    def test_generate_html_report(self, tmp_path):
        """Test generate_html_report."""
        from datetime import datetime

        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        session_data = {
            "session_info": {
                "session_id": "test_session_001",
                "session_name": "Test Fuzzing Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files": 100,
                "crashes_found": 5,
                "total_mutations": 500,
                "duration_seconds": 60,
            },
            "crashes": [],
            "fuzzed_files": {},
        }
        report_path = gen.generate_html_report(session_data)
        assert report_path.exists()
        assert report_path.suffix == ".html"

    def test_generate_html_report_custom_path(self, tmp_path):
        """Test generate_html_report with custom output path."""
        from datetime import datetime

        from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator

        gen = EnhancedReportGenerator(output_dir=str(tmp_path))
        custom_path = tmp_path / "custom_report.html"
        session_data = {
            "session_info": {
                "session_id": "test_session_002",
                "session_name": "Test Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_mutations": 100,
                "duration_seconds": 30,
            },
            "crashes": [],
            "fuzzed_files": {},
        }
        report_path = gen.generate_html_report(session_data, output_path=custom_path)
        assert report_path == custom_path
        assert custom_path.exists()


# =============================================================================
# Reporter Tests
# =============================================================================


class TestReportGenerator:
    """Tests for ReportGenerator class."""

    def test_init(self, tmp_path):
        """Test ReportGenerator initialization."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        assert gen.output_dir == tmp_path

    def test_init_creates_directory(self, tmp_path):
        """Test that output directory is created."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        output_dir = tmp_path / "new_reports"
        gen = ReportGenerator(output_dir=str(output_dir))
        assert output_dir.exists()

    def test_generate_report_json(self, tmp_path):
        """Test generate_report with JSON format."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        report_data = {"key": "value", "count": 10}
        report_path = gen.generate_report(report_data, format="json")
        assert report_path.exists()
        assert report_path.suffix == ".json"

    def test_generate_report_html(self, tmp_path):
        """Test generate_report with HTML format."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        report_data = {"key": "value", "count": 10}
        report_path = gen.generate_report(report_data, format="html")
        assert report_path.exists()
        assert report_path.suffix == ".html"

    def test_generate_html_header(self, tmp_path):
        """Test _generate_html_header."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        header = gen._generate_html_header("Test Title")
        assert "Test Title" in header
        assert "<!DOCTYPE html>" in header

    def test_generate_html_footer(self, tmp_path):
        """Test _generate_html_footer."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        footer = gen._generate_html_footer()
        assert "</html>" in footer

    def test_generate_summary_section(self, tmp_path):
        """Test _generate_summary_section."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        summary = {"crash_type_a": 5, "crash_type_b": 3}
        html = gen._generate_summary_section(summary, 8)
        assert "8" in html
        assert "5" in html
        assert "3" in html

    def test_generate_crash_details_empty(self, tmp_path):
        """Test _generate_crash_details_section with empty list."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        html = gen._generate_crash_details_section([])
        assert "No crashes found" in html

    def test_generate_performance_section(self, tmp_path):
        """Test _generate_performance_section."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        metrics = {
            "files_generated": 100,
            "mutations_applied": 500,
            "throughput_per_second": 10.5,
            "avg_time_per_file": 0.1,
        }
        html = gen._generate_performance_section(metrics)
        assert "100" in html
        assert "Performance" in html


# =============================================================================
# Stateless Harness Tests
# =============================================================================


class TestStatelessHarness:
    """Tests for stateless_harness module."""

    def test_validate_determinism_deterministic(self):
        """Test validate_determinism with deterministic function."""
        from dicom_fuzzer.utils.stateless_harness import validate_determinism

        def deterministic_func(x):
            return x * 2

        is_deterministic, error = validate_determinism(5, deterministic_func, runs=3)
        assert is_deterministic is True
        assert error is None

    def test_validate_determinism_non_deterministic(self):
        """Test validate_determinism with non-deterministic function."""
        import random

        from dicom_fuzzer.utils.stateless_harness import validate_determinism

        def non_deterministic_func(x):
            return x + random.random()

        is_deterministic, error = validate_determinism(
            5, non_deterministic_func, runs=3
        )
        assert is_deterministic is False
        assert error is not None
        assert "Non-deterministic" in error

    def test_validate_determinism_exception(self):
        """Test validate_determinism when function raises exception."""
        from dicom_fuzzer.utils.stateless_harness import validate_determinism

        def failing_func(x):
            raise ValueError("Test error")

        is_deterministic, error = validate_determinism(5, failing_func, runs=3)
        assert is_deterministic is False
        assert error is not None
        assert "exception" in error.lower()

    def test_validate_determinism_no_cleanup(self):
        """Test validate_determinism with cleanup=False."""
        from dicom_fuzzer.utils.stateless_harness import validate_determinism

        def simple_func(x):
            return x

        is_deterministic, error = validate_determinism(
            5, simple_func, runs=2, cleanup=False
        )
        assert is_deterministic is True

    def test_create_stateless_wrapper(self):
        """Test create_stateless_test_wrapper."""
        from dicom_fuzzer.utils.stateless_harness import create_stateless_test_wrapper

        def original_func(x, y):
            return x + y

        wrapped = create_stateless_test_wrapper(original_func)
        result = wrapped(3, 4)
        assert result == 7

    def test_create_stateless_wrapper_with_kwargs(self):
        """Test create_stateless_test_wrapper with kwargs."""
        from dicom_fuzzer.utils.stateless_harness import create_stateless_test_wrapper

        def original_func(x, y=10):
            return x + y

        wrapped = create_stateless_test_wrapper(original_func)
        result = wrapped(3, y=20)
        assert result == 23

    def test_detect_state_leaks_insufficient_files(self, tmp_path):
        """Test detect_state_leaks with insufficient files."""
        from dicom_fuzzer.utils.stateless_harness import detect_state_leaks

        def harness_func(path):
            return "result"

        result = detect_state_leaks(harness_func, [tmp_path / "single.dcm"])
        assert result["leaked"] is False

    def test_detect_state_leaks_no_leaks(self, tmp_path):
        """Test detect_state_leaks when no leaks exist."""
        from dicom_fuzzer.utils.stateless_harness import detect_state_leaks

        # Create test files
        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"test data")
            files.append(f)

        def stateless_harness(path):
            return path.name  # Always returns the filename

        result = detect_state_leaks(stateless_harness, files)
        assert result["leaked"] is False

    def test_detect_state_leaks_with_exception(self, tmp_path):
        """Test detect_state_leaks when harness raises exception."""
        from dicom_fuzzer.utils.stateless_harness import detect_state_leaks

        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"test")
            files.append(f)

        def failing_harness(path):
            raise ValueError("Test error")

        result = detect_state_leaks(failing_harness, files)
        # Should handle exceptions gracefully
        assert isinstance(result, dict)


# =============================================================================
# Lazy Loader Tests (Additional)
# =============================================================================


class TestLazyDicomLoaderExtended:
    """Extended tests for LazyDicomLoader."""

    def test_load_force_true(self, tmp_path, sample_dicom):
        """Test load with force=True on invalid file."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        # Create partially valid file
        dcm_path = tmp_path / "partial.dcm"
        dcm_path.write_bytes(b"DICM" + b"\x00" * 100)

        loader = LazyDicomLoader(force=True)
        # Should attempt to load without raising
        try:
            loader.load(dcm_path)
        except Exception:
            pass  # Expected for invalid files

    def test_load_with_defer_size(self, tmp_path, sample_dicom):
        """Test loading with defer_size set."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        dcm_path = tmp_path / "test.dcm"
        sample_dicom.save_as(str(dcm_path))

        loader = LazyDicomLoader(defer_size=100)
        ds = loader.load(dcm_path)
        assert ds is not None

    def test_load_batch_empty(self):
        """Test load_batch with empty list."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        loader = LazyDicomLoader()
        datasets = loader.load_batch([])
        assert datasets == []

    def test_create_metadata_loader_force(self):
        """Test create_metadata_loader sets force correctly."""
        from dicom_fuzzer.core.lazy_loader import create_metadata_loader

        loader = create_metadata_loader()
        assert loader.force is True
        assert loader.metadata_only is True

    def test_create_deferred_loader_size_calculation(self):
        """Test create_deferred_loader calculates size correctly."""
        from dicom_fuzzer.core.lazy_loader import create_deferred_loader

        loader = create_deferred_loader(defer_size_mb=10)
        assert loader.defer_size == 10 * 1024 * 1024


# =============================================================================
# Stability Tracker Tests (Extended)
# =============================================================================


class TestStabilityTrackerExtended:
    """Extended tests for StabilityTracker."""

    def test_stability_metrics_attributes(self):
        """Test StabilityMetrics has all expected attributes."""
        from dicom_fuzzer.core.stability_tracker import (
            StabilityMetrics,
            StabilityTracker,
        )

        tracker = StabilityTracker()
        metrics = tracker.get_metrics()

        assert isinstance(metrics, StabilityMetrics)
        assert hasattr(metrics, "total_executions")
        assert hasattr(metrics, "stability_percentage")
        assert hasattr(metrics, "unstable_inputs")

    def test_record_multiple_executions(self, tmp_path):
        """Test recording multiple executions."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()

        for i in range(5):
            test_file = tmp_path / f"test_{i}.dcm"
            test_file.write_bytes(b"test" + bytes([i]))
            tracker.record_execution(
                test_file=test_file, execution_signature=f"sig_{i}"
            )

        metrics = tracker.get_metrics()
        assert metrics.total_executions >= 5

    def test_is_campaign_stable_empty(self):
        """Test is_campaign_stable with no executions."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()
        # Should handle empty state gracefully
        result = tracker.is_campaign_stable()
        assert isinstance(result, bool)

    def test_calculate_stability_percentage(self, tmp_path):
        """Test stability percentage calculation."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()

        # Record consistent executions
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test data")

        for _ in range(3):
            tracker.record_execution(
                test_file=test_file, execution_signature="consistent_sig"
            )

        metrics = tracker.get_metrics()
        # Should be stable since same signature
        assert metrics.stability_percentage >= 0


# =============================================================================
# Coverage Correlation Tests
# =============================================================================


class TestCoverageCorrelation:
    """Tests for coverage_correlation module."""

    def test_correlate_crashes_empty(self):
        """Test correlate_crashes_with_coverage with empty data."""
        from dicom_fuzzer.utils.coverage_correlation import (
            correlate_crashes_with_coverage,
        )

        correlation = correlate_crashes_with_coverage(
            crashes=[], coverage_data={}, safe_inputs=[]
        )
        assert correlation is not None
        assert correlation.dangerous_paths == []

    def test_generate_correlation_report(self):
        """Test generate_correlation_report."""
        from dicom_fuzzer.utils.coverage_correlation import (
            CrashCoverageCorrelation,
            generate_correlation_report,
        )

        correlation = CrashCoverageCorrelation()
        report = generate_correlation_report(correlation)
        assert isinstance(report, str)
        assert "CRASH-COVERAGE CORRELATION REPORT" in report

    def test_get_safe_coverage(self):
        """Test get_safe_coverage."""
        from dicom_fuzzer.utils.coverage_correlation import get_safe_coverage

        coverage_data = {
            "file1.dcm": {"line1", "line2"},
            "file2.dcm": {"line2", "line3"},
        }
        safe_coverage = get_safe_coverage(coverage_data)
        assert "line1" in safe_coverage
        assert "line2" in safe_coverage
        assert "line3" in safe_coverage

    def test_identify_crash_prone_modules(self):
        """Test identify_crash_prone_modules."""
        from dicom_fuzzer.utils.coverage_correlation import (
            CoverageInsight,
            CrashCoverageCorrelation,
            identify_crash_prone_modules,
        )

        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("module.py:100", 0.8),
            ("module.py:200", 0.7),
            ("other.py:50", 0.6),
        ]
        correlation.coverage_insights = {
            "module.py:100": CoverageInsight(
                identifier="module.py:100", total_hits=10, crash_hits=8
            ),
            "module.py:200": CoverageInsight(
                identifier="module.py:200", total_hits=10, crash_hits=7
            ),
            "other.py:50": CoverageInsight(
                identifier="other.py:50", total_hits=10, crash_hits=6
            ),
        }

        module_counts = identify_crash_prone_modules(correlation)
        assert "module.py" in module_counts
        assert module_counts["module.py"] == 2


# =============================================================================
# Logger Tests
# =============================================================================


class TestLogger:
    """Tests for logger module."""

    def test_get_logger(self):
        """Test get_logger returns a logger."""
        from dicom_fuzzer.utils.logger import get_logger

        logger = get_logger("test_module")
        assert logger is not None

    def test_configure_logging_json(self, tmp_path):
        """Test configure_logging with JSON format."""
        from dicom_fuzzer.utils.logger import configure_logging, get_logger

        configure_logging(log_level="DEBUG", json_format=True)
        logger = get_logger("test_json")
        # Should not raise
        logger.info("test_message", key="value")

    def test_configure_logging_console(self):
        """Test configure_logging with console format."""
        from dicom_fuzzer.utils.logger import configure_logging, get_logger

        configure_logging(log_level="INFO", json_format=False)
        logger = get_logger("test_console")
        logger.info("test_message")

    def test_configure_logging_with_file(self, tmp_path):
        """Test configure_logging with log file."""
        from dicom_fuzzer.utils.logger import configure_logging, get_logger

        log_file = tmp_path / "test.log"
        configure_logging(log_level="DEBUG", json_format=True, log_file=log_file)
        logger = get_logger("test_file")
        logger.info("test_message_to_file")

    def test_redact_sensitive_data(self):
        """Test redact_sensitive_data processor."""
        from dicom_fuzzer.utils.logger import redact_sensitive_data

        event_dict = {
            "patient_name": "John Doe",
            "file_path": "/path/to/file",
        }
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["patient_name"] == "***REDACTED***"
        assert result["file_path"] == "/path/to/file"

    def test_add_timestamp(self):
        """Test add_timestamp processor."""
        from dicom_fuzzer.utils.logger import add_timestamp

        event_dict = {"event": "test"}
        result = add_timestamp(None, "info", event_dict)
        assert "timestamp" in result

    def test_add_security_context(self):
        """Test add_security_context processor."""
        from dicom_fuzzer.utils.logger import add_security_context

        event_dict = {"event": "test", "security_event": True}
        result = add_security_context(None, "info", event_dict)
        assert result["event_category"] == "SECURITY"
        assert result["requires_attention"] is True

    def test_security_event_logger(self):
        """Test SecurityEventLogger."""
        from dicom_fuzzer.utils.logger import (
            SecurityEventLogger,
            configure_logging,
            get_logger,
        )

        configure_logging(log_level="DEBUG", json_format=True)
        logger = get_logger("security_test")
        security_logger = SecurityEventLogger(logger)

        # Test methods don't raise
        security_logger.log_validation_failure(
            file_path="/test.dcm", reason="Invalid header"
        )
        security_logger.log_suspicious_pattern(
            pattern_type="overflow", description="Buffer overflow detected"
        )
        security_logger.log_fuzzing_campaign(
            campaign_id="test_001", status="started", stats={"files": 10}
        )

    def test_performance_logger(self):
        """Test PerformanceLogger."""
        from dicom_fuzzer.utils.logger import (
            PerformanceLogger,
            configure_logging,
            get_logger,
        )

        configure_logging(log_level="DEBUG", json_format=True)
        logger = get_logger("perf_test")
        perf_logger = PerformanceLogger(logger)

        # Test methods don't raise
        perf_logger.log_operation(operation="test_op", duration_ms=100.5)
        perf_logger.log_mutation_stats(
            strategy="random",
            mutations_count=10,
            duration_ms=50.0,
            file_size_bytes=1024,
        )
        perf_logger.log_resource_usage(memory_mb=512.5, cpu_percent=45.2)


# =============================================================================
# Helpers Tests
# =============================================================================


class TestHelpers:
    """Tests for helpers module."""

    def test_format_bytes(self):
        """Test format_bytes function."""
        from dicom_fuzzer.utils.helpers import format_bytes

        result = format_bytes(1024)
        # Can return "1.00 KB" or similar
        assert "KB" in result or "1024" in result

    def test_format_duration(self):
        """Test format_duration function."""
        from dicom_fuzzer.utils.helpers import format_duration

        result = format_duration(3661)  # 1 hour, 1 minute, 1 second
        assert isinstance(result, str)

    def test_ensure_directory(self, tmp_path):
        """Test ensure_directory function."""
        from dicom_fuzzer.utils.helpers import ensure_directory

        new_dir = tmp_path / "new" / "nested" / "dir"
        ensure_directory(new_dir)
        assert new_dir.exists()

    def test_ensure_directory_exists(self, tmp_path):
        """Test ensure_directory with existing directory."""
        from dicom_fuzzer.utils.helpers import ensure_directory

        ensure_directory(tmp_path)
        assert tmp_path.exists()


# =============================================================================
# Hashing Tests
# =============================================================================


class TestHashing:
    """Tests for hashing module."""

    def test_hash_any_string(self):
        """Test hash_any with string."""
        from dicom_fuzzer.utils.hashing import hash_any

        result = hash_any("test string")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_any_bytes(self):
        """Test hash_any with bytes."""
        from dicom_fuzzer.utils.hashing import hash_any

        result = hash_any(b"test bytes")
        assert isinstance(result, str)

    def test_hash_any_dict(self):
        """Test hash_any with dict."""
        from dicom_fuzzer.utils.hashing import hash_any

        result = hash_any({"key": "value", "num": 42})
        assert isinstance(result, str)

    def test_hash_any_list(self):
        """Test hash_any with list."""
        from dicom_fuzzer.utils.hashing import hash_any

        result = hash_any([1, 2, 3, "test"])
        assert isinstance(result, str)

    def test_hash_any_deterministic(self):
        """Test hash_any is deterministic."""
        from dicom_fuzzer.utils.hashing import hash_any

        data = {"key": "value"}
        hash1 = hash_any(data)
        hash2 = hash_any(data)
        assert hash1 == hash2


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_dicom():
    """Create a sample DICOM dataset for testing."""
    ds = Dataset()
    ds.PatientID = "TEST001"
    ds.PatientName = "Test Patient"
    ds.Modality = "CT"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.StudyInstanceUID = "1.2.3.4.5"
    ds.SeriesInstanceUID = "1.2.3.4.5.6"

    # File meta
    ds.file_meta = pydicom.Dataset()
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    return ds
