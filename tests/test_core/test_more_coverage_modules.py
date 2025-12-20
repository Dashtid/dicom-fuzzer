"""Tests for additional low-coverage modules to achieve 90% coverage.

This module targets:
- crash_analyzer.py (48% -> higher)
- crash_deduplication.py (49% -> higher)
- viewer_launcher_3d.py (28% -> higher)
- validator.py (70% -> higher)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from dicom_fuzzer.core.crash_analyzer import (
    CrashAnalyzer,
    CrashReport,
    CrashSeverity,
    CrashType,
)
from dicom_fuzzer.core.crash_deduplication import (
    CrashDeduplicator,
    DeduplicationConfig,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord
from dicom_fuzzer.harness.viewer_launcher_3d import (
    SeriesTestResult,
    ViewerConfig,
    ViewerType,
)


class TestCrashAnalyzer:
    """Tests for CrashAnalyzer class."""

    def test_init_creates_crash_dir(self, tmp_path: Path) -> None:
        """Test that CrashAnalyzer creates crash directory."""
        crash_dir = tmp_path / "crashes"
        analyzer = CrashAnalyzer(crash_dir=str(crash_dir))
        assert crash_dir.exists()
        assert analyzer.crashes == []
        assert analyzer.crash_hashes == set()

    def test_init_with_existing_dir(self, tmp_path: Path) -> None:
        """Test CrashAnalyzer with existing directory."""
        crash_dir = tmp_path / "existing_crashes"
        crash_dir.mkdir()
        analyzer = CrashAnalyzer(crash_dir=str(crash_dir))
        assert crash_dir.exists()

    def test_analyze_exception_value_error(self, tmp_path: Path) -> None:
        """Test analyzing ValueError exception."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise ValueError("Invalid DICOM tag value: 0x1234")
        except ValueError as e:
            report = analyzer.analyze_exception(e, "/path/to/test.dcm")

        assert report is not None
        assert report.crash_type == CrashType.UNCAUGHT_EXCEPTION
        assert report.severity in [CrashSeverity.LOW, CrashSeverity.MEDIUM]
        assert report.test_case_path == "/path/to/test.dcm"
        assert "ValueError" in report.stack_trace

    def test_analyze_exception_memory_error(self, tmp_path: Path) -> None:
        """Test analyzing MemoryError exception."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise MemoryError("Cannot allocate memory for pixel data")
        except MemoryError as e:
            report = analyzer.analyze_exception(e, "/path/to/large.dcm")

        assert report is not None
        assert report.crash_type == CrashType.OUT_OF_MEMORY
        assert report.severity == CrashSeverity.HIGH

    def test_analyze_exception_recursion_error(self, tmp_path: Path) -> None:
        """Test analyzing RecursionError (stack overflow)."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise RecursionError("maximum recursion depth exceeded")
        except RecursionError as e:
            report = analyzer.analyze_exception(e, "/path/to/recursive.dcm")

        assert report is not None
        assert report.crash_type == CrashType.STACK_OVERFLOW
        # RecursionError is classified as HIGH severity in the implementation
        assert report.severity == CrashSeverity.HIGH

    def test_analyze_exception_assertion_error(self, tmp_path: Path) -> None:
        """Test analyzing AssertionError."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            assert False, "Invalid state: sequence should not be empty"
        except AssertionError as e:
            report = analyzer.analyze_exception(e, "/path/to/invalid.dcm")

        assert report is not None
        assert report.crash_type == CrashType.ASSERTION_FAILURE
        assert report.severity == CrashSeverity.MEDIUM

    def test_analyze_exception_generic(self, tmp_path: Path) -> None:
        """Test analyzing generic exception."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise RuntimeError("Unexpected error during processing")
        except RuntimeError as e:
            report = analyzer.analyze_exception(e, "/path/to/error.dcm")

        assert report is not None
        assert report.crash_type == CrashType.UNCAUGHT_EXCEPTION

    def test_crash_report_generation(self, tmp_path: Path) -> None:
        """Test that crash report contains required fields."""
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        try:
            raise KeyError("Missing required DICOM tag")
        except KeyError as e:
            report = analyzer.analyze_exception(e, "/test/path.dcm")

        # Verify all required fields
        assert report.crash_id
        assert isinstance(report.timestamp, datetime)
        assert isinstance(report.crash_type, CrashType)
        assert isinstance(report.severity, CrashSeverity)
        assert report.test_case_path == "/test/path.dcm"
        assert report.stack_trace
        assert report.crash_hash


class TestCrashDeduplicator:
    """Tests for CrashDeduplicator class."""

    def create_mock_crash(
        self,
        crash_id: str = "crash_001",
        crash_type: str = "crash",
        exception_type: str = "ValueError",
        exception_message: str = "Test error",
        stack_trace: str = "File 'test.py', line 10, in func\n  raise ValueError('Test')",
    ) -> CrashRecord:
        """Create a mock CrashRecord for testing."""
        return CrashRecord(
            crash_id=crash_id,
            timestamp=datetime.now(),
            crash_type=crash_type,
            severity="medium",
            fuzzed_file_id="file_001",
            fuzzed_file_path=str(Path(f"/tmp/{crash_id}.dcm")),
            exception_type=exception_type,
            exception_message=exception_message,
            stack_trace=stack_trace,
        )

    def test_init_default_config(self) -> None:
        """Test CrashDeduplicator with default config."""
        dedup = CrashDeduplicator()
        assert dedup.config is not None
        assert dedup.crash_groups == []

    def test_init_custom_config(self) -> None:
        """Test CrashDeduplicator with custom config."""
        config = DeduplicationConfig(
            stack_trace_weight=0.6,
            exception_weight=0.3,
            mutation_weight=0.1,
            overall_threshold=0.8,
        )
        dedup = CrashDeduplicator(config=config)
        assert dedup.config.overall_threshold == 0.8

    def test_deduplicate_empty_list(self) -> None:
        """Test deduplication of empty crash list."""
        dedup = CrashDeduplicator()
        groups = dedup.deduplicate_crashes([])
        assert groups == {}

    def test_deduplicate_single_crash(self) -> None:
        """Test deduplication with single crash."""
        dedup = CrashDeduplicator()
        crash = self.create_mock_crash()
        groups = dedup.deduplicate_crashes([crash])

        assert len(groups) == 1
        assert dedup.get_unique_crash_count() == 1

    def test_deduplicate_identical_crashes(self) -> None:
        """Test that identical crashes are grouped together."""
        dedup = CrashDeduplicator()

        # Create two identical crashes
        crash1 = self.create_mock_crash(
            crash_id="crash_001",
            exception_type="ValueError",
            exception_message="Same error",
            stack_trace="File 'test.py', line 10\n  raise ValueError()",
        )
        crash2 = self.create_mock_crash(
            crash_id="crash_002",
            exception_type="ValueError",
            exception_message="Same error",
            stack_trace="File 'test.py', line 10\n  raise ValueError()",
        )

        groups = dedup.deduplicate_crashes([crash1, crash2])

        # Should be grouped together
        assert dedup.get_unique_crash_count() == 1

    def test_deduplicate_different_crashes(self) -> None:
        """Test that different crashes are in separate groups."""
        dedup = CrashDeduplicator()

        crash1 = self.create_mock_crash(
            crash_id="crash_001",
            exception_type="ValueError",
            exception_message="Error in parsing",
            stack_trace="File 'parser.py', line 50\n  raise ValueError()",
        )
        crash2 = self.create_mock_crash(
            crash_id="crash_002",
            exception_type="MemoryError",
            exception_message="Out of memory",
            stack_trace="File 'loader.py', line 100\n  raise MemoryError()",
        )

        groups = dedup.deduplicate_crashes([crash1, crash2])

        # Should be in different groups
        assert dedup.get_unique_crash_count() == 2

    def test_get_deduplication_stats_empty(self) -> None:
        """Test stats with no crashes."""
        dedup = CrashDeduplicator()
        stats = dedup.get_deduplication_stats()

        assert stats["total_crashes"] == 0
        assert stats["unique_groups"] == 0
        assert stats["largest_group"] == 0
        assert stats["deduplication_ratio"] == 0.0

    def test_get_deduplication_stats_with_crashes(self) -> None:
        """Test stats after deduplication."""
        dedup = CrashDeduplicator()

        crashes = [
            self.create_mock_crash(
                crash_id=f"crash_{i:03d}",
                exception_type="ValueError",
                exception_message="Same error",
                stack_trace="same stack trace",
            )
            for i in range(5)
        ]

        dedup.deduplicate_crashes(crashes)
        stats = dedup.get_deduplication_stats()

        assert stats["total_crashes"] == 5
        assert stats["unique_groups"] >= 1
        assert stats["largest_group"] >= 1

    def test_config_weight_validation(self) -> None:
        """Test that config validates weight sum."""
        with pytest.raises(ValueError, match="Weights must sum to 1.0"):
            DeduplicationConfig(
                stack_trace_weight=0.5,
                exception_weight=0.5,
                mutation_weight=0.5,  # Total = 1.5, should fail
            )

    def test_compare_stack_traces_similar(self) -> None:
        """Test stack trace comparison with similar traces."""
        dedup = CrashDeduplicator()

        trace1 = """File "parser.py", line 50, in parse_dicom
    raise ValueError("Invalid tag")
File "main.py", line 100, in main
    parse_dicom(file)"""

        trace2 = """File "parser.py", line 52, in parse_dicom
    raise ValueError("Bad tag value")
File "main.py", line 102, in main
    parse_dicom(file)"""

        similarity = dedup._compare_stack_traces(trace1, trace2)
        assert similarity > 0.5  # Should be similar

    def test_normalize_stack_trace(self) -> None:
        """Test stack trace normalization."""
        dedup = CrashDeduplicator()

        trace = """0x7fff12345678 in crash_func at file.c:42
pid: 12345 tid: 67890
2025-01-15 10:30:00 Error occurred"""

        normalized = dedup._normalize_stack_trace(trace)

        assert "0x7fff12345678" not in normalized
        assert "0xADDR" in normalized
        assert ":42" not in normalized
        assert "12345" not in normalized or "ID" in normalized

    def test_extract_function_sequence(self) -> None:
        """Test function sequence extraction."""
        dedup = CrashDeduplicator()

        trace = """at parse_header(file.c:10)
at load_dicom(main.c:50)
at main(main.c:100)"""

        funcs = dedup._extract_function_sequence(trace)
        assert len(funcs) > 0

    def test_compare_exceptions_identical(self) -> None:
        """Test exception comparison with identical exceptions."""
        dedup = CrashDeduplicator()

        crash1 = self.create_mock_crash(
            exception_type="ValueError",
            exception_message="Invalid value: 12345",
        )
        crash2 = self.create_mock_crash(
            exception_type="ValueError",
            exception_message="Invalid value: 12345",
        )

        similarity = dedup._compare_exceptions(crash1, crash2)
        assert similarity == 1.0

    def test_compare_exceptions_different_types(self) -> None:
        """Test exception comparison with different types."""
        dedup = CrashDeduplicator()

        crash1 = self.create_mock_crash(exception_type="ValueError")
        crash2 = self.create_mock_crash(exception_type="KeyError")

        similarity = dedup._compare_exceptions(crash1, crash2)
        assert similarity < 1.0

    def test_compare_exceptions_empty(self) -> None:
        """Test exception comparison with no exception info."""
        dedup = CrashDeduplicator()

        crash1 = self.create_mock_crash(
            exception_type=None,
            exception_message=None,
        )
        crash2 = self.create_mock_crash(
            exception_type=None,
            exception_message=None,
        )

        # Should handle None gracefully
        similarity = dedup._compare_exceptions(crash1, crash2)
        assert 0 <= similarity <= 1.0


class TestViewerConfig:
    """Tests for ViewerConfig dataclass."""

    def test_viewer_config_format_command(self) -> None:
        """Test formatting command with series folder."""
        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=Path("/usr/bin/viewer"),
            command_template="{folder_path}",
            timeout_seconds=30,
        )

        cmd = config.format_command(Path("/path/to/series"))
        # Path conversion may differ on Windows vs Unix
        assert "viewer" in cmd[0]
        assert "series" in " ".join(cmd)

    def test_viewer_config_with_additional_args(self) -> None:
        """Test command formatting with additional arguments."""
        config = ViewerConfig(
            viewer_type=ViewerType.CUSTOM,
            executable_path=Path("/opt/viewer/viewer.exe"),
            command_template="--input {folder_path}",
            additional_args=["--verbose", "--no-cache"],
        )

        cmd = config.format_command(Path("/series/folder"))
        assert "--verbose" in cmd
        assert "--no-cache" in cmd

    def test_viewer_type_enum(self) -> None:
        """Test ViewerType enum values."""
        assert ViewerType.GENERIC.value == "generic"
        assert ViewerType.MICRODICOM.value == "microdicom"
        assert ViewerType.RADIANT.value == "radiant"
        assert ViewerType.RUBO.value == "rubo"
        assert ViewerType.CUSTOM.value == "custom"


class TestSeriesTestResult:
    """Tests for SeriesTestResult dataclass."""

    def test_series_test_result_creation(self) -> None:
        """Test creating SeriesTestResult."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus

        result = SeriesTestResult(
            status=ExecutionStatus.SUCCESS,
            series_folder=Path("/series/folder"),
            slice_count=100,
            execution_time=5.5,
            peak_memory_mb=512.0,
        )

        assert result.status == ExecutionStatus.SUCCESS
        assert result.series_folder == Path("/series/folder")
        assert result.slice_count == 100
        assert result.peak_memory_mb == 512.0

    def test_series_test_result_crashed(self) -> None:
        """Test SeriesTestResult with crash."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus

        result = SeriesTestResult(
            status=ExecutionStatus.CRASH,
            series_folder=Path("/bad/series"),
            slice_count=50,
            execution_time=2.5,
            peak_memory_mb=256.0,
            crashed=True,
            crash_slice_index=25,
            exit_code=-11,
        )

        assert result.status == ExecutionStatus.CRASH
        assert result.crashed is True
        assert result.crash_slice_index == 25


class TestDeduplicationConfig:
    """Tests for DeduplicationConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = DeduplicationConfig()

        assert config.use_stack_trace is True
        assert config.use_exception_type is True
        assert config.use_mutation_pattern is True
        assert config.stack_trace_weight == 0.5
        assert config.exception_weight == 0.3
        assert config.mutation_weight == 0.2
        assert config.overall_threshold == 0.75

    def test_config_post_init_valid(self) -> None:
        """Test that valid config passes validation."""
        # Should not raise
        config = DeduplicationConfig(
            stack_trace_weight=0.4,
            exception_weight=0.4,
            mutation_weight=0.2,
        )
        assert config is not None

    def test_config_disabled_strategies(self) -> None:
        """Test config with disabled strategies."""
        config = DeduplicationConfig(
            use_stack_trace=False,
            use_exception_type=True,
            use_mutation_pattern=False,
        )

        assert config.use_stack_trace is False
        assert config.use_mutation_pattern is False


class TestCrashEnums:
    """Tests for crash-related enums."""

    def test_crash_severity_values(self) -> None:
        """Test CrashSeverity enum values."""
        assert CrashSeverity.CRITICAL.value == "critical"
        assert CrashSeverity.HIGH.value == "high"
        assert CrashSeverity.MEDIUM.value == "medium"
        assert CrashSeverity.LOW.value == "low"
        assert CrashSeverity.UNKNOWN.value == "unknown"

    def test_crash_type_values(self) -> None:
        """Test CrashType enum values."""
        assert CrashType.SEGFAULT.value == "segmentation_fault"
        assert CrashType.ASSERTION_FAILURE.value == "assertion_failure"
        assert CrashType.UNCAUGHT_EXCEPTION.value == "uncaught_exception"
        assert CrashType.TIMEOUT.value == "timeout"
        assert CrashType.OUT_OF_MEMORY.value == "out_of_memory"
        assert CrashType.STACK_OVERFLOW.value == "stack_overflow"


class TestCrashReport:
    """Tests for CrashReport dataclass."""

    def test_crash_report_creation(self) -> None:
        """Test creating CrashReport."""
        report = CrashReport(
            crash_id="crash_123",
            timestamp=datetime.now(),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=CrashSeverity.MEDIUM,
            test_case_path="/path/to/test.dcm",
            stack_trace="stack trace here",
            exception_message="Test exception",
            crash_hash="abc123",
            additional_info={"key": "value"},
        )

        assert report.crash_id == "crash_123"
        assert report.crash_type == CrashType.UNCAUGHT_EXCEPTION
        assert report.severity == CrashSeverity.MEDIUM

    def test_crash_report_optional_fields(self) -> None:
        """Test CrashReport with optional fields as None."""
        report = CrashReport(
            crash_id="crash_456",
            timestamp=datetime.now(),
            crash_type=CrashType.TIMEOUT,
            severity=CrashSeverity.HIGH,
            test_case_path="/path/to/timeout.dcm",
            stack_trace=None,
            exception_message=None,
            crash_hash="def456",
            additional_info={},
        )

        assert report.stack_trace is None
        assert report.exception_message is None
