"""Additional Coverage Tests for Remaining Low-Coverage Modules

Target modules with verified correct signatures.
"""

from datetime import datetime
from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

# =============================================================================
# ViewerConfig Tests
# =============================================================================


class TestViewerConfig:
    """Tests for ViewerConfig dataclass."""

    def test_format_command_basic(self, tmp_path):
        """Test format_command with basic template."""
        from dicom_fuzzer.harness.viewer_launcher_3d import ViewerConfig, ViewerType

        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=tmp_path / "viewer.exe",
            command_template="{folder_path}",
            timeout_seconds=30,
        )
        series_folder = tmp_path / "series"
        series_folder.mkdir()

        cmd = config.format_command(series_folder)
        assert str(series_folder) in cmd[-1]

    def test_format_command_with_args(self, tmp_path):
        """Test format_command with additional arguments."""
        from dicom_fuzzer.harness.viewer_launcher_3d import ViewerConfig, ViewerType

        config = ViewerConfig(
            viewer_type=ViewerType.CUSTOM,
            executable_path=tmp_path / "custom_viewer.exe",
            command_template="--input {folder_path} --mode 3d",
            timeout_seconds=60,
            additional_args=["--verbose"],
        )
        series_folder = tmp_path / "series"
        series_folder.mkdir()

        cmd = config.format_command(series_folder)
        assert "--verbose" in cmd
        assert "--mode" in cmd
        assert "3d" in cmd


class TestSeriesTestResult:
    """Tests for SeriesTestResult dataclass."""

    def test_basic_creation(self, tmp_path):
        """Test basic SeriesTestResult creation."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus
        from dicom_fuzzer.harness.viewer_launcher_3d import SeriesTestResult

        result = SeriesTestResult(
            status=ExecutionStatus.SUCCESS,
            series_folder=tmp_path,
            slice_count=10,
            execution_time=5.5,
            peak_memory_mb=512.0,
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert result.crashed is False
        assert result.slice_count == 10

    def test_with_crash(self, tmp_path):
        """Test SeriesTestResult with crash info."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus
        from dicom_fuzzer.harness.viewer_launcher_3d import SeriesTestResult

        result = SeriesTestResult(
            status=ExecutionStatus.CRASH,
            series_folder=tmp_path,
            slice_count=10,
            execution_time=2.0,
            peak_memory_mb=256.0,
            crashed=True,
            crash_slice_index=5,
            exit_code=-11,
            error_message="Segmentation fault",
        )
        assert result.crashed is True
        assert result.crash_slice_index == 5
        assert result.exit_code == -11


# =============================================================================
# Reporter Extended Tests
# =============================================================================


class TestReporterExtended:
    """Extended tests for reporter module."""

    def test_crash_to_dict(self, tmp_path):
        """Test _crash_to_dict method."""
        from datetime import datetime

        from dicom_fuzzer.core.crash_analyzer import (
            CrashReport,
            CrashSeverity,
            CrashType,
        )
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="crash_001",
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.HIGH,
            timestamp=datetime.now(),
            test_case_path="/path/to/test.dcm",
            crash_hash="abc123",
            exception_message="Test exception",
            stack_trace="test stack trace",
            additional_info={"exception_type": "ValueError"},
        )

        crash_dict = gen._crash_to_dict(crash)
        assert crash_dict["crash_type"] == "segmentation_fault"
        assert crash_dict["severity"] == "high"
        assert crash_dict["crash_hash"] == "abc123"

    def test_generate_crash_details_with_data(self, tmp_path):
        """Test _generate_crash_details_section with crash data."""
        from datetime import datetime

        from dicom_fuzzer.core.crash_analyzer import (
            CrashReport,
            CrashSeverity,
            CrashType,
        )
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))

        crashes = [
            CrashReport(
                crash_id="crash_001",
                crash_type=CrashType.SEGFAULT,
                severity=CrashSeverity.HIGH,
                timestamp=datetime.now(),
                test_case_path="/path/to/test.dcm",
                crash_hash="abc123",
                exception_message="Test exception",
                stack_trace="test\nstack\ntrace",
                additional_info={"exception_type": "ValueError"},
            )
        ]

        html = gen._generate_crash_details_section(crashes)
        assert "Crash Details" in html
        assert "test.dcm" in html

    def test_generate_performance_section_metrics(self, tmp_path):
        """Test _generate_performance_section with various metrics."""
        from dicom_fuzzer.core.reporter import ReportGenerator

        gen = ReportGenerator(output_dir=str(tmp_path))
        metrics = {
            "files_generated": 1000,
            "mutations_applied": 5000,
            "throughput_per_second": 50.5,
            "avg_time_per_file": 0.02,
            "total_time": 20.0,
        }

        html = gen._generate_performance_section(metrics)
        assert "1000" in html
        assert "Performance" in html


# =============================================================================
# Stateless Harness Extended Tests
# =============================================================================


class TestStatelessHarnessExtended:
    """Extended tests for stateless_harness module."""

    def test_hash_result_string(self):
        """Test _hash_result with string."""
        from dicom_fuzzer.utils.stateless_harness import _hash_result

        result = _hash_result("test string")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_result_dict(self):
        """Test _hash_result with dict."""
        from dicom_fuzzer.utils.stateless_harness import _hash_result

        result = _hash_result({"key": "value"})
        assert isinstance(result, str)

    def test_hash_result_list(self):
        """Test _hash_result with list."""
        from dicom_fuzzer.utils.stateless_harness import _hash_result

        result = _hash_result([1, 2, 3])
        assert isinstance(result, str)

    def test_detect_state_leaks_with_state(self, tmp_path):
        """Test detect_state_leaks with stateful harness."""
        from dicom_fuzzer.utils.stateless_harness import detect_state_leaks

        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"test data " + bytes([i]))
            files.append(f)

        call_count = [0]

        def stateful_harness(path):
            call_count[0] += 1
            return f"result_{call_count[0]}"

        result = detect_state_leaks(stateful_harness, files)
        assert isinstance(result, dict)
        assert "leaked" in result


# =============================================================================
# Resource Manager Tests
# =============================================================================


class TestResourceManager:
    """Tests for resource_manager module."""

    def test_resource_manager_init(self):
        """Test ResourceManager initialization."""
        from dicom_fuzzer.core.resource_manager import ResourceManager

        manager = ResourceManager()
        assert manager is not None

    def test_resource_limits_dataclass(self):
        """Test ResourceLimits dataclass."""
        from dicom_fuzzer.core.resource_manager import ResourceLimits

        # Use correct field names
        limits = ResourceLimits(max_memory_mb=1024.0)
        assert limits.max_memory_mb == 1024.0

    def test_resource_usage_dataclass(self):
        """Test ResourceUsage dataclass."""
        from dicom_fuzzer.core.resource_manager import ResourceUsage

        # Use correct field names and required fields including timestamp
        usage = ResourceUsage(
            memory_mb=512.5,
            cpu_seconds=10.0,
            disk_free_mb=1024.0,
            open_files=10,
            timestamp=datetime.now(),
        )
        assert usage.memory_mb == 512.5


# =============================================================================
# Coverage Guided Fuzzer Tests
# =============================================================================


class TestCoverageGuidedFuzzerExtended:
    """Extended tests for coverage_guided_fuzzer module."""

    def test_fuzzing_config_defaults(self):
        """Test FuzzingConfig with default values."""
        from dicom_fuzzer.core.coverage_guided_fuzzer import FuzzingConfig

        config = FuzzingConfig()
        assert config.timeout_per_run > 0
        assert config.max_iterations > 0

    def test_fuzzing_config_custom(self):
        """Test FuzzingConfig with custom values."""
        from dicom_fuzzer.core.coverage_guided_fuzzer import FuzzingConfig

        config = FuzzingConfig(
            timeout_per_run=60,
            max_iterations=1000,
        )
        assert config.timeout_per_run == 60
        assert config.max_iterations == 1000

    def test_coverage_info_creation(self):
        """Test CoverageInfo creation."""
        from dicom_fuzzer.core.coverage_guided_fuzzer import CoverageInfo

        info = CoverageInfo(
            edges={"edge1", "edge2"},
            branches={"branch1"},
            functions={"func1", "func2", "func3"},
            lines={10, 20, 30},
        )
        assert len(info.edges) == 2
        assert len(info.branches) == 1
        assert len(info.functions) == 3
        assert len(info.lines) == 3


# =============================================================================
# Statistics Tests
# =============================================================================


class TestStatisticsExtended:
    """Extended tests for statistics module."""

    def test_statistics_collector_init(self):
        """Test StatisticsCollector initialization."""
        from dicom_fuzzer.core.statistics import StatisticsCollector

        collector = StatisticsCollector()
        assert collector is not None

    def test_iteration_data_dataclass(self):
        """Test IterationData dataclass."""
        from dicom_fuzzer.core.statistics import IterationData

        data = IterationData(
            iteration_number=1,
            file_path=Path("/test/file.dcm"),
            mutations_applied=5,
            severity="moderate",
            timestamp=datetime.now(),
        )
        assert data.iteration_number == 1

    def test_mutation_statistics_dataclass(self):
        """Test MutationStatistics dataclass."""
        from dicom_fuzzer.core.statistics import MutationStatistics

        stats = MutationStatistics()
        assert stats is not None


# =============================================================================
# Timeout Budget Tests
# =============================================================================


class TestTimeoutBudget:
    """Tests for timeout_budget module."""

    def test_timeout_budget_init(self):
        """Test TimeoutBudget initialization."""
        from dicom_fuzzer.utils.timeout_budget import TimeoutBudget

        budget = TimeoutBudget(total_seconds=60.0)
        assert budget is not None

    def test_execution_timer_init(self):
        """Test ExecutionTimer initialization."""
        from dicom_fuzzer.utils.timeout_budget import ExecutionTimer

        timer = ExecutionTimer()
        assert timer is not None

    def test_timeout_budget_manager(self):
        """Test TimeoutBudgetManager."""
        from dicom_fuzzer.utils.timeout_budget import TimeoutBudgetManager

        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)
        assert manager is not None


# =============================================================================
# Validator Tests
# =============================================================================


class TestValidatorExtended:
    """Extended tests for validator module."""

    def test_dicom_validator_init(self):
        """Test DicomValidator initialization."""
        from dicom_fuzzer.core.validator import DicomValidator

        validator = DicomValidator()
        assert validator is not None

    def test_validation_result(self):
        """Test ValidationResult."""
        from dicom_fuzzer.core.validator import ValidationResult

        # ValidationResult has default is_valid=True
        result = ValidationResult()
        assert result.is_valid is True


# =============================================================================
# Corpus Minimization Tests
# =============================================================================


class TestCorpusMinimization:
    """Tests for corpus_minimization module."""

    def test_minimize_corpus_for_campaign(self, tmp_path):
        """Test minimize_corpus_for_campaign function exists."""
        from dicom_fuzzer.utils.corpus_minimization import minimize_corpus_for_campaign

        assert callable(minimize_corpus_for_campaign)

    def test_validate_corpus_quality(self, tmp_path):
        """Test validate_corpus_quality function exists."""
        from dicom_fuzzer.utils.corpus_minimization import validate_corpus_quality

        assert callable(validate_corpus_quality)


# =============================================================================
# Series Cache Tests
# =============================================================================


class TestSeriesCache:
    """Tests for series_cache module."""

    def test_cache_init(self, tmp_path):
        """Test SeriesCache initialization."""
        from dicom_fuzzer.core.series_cache import SeriesCache

        cache = SeriesCache(cache_dir=tmp_path)
        assert cache.cache_dir == tmp_path


# =============================================================================
# Coverage Correlation Extended Tests
# =============================================================================


class TestCoverageCorrelationExtended:
    """Extended tests for coverage_correlation module."""

    def test_coverage_insight_update(self):
        """Test CoverageInsight update_crash_rate."""
        from dicom_fuzzer.utils.coverage_correlation import CoverageInsight

        insight = CoverageInsight(
            identifier="test_id", total_hits=10, crash_hits=5, safe_hits=5
        )
        insight.update_crash_rate()
        assert insight.crash_rate == 0.5

    def test_coverage_insight_zero_hits(self):
        """Test CoverageInsight with zero hits."""
        from dicom_fuzzer.utils.coverage_correlation import CoverageInsight

        insight = CoverageInsight(identifier="test_id")
        insight.update_crash_rate()
        assert insight.crash_rate == 0.0

    def test_extract_functions_various_formats(self):
        """Test _extract_functions_from_coverage with various ID formats."""
        from dicom_fuzzer.utils.coverage_correlation import (
            _extract_functions_from_coverage,
        )

        dangerous_paths = [
            ("file.py:123", 0.9),
            ("file.py:function_name", 0.8),
            ("module.submodule.function", 0.7),
            ("standalone_func", 0.6),
        ]

        functions = _extract_functions_from_coverage(dangerous_paths)
        assert "function_name" in functions
        assert "function" in functions
        assert "standalone_func" in functions


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
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()

    ds.file_meta = pydicom.Dataset()
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    return ds
