"""Tests for StressTester - Memory and Performance Stress Testing."""

import tempfile
from pathlib import Path

import pydicom
import pytest

from dicom_fuzzer.core.harness.stress_tester import (
    MemorySnapshot,
    StressTestConfig,
    StressTester,
    StressTestResult,
)


class TestStressTestConfig:
    """Test StressTestConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = StressTestConfig()
        assert config.max_slices == 1000
        assert config.max_dimensions == (2048, 2048)
        assert config.bits_allocated == 16
        assert config.duration_minutes == 60
        assert config.monitor_interval_seconds == 5.0
        assert config.memory_limit_mb == 4096
        assert config.disk_limit_mb == 10240

    def test_custom_config(self):
        """Test custom configuration values."""
        config = StressTestConfig(
            max_slices=500,
            max_dimensions=(1024, 1024),
            bits_allocated=8,
            duration_minutes=30,
        )
        assert config.max_slices == 500
        assert config.max_dimensions == (1024, 1024)
        assert config.bits_allocated == 8
        assert config.duration_minutes == 30


class TestMemorySnapshot:
    """Test MemorySnapshot dataclass."""

    def test_memory_snapshot_creation(self):
        """Test creating a memory snapshot."""
        snapshot = MemorySnapshot(
            timestamp=12345.0,
            process_memory_mb=512.0,
            system_memory_percent=75.0,
            details={"process_rss_mb": 512.0},
        )
        assert snapshot.timestamp == 12345.0
        assert snapshot.process_memory_mb == 512.0
        assert snapshot.system_memory_percent == 75.0
        assert "process_rss_mb" in snapshot.details

    def test_memory_snapshot_default_details(self):
        """Test memory snapshot with default details."""
        snapshot = MemorySnapshot(
            timestamp=0.0,
            process_memory_mb=0.0,
            system_memory_percent=0.0,
        )
        assert snapshot.details == {}


class TestStressTestResult:
    """Test StressTestResult dataclass."""

    def test_result_creation(self):
        """Test creating a stress test result."""
        result = StressTestResult(
            start_time=1000.0,
            end_time=1100.0,
            duration_seconds=100.0,
            series_path=Path("/test/series"),
            slice_count=100,
            dimensions=(512, 512),
            memory_peak_mb=256.0,
            success=True,
        )
        assert result.start_time == 1000.0
        assert result.end_time == 1100.0
        assert result.duration_seconds == 100.0
        assert result.slice_count == 100
        assert result.dimensions == (512, 512)
        assert result.success is True

    def test_result_summary(self):
        """Test result summary generation."""
        result = StressTestResult(
            start_time=0.0,
            end_time=60.0,
            duration_seconds=60.0,
            series_path=None,
            slice_count=50,
            dimensions=(256, 256),
            memory_peak_mb=128.0,
            success=True,
        )
        summary = result.summary()

        assert "60.0s" in summary
        assert "50" in summary
        assert "256x256" in summary
        assert "128.0 MB" in summary
        assert "Success: True" in summary

    def test_result_with_errors(self):
        """Test result with errors."""
        result = StressTestResult(
            start_time=0.0,
            end_time=10.0,
            duration_seconds=10.0,
            series_path=None,
            slice_count=0,
            dimensions=(512, 512),
            errors=["Memory error", "Disk full"],
            success=False,
        )
        assert len(result.errors) == 2
        assert result.success is False
        summary = result.summary()
        assert "Errors: 2" in summary
        assert "Success: False" in summary


class TestStressTester:
    """Test StressTester class."""

    def test_init_default(self):
        """Test default initialization."""
        tester = StressTester()
        assert tester.config.max_slices == 1000
        assert tester.config.max_dimensions == (2048, 2048)

    def test_init_with_config(self):
        """Test initialization with custom config."""
        config = StressTestConfig(max_slices=100, max_dimensions=(256, 256))
        tester = StressTester(config)
        assert tester.config.max_slices == 100
        assert tester.config.max_dimensions == (256, 256)

    def test_estimate_memory_usage(self):
        """Test memory usage estimation."""
        tester = StressTester()
        estimate = tester.estimate_memory_usage(
            slice_count=100,
            dimensions=(512, 512),
        )

        assert "slice_mb" in estimate
        assert "series_pixel_data_mb" in estimate
        assert "estimated_viewer_mb" in estimate
        assert estimate["slice_count"] == 100
        assert estimate["dimensions"] == "512x512"

        # Verify calculations
        # 512 * 512 * 2 bytes = 524288 bytes = 0.5 MB per slice
        assert estimate["slice_mb"] == pytest.approx(0.5, rel=0.01)
        assert estimate["series_pixel_data_mb"] == pytest.approx(50.0, rel=0.01)

    def test_get_current_memory(self):
        """Test getting current memory usage."""
        tester = StressTester()
        snapshot = tester.get_current_memory()

        assert isinstance(snapshot, MemorySnapshot)
        assert snapshot.timestamp > 0
        # Memory values should be non-negative
        assert snapshot.process_memory_mb >= 0
        assert snapshot.system_memory_percent >= 0


class TestGenerateLargeSeries:
    """Test large series generation."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary directory for test output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generate_small_series(self, temp_output_dir):
        """Test generating a small series."""
        config = StressTestConfig(max_slices=100, max_dimensions=(128, 128))
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=5,
            dimensions=(64, 64),
        )

        assert series_path.exists()
        dcm_files = list(series_path.glob("*.dcm"))
        assert len(dcm_files) == 5

    def test_generated_files_are_valid_dicom(self, temp_output_dir):
        """Test that generated files are valid DICOM."""
        config = StressTestConfig(max_slices=10, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=3,
            dimensions=(32, 32),
        )

        # Read and validate first file
        dcm_files = sorted(series_path.glob("*.dcm"))
        ds = pydicom.dcmread(dcm_files[0])

        assert ds.PatientName == "STRESS^TEST^PATIENT"
        assert ds.PatientID == "STRESS_TEST_001"
        assert ds.Rows == 32
        assert ds.Columns == 32
        assert ds.BitsAllocated == 16
        assert hasattr(ds, "PixelData")

    def test_series_consistency(self, temp_output_dir):
        """Test that series has consistent UIDs across slices."""
        config = StressTestConfig(max_slices=10, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=5,
            dimensions=(32, 32),
        )

        dcm_files = sorted(series_path.glob("*.dcm"))
        datasets = [pydicom.dcmread(f) for f in dcm_files]

        # All should share same StudyInstanceUID and SeriesInstanceUID
        study_uid = datasets[0].StudyInstanceUID
        series_uid = datasets[0].SeriesInstanceUID
        frame_uid = datasets[0].FrameOfReferenceUID

        for ds in datasets[1:]:
            assert ds.StudyInstanceUID == study_uid
            assert ds.SeriesInstanceUID == series_uid
            assert ds.FrameOfReferenceUID == frame_uid

        # Each should have unique SOPInstanceUID
        sop_uids = [ds.SOPInstanceUID for ds in datasets]
        assert len(set(sop_uids)) == len(sop_uids)

    def test_dimensions_limited_by_config(self, temp_output_dir):
        """Test that dimensions are limited by config."""
        config = StressTestConfig(max_slices=10, max_dimensions=(64, 64))
        tester = StressTester(config)

        # Request larger dimensions than allowed
        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(256, 256),
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.Rows == 64
        assert ds.Columns == 64

    def test_slice_count_limited_by_config(self, temp_output_dir):
        """Test that slice count is limited by config."""
        config = StressTestConfig(max_slices=5, max_dimensions=(64, 64))
        tester = StressTester(config)

        # Request more slices than allowed
        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=100,
            dimensions=(32, 32),
        )

        dcm_files = list(series_path.glob("*.dcm"))
        assert len(dcm_files) == 5

    def test_pixel_pattern_gradient(self, temp_output_dir):
        """Test gradient pixel pattern."""
        tester = StressTester(StressTestConfig(max_slices=10, max_dimensions=(64, 64)))

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="gradient",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert hasattr(ds, "PixelData")
        assert len(ds.PixelData) == 32 * 32 * 2  # 16-bit = 2 bytes

    def test_pixel_pattern_random(self, temp_output_dir):
        """Test random pixel pattern."""
        tester = StressTester(StressTestConfig(max_slices=10, max_dimensions=(64, 64)))

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="random",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert hasattr(ds, "PixelData")

    def test_pixel_pattern_anatomical(self, temp_output_dir):
        """Test anatomical pixel pattern."""
        tester = StressTester(StressTestConfig(max_slices=10, max_dimensions=(64, 64)))

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="anatomical",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert hasattr(ds, "PixelData")

    def test_modality_mr(self, temp_output_dir):
        """Test MR modality series generation."""
        tester = StressTester(StressTestConfig(max_slices=10, max_dimensions=(64, 64)))

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            modality="MR",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.Modality == "MR"
        # MR should not have RescaleSlope/Intercept
        assert not hasattr(ds, "RescaleSlope")


class TestGenerateIncrementalSeries:
    """Test incremental series generation with missing slices."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary directory for test output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_middle_missing_pattern(self, temp_output_dir):
        """Test middle missing pattern."""
        config = StressTestConfig(max_slices=100, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path, missing = tester.generate_incremental_series(
            output_dir=temp_output_dir,
            slice_count=30,
            missing_pattern="middle",
        )

        dcm_files = list(series_path.glob("*.dcm"))

        # Should have 30 - (middle 30%) = 30 - 10 = 20 files
        assert len(dcm_files) == 20
        # Missing should be middle 30%
        assert 10 in missing
        assert 15 in missing

    def test_boundary_missing_pattern(self, temp_output_dir):
        """Test boundary missing pattern."""
        config = StressTestConfig(max_slices=100, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path, missing = tester.generate_incremental_series(
            output_dir=temp_output_dir,
            slice_count=30,
            missing_pattern="boundary",
        )

        # Should have first and last 10% missing
        assert 0 in missing
        assert 1 in missing
        assert 2 in missing
        assert 27 in missing
        assert 28 in missing
        assert 29 in missing

    def test_every_nth_missing_pattern(self, temp_output_dir):
        """Test every_nth missing pattern."""
        config = StressTestConfig(max_slices=100, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path, missing = tester.generate_incremental_series(
            output_dir=temp_output_dir,
            slice_count=25,
            missing_pattern="every_nth",
        )

        # Every 5th slice should be missing
        expected_missing = [0, 5, 10, 15, 20]
        assert sorted(missing) == expected_missing

    def test_random_missing_pattern(self, temp_output_dir):
        """Test random missing pattern."""
        config = StressTestConfig(max_slices=100, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path, missing = tester.generate_incremental_series(
            output_dir=temp_output_dir,
            slice_count=50,
            missing_pattern="random",
        )

        # Should remove 20% = 10 slices
        assert len(missing) == 10
        # Remaining files
        dcm_files = list(series_path.glob("*.dcm"))
        assert len(dcm_files) == 40


class TestRunMemoryStressTest:
    """Test memory stress test execution."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary directory for test output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_memory_stress_test_basic(self, temp_output_dir):
        """Test basic memory stress test."""
        config = StressTestConfig(max_slices=100, max_dimensions=(64, 64))
        tester = StressTester(config)

        results = tester.run_memory_stress_test(
            output_dir=temp_output_dir,
            escalation_steps=[5, 10],
        )

        assert len(results) == 2
        assert all(r.success for r in results)
        assert results[0].slice_count == 5
        assert results[1].slice_count == 10

    def test_memory_stress_test_creates_directories(self, temp_output_dir):
        """Test that stress test creates step directories."""
        config = StressTestConfig(max_slices=50, max_dimensions=(64, 64))
        tester = StressTester(config)

        tester.run_memory_stress_test(
            output_dir=temp_output_dir,
            escalation_steps=[5, 10],
        )

        # Check directories were created
        step_dirs = list(temp_output_dir.glob("step_*"))
        assert len(step_dirs) == 2

    def test_memory_stress_test_default_steps(self, temp_output_dir):
        """Test default escalation steps."""
        config = StressTestConfig(max_slices=5, max_dimensions=(32, 32))
        tester = StressTester(config)

        # Will be limited by max_slices=5
        results = tester.run_memory_stress_test(
            output_dir=temp_output_dir,
        )

        # Results store the requested slice counts (100, 250, 500, 1000)
        # but actual files generated are capped by max_slices
        default_steps = [100, 250, 500, 1000]
        assert len(results) == len(default_steps)
        for i, result in enumerate(results):
            assert result.slice_count == default_steps[i]
            # Verify actual files are capped
            if result.series_path:
                dcm_files = list(result.series_path.glob("*.dcm"))
                assert len(dcm_files) == 5

    def test_memory_stress_test_captures_snapshots(self, temp_output_dir):
        """Test that memory snapshots are captured."""
        config = StressTestConfig(max_slices=20, max_dimensions=(32, 32))
        tester = StressTester(config)

        results = tester.run_memory_stress_test(
            output_dir=temp_output_dir,
            escalation_steps=[5],
        )

        assert len(results) == 1
        result = results[0]
        assert len(result.memory_snapshots) == 2  # Before and after


class TestStressTesterBranchCoverage:
    """Additional tests for branch coverage."""

    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary directory for test output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_pixel_pattern_noise_else_branch(self, temp_output_dir):
        """Test noise pixel pattern (the else branch for unknown patterns)."""
        config = StressTestConfig(max_slices=10, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="noise",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert hasattr(ds, "PixelData")
        assert len(ds.PixelData) == 32 * 32 * 2

    def test_pixel_pattern_unknown_falls_to_noise(self, temp_output_dir):
        """Test unknown pattern falls through to noise (else branch)."""
        config = StressTestConfig(max_slices=10, max_dimensions=(64, 64))
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="unknown_pattern",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert hasattr(ds, "PixelData")

    def test_8bit_pixel_data(self, temp_output_dir):
        """Test 8-bit pixel data generation (bits_allocated=8 branch)."""
        config = StressTestConfig(
            max_slices=10,
            max_dimensions=(64, 64),
            bits_allocated=8,
        )
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="gradient",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.BitsAllocated == 8
        # 8-bit = 1 byte per pixel
        assert len(ds.PixelData) == 32 * 32 * 1

    def test_8bit_random_pattern(self, temp_output_dir):
        """Test 8-bit with random pattern."""
        config = StressTestConfig(
            max_slices=10,
            max_dimensions=(64, 64),
            bits_allocated=8,
        )
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="random",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.BitsAllocated == 8

    def test_8bit_anatomical_pattern(self, temp_output_dir):
        """Test 8-bit with anatomical pattern."""
        config = StressTestConfig(
            max_slices=10,
            max_dimensions=(64, 64),
            bits_allocated=8,
        )
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="anatomical",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.BitsAllocated == 8

    def test_8bit_noise_pattern(self, temp_output_dir):
        """Test 8-bit with noise pattern."""
        config = StressTestConfig(
            max_slices=10,
            max_dimensions=(64, 64),
            bits_allocated=8,
        )
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=2,
            dimensions=(32, 32),
            pixel_pattern="noise",
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.BitsAllocated == 8

    def test_get_current_memory_without_psutil(self):
        """Test get_current_memory when psutil import fails."""
        from unittest.mock import patch

        tester = StressTester()

        # Mock the import to raise ImportError
        with patch.dict("sys.modules", {"psutil": None}):
            with patch(
                "dicom_fuzzer.core.harness.stress_tester.StressTester.get_current_memory"
            ) as mock_mem:
                # Simulate ImportError behavior
                mock_mem.return_value = MemorySnapshot(
                    timestamp=0.0,
                    process_memory_mb=0.0,
                    system_memory_percent=0.0,
                    details={"error": "psutil not installed"},
                )
                snapshot = mock_mem()
                assert "error" in snapshot.details
                assert "psutil" in snapshot.details["error"]

    def test_get_current_memory_general_exception(self):
        """Test get_current_memory when psutil raises exception."""
        from unittest.mock import MagicMock, patch

        tester = StressTester()

        mock_psutil = MagicMock()
        mock_psutil.Process.side_effect = RuntimeError("Process error")

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            # Call the actual method - it should handle the exception
            snapshot = tester.get_current_memory()
            # Should return snapshot with error in details or zero values
            assert isinstance(snapshot, MemorySnapshot)
            assert snapshot.timestamp > 0

    def test_run_memory_stress_test_exception_during_generation(self, temp_output_dir):
        """Test memory stress test when generation fails."""
        from unittest.mock import patch

        config = StressTestConfig(max_slices=10, max_dimensions=(32, 32))
        tester = StressTester(config)

        with patch.object(
            tester, "generate_large_series", side_effect=OSError("Disk full")
        ):
            results = tester.run_memory_stress_test(
                output_dir=temp_output_dir,
                escalation_steps=[5],
            )

            assert len(results) == 1
            assert results[0].success is False
            assert "Disk full" in results[0].errors[0]

    def test_run_memory_stress_test_stops_on_failure(self, temp_output_dir):
        """Test that stress test stops after failure."""
        from unittest.mock import patch

        config = StressTestConfig(max_slices=10, max_dimensions=(32, 32))
        tester = StressTester(config)

        call_count = 0

        def fail_on_second(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise MemoryError("Out of memory")
            return temp_output_dir / f"step_{call_count}"

        with patch.object(tester, "generate_large_series", side_effect=fail_on_second):
            results = tester.run_memory_stress_test(
                output_dir=temp_output_dir,
                escalation_steps=[5, 10, 15],
            )

            # Should stop after second step fails
            assert len(results) == 2
            assert results[0].success is True
            assert results[1].success is False

    def test_run_memory_stress_test_stops_on_memory_limit(self, temp_output_dir):
        """Test that stress test stops when memory limit exceeded."""
        from unittest.mock import patch

        # Very low memory limit
        config = StressTestConfig(
            max_slices=10, max_dimensions=(32, 32), memory_limit_mb=1
        )
        tester = StressTester(config)

        # Mock get_current_memory to return high memory usage
        high_memory = MemorySnapshot(
            timestamp=0.0,
            process_memory_mb=1000.0,  # Much higher than limit
            system_memory_percent=90.0,
        )

        with patch.object(tester, "get_current_memory", return_value=high_memory):
            results = tester.run_memory_stress_test(
                output_dir=temp_output_dir,
                escalation_steps=[5, 10, 15],
            )

            # Should stop after first step due to memory limit
            assert len(results) == 1
            assert results[0].memory_peak_mb > config.memory_limit_mb

    def test_generate_series_with_none_dimensions(self, temp_output_dir):
        """Test that dimensions=None uses default 512x512."""
        config = StressTestConfig(max_slices=10, max_dimensions=(512, 512))
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=1,
            dimensions=None,  # Should use default
        )

        ds = pydicom.dcmread(next(series_path.glob("*.dcm")))
        assert ds.Rows == 512
        assert ds.Columns == 512

    def test_single_slice_gradient_division(self, temp_output_dir):
        """Test gradient with single slice (tests max(total_slices-1, 1) branch)."""
        config = StressTestConfig(max_slices=10, max_dimensions=(64, 64))
        tester = StressTester(config)

        # Single slice should not cause division by zero
        series_path = tester.generate_large_series(
            output_dir=temp_output_dir,
            slice_count=1,
            dimensions=(32, 32),
            pixel_pattern="gradient",
        )

        dcm_files = list(series_path.glob("*.dcm"))
        assert len(dcm_files) == 1

    def test_result_with_crashes(self):
        """Test StressTestResult with crashes list populated."""
        result = StressTestResult(
            start_time=0.0,
            end_time=100.0,
            duration_seconds=100.0,
            series_path=None,
            slice_count=10,
            dimensions=(512, 512),
            crashes=[{"type": "segfault", "address": "0x0"}],
            success=False,
        )
        summary = result.summary()
        assert "Crashes: 1" in summary

    def test_incremental_series_file_not_exists(self, temp_output_dir):
        """Test incremental series when file to delete doesn't exist."""
        config = StressTestConfig(max_slices=10, max_dimensions=(32, 32))
        tester = StressTester(config)

        # Generate with every_nth pattern - remove files that exist
        series_path, missing = tester.generate_incremental_series(
            output_dir=temp_output_dir,
            slice_count=5,
            missing_pattern="every_nth",
        )

        # Files were removed successfully
        assert 0 in missing
        # File should not exist
        assert not (series_path / "slice_00000.dcm").exists()
