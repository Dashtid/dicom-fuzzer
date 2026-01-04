"""Integration Tests for v1.7.0 Stress Testing Workflows

Tests the StressTester integration for large series generation,
memory estimation, and stress test campaign execution.
"""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestStressTesterConfig:
    """Test StressTestConfig validation and defaults."""

    def test_default_config(self):
        """Test default configuration values."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig

        config = StressTestConfig()

        assert config.max_slices == 1000
        assert config.max_dimensions == (2048, 2048)
        assert config.bits_allocated == 16
        assert config.memory_limit_mb == 4096

    def test_custom_config(self):
        """Test custom configuration."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig

        config = StressTestConfig(
            max_slices=500,
            max_dimensions=(1024, 1024),
            memory_limit_mb=2048,
        )

        assert config.max_slices == 500
        assert config.max_dimensions == (1024, 1024)
        assert config.memory_limit_mb == 2048


class TestStressTesterIntegration:
    """Integration tests for StressTester workflows."""

    def test_stress_tester_initialization(self):
        """Test StressTester initialization with config."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig(max_slices=100)
        tester = StressTester(config)

        assert tester is not None
        assert tester.config.max_slices == 100

    def test_generate_small_series(self, temp_dir):
        """Test generating a small series (5 slices)."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig(max_slices=100)
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_dir,
            slice_count=5,
            dimensions=(64, 64),
            pixel_pattern="gradient",
        )

        assert series_path.exists()
        dcm_files = list(series_path.glob("*.dcm"))
        assert len(dcm_files) == 5

    def test_generate_series_with_different_patterns(self, temp_dir):
        """Test series generation with different pixel patterns."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        for pattern in ["gradient", "random"]:
            output_dir = temp_dir / f"series_{pattern}"
            output_dir.mkdir()

            series_path = tester.generate_large_series(
                output_dir=output_dir,
                slice_count=3,
                dimensions=(32, 32),
                pixel_pattern=pattern,
            )

            assert series_path.exists()
            dcm_files = list(series_path.glob("*.dcm"))
            assert len(dcm_files) == 3

    def test_generate_series_with_modalities(self, temp_dir):
        """Test series generation with different modalities."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        for modality in ["CT", "MR", "PT"]:
            output_dir = temp_dir / f"series_{modality}"
            output_dir.mkdir()

            series_path = tester.generate_large_series(
                output_dir=output_dir,
                slice_count=2,
                dimensions=(32, 32),
                modality=modality,
            )

            # Verify modality in generated files
            import pydicom

            dcm_files = list(series_path.glob("*.dcm"))
            assert len(dcm_files) > 0

            ds = pydicom.dcmread(str(dcm_files[0]))
            assert ds.Modality == modality


class TestMemoryEstimation:
    """Test memory usage estimation functionality."""

    def test_memory_estimation_basic(self):
        """Test basic memory estimation."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        estimate = tester.estimate_memory_usage(slice_count=100, dimensions=(512, 512))

        assert "slice_mb" in estimate
        assert "series_pixel_data_mb" in estimate
        assert "estimated_viewer_mb" in estimate
        assert estimate["slice_mb"] > 0
        assert estimate["series_pixel_data_mb"] > 0

    def test_memory_estimation_large_series(self):
        """Test memory estimation for large series."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        small_estimate = tester.estimate_memory_usage(
            slice_count=10, dimensions=(256, 256)
        )

        large_estimate = tester.estimate_memory_usage(
            slice_count=100, dimensions=(512, 512)
        )

        # Large series should require more memory
        assert (
            large_estimate["series_pixel_data_mb"]
            > small_estimate["series_pixel_data_mb"]
        )

    def test_memory_estimation_high_resolution(self):
        """Test memory estimation for high resolution slices."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        low_res = tester.estimate_memory_usage(slice_count=10, dimensions=(256, 256))
        high_res = tester.estimate_memory_usage(slice_count=10, dimensions=(1024, 1024))

        # Higher resolution should require more memory per slice
        assert high_res["slice_mb"] > low_res["slice_mb"]


class TestStressTestResults:
    """Test StressTestResult data structure."""

    def test_result_summary(self):
        """Test result summary generation."""
        from dicom_fuzzer.harness.stress_tester import StressTestResult

        result = StressTestResult(
            start_time=0.0,
            end_time=10.0,
            duration_seconds=10.0,
            series_path=None,
            slice_count=100,
            dimensions=(512, 512),
            memory_peak_mb=256.0,
            success=True,
        )

        summary = result.summary()
        assert "Duration" in summary
        assert "Slices: 100" in summary
        assert "Memory Peak" in summary


class TestMemoryStressTestCampaign:
    """Test memory stress test campaign execution."""

    def test_run_memory_stress_test_small(self, temp_dir):
        """Test running a small memory stress test campaign."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig(
            max_slices=50,
            max_dimensions=(64, 64),
            memory_limit_mb=512,
        )
        tester = StressTester(config)

        # Run with minimal escalation steps
        results = tester.run_memory_stress_test(
            output_dir=temp_dir,
            escalation_steps=[5, 10],
        )

        # May return 1 result if first step fails (loop breaks on failure),
        # or 2 if both steps complete
        assert 1 <= len(results) <= 2
        for result in results:
            assert result.duration_seconds >= 0
            assert result.slice_count > 0

    def test_stress_test_escalation_pattern(self, temp_dir):
        """Test that escalation steps increase slice counts."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig(max_slices=100, max_dimensions=(32, 32))
        tester = StressTester(config)

        steps = [3, 6, 9]
        results = tester.run_memory_stress_test(
            output_dir=temp_dir,
            escalation_steps=steps,
        )

        assert len(results) == len(steps)
        for i, result in enumerate(results):
            assert result.slice_count == steps[i]


class TestGeneratedDicomValidity:
    """Test that generated DICOM files are valid."""

    def test_generated_files_readable(self, temp_dir):
        """Test that generated files can be read by pydicom."""
        import pydicom

        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_dir,
            slice_count=3,
            dimensions=(64, 64),
        )

        dcm_files = list(series_path.glob("*.dcm"))
        for f in dcm_files:
            ds = pydicom.dcmread(str(f))
            assert ds is not None
            assert hasattr(ds, "PixelData")
            assert ds.Rows == 64
            assert ds.Columns == 64

    def test_generated_files_have_consistent_series_uid(self, temp_dir):
        """Test that all slices share the same SeriesInstanceUID."""
        import pydicom

        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_dir,
            slice_count=5,
            dimensions=(32, 32),
        )

        dcm_files = list(series_path.glob("*.dcm"))
        series_uids = set()
        study_uids = set()

        for f in dcm_files:
            ds = pydicom.dcmread(str(f))
            series_uids.add(ds.SeriesInstanceUID)
            study_uids.add(ds.StudyInstanceUID)

        # All slices should share one SeriesInstanceUID and StudyInstanceUID
        assert len(series_uids) == 1
        assert len(study_uids) == 1

    def test_generated_files_have_correct_slice_positions(self, temp_dir):
        """Test that slice positions are correctly ordered."""
        import pydicom

        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        series_path = tester.generate_large_series(
            output_dir=temp_dir,
            slice_count=5,
            dimensions=(32, 32),
        )

        dcm_files = sorted(series_path.glob("*.dcm"))
        positions = []

        for f in dcm_files:
            ds = pydicom.dcmread(str(f))
            if hasattr(ds, "SliceLocation"):
                positions.append(float(ds.SliceLocation))

        # Positions should be ordered
        if positions:
            assert positions == sorted(positions)


class TestStressTesterEdgeCases:
    """Test edge cases and error handling."""

    def test_zero_slices_handling(self, temp_dir):
        """Test handling of zero slice count - generates empty directory."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        # Zero slices generates empty series directory (graceful handling)
        series_path = tester.generate_large_series(
            output_dir=temp_dir,
            slice_count=0,
            dimensions=(64, 64),
        )

        # Should create directory but with no files
        assert series_path.exists()
        dcm_files = list(series_path.glob("*.dcm"))
        assert len(dcm_files) == 0

    def test_output_dir_creation(self, temp_dir):
        """Test that output directories are created if they don't exist."""
        from dicom_fuzzer.harness.stress_tester import StressTestConfig, StressTester

        config = StressTestConfig()
        tester = StressTester(config)

        nested_dir = temp_dir / "nested" / "output" / "dir"

        series_path = tester.generate_large_series(
            output_dir=nested_dir,
            slice_count=2,
            dimensions=(32, 32),
        )

        assert series_path.exists()
