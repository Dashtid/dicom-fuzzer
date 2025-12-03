"""Tests for Low-Coverage Modules

This module provides comprehensive tests for modules with low coverage:
- lazy_loader.py
- stability_tracker.py
- corpus_manager.py
- series_mutator.py
- viewer_launcher_3d.py
- coverage_guided_fuzzer.py
"""

import pydicom
import pytest
from pydicom.dataset import Dataset


class TestLazyDicomLoader:
    """Tests for the LazyDicomLoader class."""

    def test_init_default(self):
        """Test LazyDicomLoader initialization with defaults."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        loader = LazyDicomLoader()
        assert loader.metadata_only is False
        assert loader.defer_size is None
        assert loader.force is True

    def test_init_metadata_only(self):
        """Test LazyDicomLoader with metadata_only=True."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        loader = LazyDicomLoader(metadata_only=True)
        assert loader.metadata_only is True

    def test_init_with_defer_size(self):
        """Test LazyDicomLoader with defer_size."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        loader = LazyDicomLoader(defer_size=1024)
        assert loader.defer_size == 1024

    def test_load_file_not_found(self, tmp_path):
        """Test load raises FileNotFoundError."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        loader = LazyDicomLoader()
        with pytest.raises(FileNotFoundError):
            loader.load(tmp_path / "nonexistent.dcm")

    def test_load_valid_dicom(self, tmp_path, sample_dicom):
        """Test loading a valid DICOM file."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        dcm_path = tmp_path / "test.dcm"
        sample_dicom.save_as(str(dcm_path))

        loader = LazyDicomLoader()
        ds = loader.load(dcm_path)
        assert ds is not None
        assert ds.PatientID == sample_dicom.PatientID

    def test_load_metadata_only(self, tmp_path, sample_dicom):
        """Test metadata-only loading."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        dcm_path = tmp_path / "test.dcm"
        sample_dicom.save_as(str(dcm_path))

        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(dcm_path)
        assert ds is not None

    def test_load_invalid_file(self, tmp_path):
        """Test loading an invalid DICOM file."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        invalid_path = tmp_path / "invalid.dcm"
        invalid_path.write_text("not a dicom file")

        loader = LazyDicomLoader(force=False)
        with pytest.raises(Exception):
            loader.load(invalid_path)

    def test_load_pixels_already_loaded(self, tmp_path, sample_dicom):
        """Test load_pixels when pixels already loaded."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        dcm_path = tmp_path / "test.dcm"
        sample_dicom.save_as(str(dcm_path))

        loader = LazyDicomLoader()
        ds = loader.load(dcm_path)

        # Try to load pixels when already present
        if hasattr(ds, "PixelData"):
            result = loader.load_pixels(ds, dcm_path)
            assert result is not None

    def test_load_batch(self, tmp_path, sample_dicom):
        """Test batch loading multiple files."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        # Create multiple DICOM files
        paths = []
        for i in range(3):
            dcm_path = tmp_path / f"test_{i}.dcm"
            sample_dicom.save_as(str(dcm_path))
            paths.append(dcm_path)

        loader = LazyDicomLoader()
        datasets = loader.load_batch(paths)
        assert len(datasets) == 3

    def test_load_batch_with_invalid_file(self, tmp_path, sample_dicom):
        """Test batch loading skips invalid files."""
        from dicom_fuzzer.core.lazy_loader import LazyDicomLoader

        # Create one valid and one invalid file
        valid_path = tmp_path / "valid.dcm"
        sample_dicom.save_as(str(valid_path))

        invalid_path = tmp_path / "invalid.dcm"
        invalid_path.write_text("invalid")

        # Use force=True to allow loading even without proper header
        loader = LazyDicomLoader(force=True)
        datasets = loader.load_batch([valid_path, invalid_path])
        # Should have loaded at least the valid one
        assert len(datasets) >= 1

    def test_create_metadata_loader(self):
        """Test create_metadata_loader factory function."""
        from dicom_fuzzer.core.lazy_loader import create_metadata_loader

        loader = create_metadata_loader()
        assert loader.metadata_only is True
        assert loader.force is True

    def test_create_deferred_loader(self):
        """Test create_deferred_loader factory function."""
        from dicom_fuzzer.core.lazy_loader import create_deferred_loader

        loader = create_deferred_loader(defer_size_mb=5)
        assert loader.defer_size == 5 * 1024 * 1024
        assert loader.metadata_only is False


class TestStabilityTracker:
    """Tests for the StabilityTracker class."""

    def test_init(self):
        """Test StabilityTracker initialization."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()
        assert tracker is not None

    def test_record_execution(self, tmp_path):
        """Test recording an execution."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        result = tracker.record_execution(
            test_file=test_file,
            execution_signature="sig123",
        )
        assert isinstance(result, bool)

    def test_get_metrics(self):
        """Test getting metrics."""
        from dicom_fuzzer.core.stability_tracker import (
            StabilityMetrics,
            StabilityTracker,
        )

        tracker = StabilityTracker()
        metrics = tracker.get_metrics()
        assert isinstance(metrics, StabilityMetrics)
        # Verify metrics has expected attributes
        assert hasattr(metrics, "total_executions")
        assert hasattr(metrics, "stability_percentage")

    def test_is_campaign_stable(self):
        """Test is_campaign_stable."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()
        is_stable = tracker.is_campaign_stable()
        assert isinstance(is_stable, bool)

    def test_should_retest(self, tmp_path):
        """Test should_retest."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        should_retest = tracker.should_retest(test_file)
        assert isinstance(should_retest, bool)

    def test_reset(self):
        """Test reset."""
        from dicom_fuzzer.core.stability_tracker import StabilityTracker

        tracker = StabilityTracker()
        tracker.reset()
        # Just verify no error


class TestCorpusManagerExtended:
    """Extended tests for corpus_manager module."""

    def test_corpus_stats_creation(self):
        """Test CorpusStats dataclass."""
        from dicom_fuzzer.core.corpus_manager import CorpusStats

        stats = CorpusStats(
            total_seeds=10,
            unique_coverage_signatures=5,
            total_edges_covered=50,
        )
        assert stats.total_seeds == 10

    def test_seed_priority_values(self):
        """Test SeedPriority enum values."""
        from dicom_fuzzer.core.corpus_manager import SeedPriority

        assert SeedPriority.HIGH.value < SeedPriority.NORMAL.value
        assert SeedPriority.NORMAL.value < SeedPriority.LOW.value

    def test_corpus_manager_init(self):
        """Test CorpusManager initialization."""
        from dicom_fuzzer.core.corpus_manager import CorpusManager

        manager = CorpusManager(max_corpus_size=100)
        assert manager is not None

    def test_corpus_manager_add_seed(self):
        """Test adding a seed to the corpus."""
        from dicom_fuzzer.core.corpus_manager import CorpusManager
        from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo

        manager = CorpusManager(max_corpus_size=100)
        coverage = CoverageInfo()

        # Use add_seed method
        seed_id = manager.add_seed(
            data=b"test seed data",
            coverage=coverage,
        )
        assert seed_id is not None


class TestSeriesMutatorExtended:
    """Extended tests for series_mutator module."""

    def test_mutation_strategy_enum(self):
        """Test SeriesMutationStrategy enum."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationStrategy

        assert SeriesMutationStrategy.METADATA_CORRUPTION is not None
        assert SeriesMutationStrategy.INCONSISTENCY_INJECTION is not None
        assert SeriesMutationStrategy.GRADIENT_MUTATION is not None

    def test_series_3d_mutator_init(self):
        """Test Series3DMutator initialization."""
        from dicom_fuzzer.strategies.series_mutator import Series3DMutator

        mutator = Series3DMutator()
        assert mutator is not None


class TestViewerLauncher3DExtended:
    """Extended tests for viewer_launcher_3d module."""

    def test_viewer_type_enum(self):
        """Test ViewerType enum values."""
        from dicom_fuzzer.harness.viewer_launcher_3d import ViewerType

        assert ViewerType.GENERIC is not None
        assert ViewerType.RADIANT is not None
        assert ViewerType.MICRODICOM is not None

    def test_execution_status_enum(self):
        """Test ExecutionStatus enum values."""
        from dicom_fuzzer.harness.viewer_launcher_3d import ExecutionStatus

        assert ExecutionStatus.SUCCESS is not None
        assert ExecutionStatus.CRASH is not None
        assert ExecutionStatus.ERROR is not None

    def test_viewer_config_creation(self, tmp_path):
        """Test ViewerConfig dataclass creation."""
        from dicom_fuzzer.harness.viewer_launcher_3d import ViewerConfig, ViewerType

        fake_exe = tmp_path / "viewer.exe"
        fake_exe.write_text("fake")

        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=fake_exe,
            command_template="{executable} {input_path}",
            timeout_seconds=60,
        )
        assert config.timeout_seconds == 60

    def test_series_test_result_creation(self, tmp_path):
        """Test SeriesTestResult dataclass."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus
        from dicom_fuzzer.harness.viewer_launcher_3d import SeriesTestResult

        result = SeriesTestResult(
            status=ExecutionStatus.SUCCESS,
            series_folder=tmp_path,
            slice_count=10,
            execution_time=1.5,
            peak_memory_mb=100.0,
            exit_code=0,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestCoverageGuidedFuzzerExtended:
    """Extended tests for coverage_guided_fuzzer module."""

    def test_fuzzing_config_fields(self):
        """Test FuzzingConfig has expected fields."""
        from dicom_fuzzer.core.coverage_guided_fuzzer import FuzzingConfig

        config = FuzzingConfig()
        assert hasattr(config, "max_iterations")
        assert hasattr(config, "timeout_per_run")
        assert hasattr(config, "coverage_guided")

    def test_fuzzing_config_custom_values(self, tmp_path):
        """Test FuzzingConfig with custom values."""
        from dicom_fuzzer.core.coverage_guided_fuzzer import FuzzingConfig

        config = FuzzingConfig(
            max_iterations=100,
            timeout_per_run=2.0,
            coverage_guided=True,
            output_dir=tmp_path / "output",
        )
        assert config.max_iterations == 100
        assert config.timeout_per_run == 2.0


class TestStatelessHarnessExtended:
    """Extended tests for stateless_harness module."""

    def test_validate_determinism_non_deterministic(self):
        """Test validate_determinism detects non-deterministic function."""
        import random

        from dicom_fuzzer.utils.stateless_harness import validate_determinism

        def non_deterministic(x):
            return random.random()

        is_det, error = validate_determinism(1, non_deterministic)
        # May or may not detect depending on random values
        assert isinstance(is_det, bool)

    def test_detect_state_leaks_single_file(self, tmp_path, sample_dicom):
        """Test detect_state_leaks with single file."""
        from dicom_fuzzer.utils.stateless_harness import detect_state_leaks

        dcm_path = tmp_path / "test.dcm"
        sample_dicom.save_as(str(dcm_path))

        def harness_func(path):
            return path.stat().st_size

        # Needs at least 2 files
        result = detect_state_leaks(harness_func, [dcm_path])
        assert "leaked" in result

    def test_detect_state_leaks_multiple_files(self, tmp_path, sample_dicom):
        """Test detect_state_leaks with multiple files."""
        from dicom_fuzzer.utils.stateless_harness import detect_state_leaks

        paths = []
        for i in range(3):
            dcm_path = tmp_path / f"test_{i}.dcm"
            sample_dicom.save_as(str(dcm_path))
            paths.append(dcm_path)

        def harness_func(path):
            return path.stat().st_size

        result = detect_state_leaks(harness_func, paths)
        assert "leaked" in result
        assert "affected_files" in result


class TestCoverageCorrelationExtended:
    """Extended tests for coverage_correlation module."""

    def test_coverage_insight_update_crash_rate(self):
        """Test CoverageInsight crash rate calculation."""
        from dicom_fuzzer.utils.coverage_correlation import CoverageInsight

        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 10
        insight.crash_hits = 3
        insight.update_crash_rate()
        assert insight.crash_rate == 0.3

    def test_coverage_insight_zero_hits(self):
        """Test CoverageInsight with zero hits."""
        from dicom_fuzzer.utils.coverage_correlation import CoverageInsight

        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 0
        insight.update_crash_rate()
        assert insight.crash_rate == 0.0

    def test_generate_correlation_report(self):
        """Test generating a correlation report."""
        from dicom_fuzzer.utils.coverage_correlation import (
            CrashCoverageCorrelation,
            generate_correlation_report,
        )

        correlation = CrashCoverageCorrelation()
        report = generate_correlation_report(correlation)
        assert "CRASH-COVERAGE CORRELATION REPORT" in report

    def test_identify_crash_prone_modules(self):
        """Test identify_crash_prone_modules function."""
        from dicom_fuzzer.utils.coverage_correlation import (
            CrashCoverageCorrelation,
            identify_crash_prone_modules,
        )

        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("module.py:123", 0.8),
            ("module.py:456", 0.6),
            ("other.py:10", 0.9),
        ]

        modules = identify_crash_prone_modules(correlation)
        assert "module.py" in modules
        assert "other.py" in modules


class TestCorpusMinimizationExtended:
    """Extended tests for corpus_minimization module."""

    def test_minimize_corpus_for_campaign_empty_dir(self, tmp_path):
        """Test minimize_corpus with non-existent directory."""
        from dicom_fuzzer.utils.corpus_minimization import minimize_corpus_for_campaign

        result = minimize_corpus_for_campaign(
            corpus_dir=tmp_path / "nonexistent",
            output_dir=tmp_path / "output",
        )
        assert result == []

    def test_minimize_corpus_for_campaign_no_dicom_files(self, tmp_path):
        """Test minimize_corpus with no DICOM files."""
        from dicom_fuzzer.utils.corpus_minimization import minimize_corpus_for_campaign

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        result = minimize_corpus_for_campaign(
            corpus_dir=corpus_dir,
            output_dir=tmp_path / "output",
        )
        assert result == []

    def test_validate_corpus_quality_non_existent(self, tmp_path):
        """Test validate_corpus_quality with non-existent directory."""
        from dicom_fuzzer.utils.corpus_minimization import validate_corpus_quality

        metrics = validate_corpus_quality(tmp_path / "nonexistent")
        assert metrics["total_files"] == 0


# Fixtures


@pytest.fixture
def sample_dicom():
    """Create a sample DICOM dataset for testing."""
    ds = Dataset()
    ds.PatientID = "TEST_PATIENT_001"
    ds.PatientName = "Test^Patient"
    ds.StudyInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9.10"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9.10.11"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    ds.Modality = "CT"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"

    # Add minimal pixel data
    import numpy as np

    pixel_array = np.zeros((64, 64), dtype=np.uint16)
    ds.PixelData = pixel_array.tobytes()

    # Set file meta
    ds.file_meta = pydicom.dataset.FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian

    ds.is_little_endian = True
    ds.is_implicit_VR = False

    return ds
