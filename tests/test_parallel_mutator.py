"""
Tests for ParallelSeriesMutator (Performance Optimization Phase 4).

Tests parallel mutation strategies:
- Parallel slice processing with ProcessPoolExecutor
- Worker pool management
- Strategy-specific parallelization
- Reproducibility with seeding
- Performance characteristics
"""

import multiprocessing
from pathlib import Path

import pytest
from pydicom.dataset import Dataset, FileMetaInformationDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.strategies.parallel_mutator import (
    ParallelSeriesMutator,
    get_optimal_workers,
)
from dicom_fuzzer.strategies.series_mutator import SeriesMutationStrategy


@pytest.fixture
def sample_series(tmp_path):
    """Create a sample DICOM series for testing."""
    series_uid = generate_uid()
    study_uid = generate_uid()
    slice_paths = []

    for i in range(10):  # 10 slices
        # Create file meta
        file_meta = FileMetaInformationDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        # Create main dataset
        ds = Dataset()
        ds.file_meta = file_meta
        ds.is_implicit_VR = True
        ds.is_little_endian = True
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SeriesInstanceUID = series_uid
        ds.StudyInstanceUID = study_uid
        ds.Modality = "CT"
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.InstanceNumber = i + 1
        ds.ImagePositionPatient = [0.0, 0.0, float(i)]
        ds.SliceLocation = float(i)

        # Add pixel data
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.PixelRepresentation = 0
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = b"\x00" * (64 * 64 * 2)

        # Save to file
        file_path = tmp_path / f"slice_{i:03d}.dcm"
        ds.save_as(file_path, write_like_original=False)
        slice_paths.append(file_path)

    return DicomSeries(
        series_uid=series_uid,
        modality="CT",
        slices=slice_paths,
        metadata={
            "StudyInstanceUID": study_uid,
            "PatientName": "Test^Patient",
            "PatientID": "12345",
        },
    )


class TestGetOptimalWorkers:
    """Test get_optimal_workers helper function."""

    def test_returns_positive_integer(self):
        """Test that function returns positive integer."""
        workers = get_optimal_workers()
        assert isinstance(workers, int)
        assert workers > 0

    def test_leaves_cores_for_os(self):
        """Test that function leaves cores for OS/main process."""
        cpu_count = multiprocessing.cpu_count()
        workers = get_optimal_workers()

        if cpu_count <= 2:
            assert workers == 1
        elif cpu_count <= 4:
            assert workers == cpu_count - 1
        else:
            assert workers == cpu_count - 2


class TestParallelSeriesMutator:
    """Test ParallelSeriesMutator class."""

    def test_initialization_default_workers(self):
        """Test initialization with default worker count."""
        mutator = ParallelSeriesMutator()

        assert mutator.workers > 0
        assert mutator.severity == "moderate"
        assert mutator.seed is None

    def test_initialization_custom_workers(self):
        """Test initialization with custom worker count."""
        mutator = ParallelSeriesMutator(workers=4, severity="aggressive", seed=42)

        assert mutator.workers == 4
        assert mutator.severity == "aggressive"
        assert mutator.seed == 42

    def test_parallel_slice_position_attack(self, sample_series):
        """Test parallel SLICE_POSITION_ATTACK strategy."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        mutated_ds, records = mutator.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        # Should return mutated datasets
        assert len(mutated_ds) == sample_series.slice_count
        assert all(ds is not None for ds in mutated_ds)

        # Should have mutation records
        assert len(records) > 0

    def test_parallel_boundary_slice_targeting(self, sample_series):
        """Test parallel BOUNDARY_SLICE_TARGETING strategy."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        mutated_ds, records = mutator.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING
        )

        # Should return mutated datasets (only boundary slices mutated)
        assert len(mutated_ds) == sample_series.slice_count

        # Should have mutation records (only for boundary slices)
        assert len(records) > 0
        # Boundary targeting mutates first, middle, and last
        assert len(records) <= sample_series.slice_count

    def test_parallel_gradient_mutation(self, sample_series):
        """Test parallel GRADIENT_MUTATION strategy."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        mutated_ds, records = mutator.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.GRADIENT_MUTATION
        )

        # Should return mutated datasets
        assert len(mutated_ds) == sample_series.slice_count
        assert all(ds is not None for ds in mutated_ds)

        # Should have mutation records
        assert len(records) > 0

    def test_reproducibility_with_seed(self, sample_series):
        """Test that same seed produces same results."""
        mutator1 = ParallelSeriesMutator(workers=2, seed=42)
        mutator2 = ParallelSeriesMutator(workers=2, seed=42)

        mutated1, records1 = mutator1.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        mutated2, records2 = mutator2.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        # Same seed should produce same mutations
        # Compare SliceLocation values
        for ds1, ds2 in zip(mutated1, mutated2):
            if hasattr(ds1, "SliceLocation") and hasattr(ds2, "SliceLocation"):
                assert ds1.SliceLocation == ds2.SliceLocation

    def test_different_seeds_produce_different_results(self, sample_series):
        """Test that different seeds produce different results."""
        mutator1 = ParallelSeriesMutator(workers=2, seed=42)
        mutator2 = ParallelSeriesMutator(workers=2, seed=99)

        mutated1, _ = mutator1.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        mutated2, _ = mutator2.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        # Different seeds should produce different mutations
        different = False
        for ds1, ds2 in zip(mutated1, mutated2):
            if hasattr(ds1, "SliceLocation") and hasattr(ds2, "SliceLocation"):
                if ds1.SliceLocation != ds2.SliceLocation:
                    different = True
                    break

        assert different, "Different seeds should produce different mutations"


class TestMutateSeriesAutoDetection:
    """Test mutate_series with auto-detection of parallel vs serial."""

    def test_auto_parallel_for_large_series(self, sample_series):
        """Test auto-detection chooses parallel for large series."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # Series with 10 slices should use parallel (threshold is 10)
        mutated_ds, records = mutator.mutate_series(
            sample_series,
            SeriesMutationStrategy.SLICE_POSITION_ATTACK,
            parallel=True,
        )

        assert len(mutated_ds) == sample_series.slice_count
        assert len(records) > 0

    def test_force_serial_execution(self, sample_series):
        """Test forcing serial execution."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # Force serial
        mutated_ds, records = mutator.mutate_series(
            sample_series,
            SeriesMutationStrategy.SLICE_POSITION_ATTACK,
            parallel=False,
        )

        assert len(mutated_ds) == sample_series.slice_count
        assert len(records) > 0


class TestNonParallelizableStrategies:
    """Test strategies that require serial execution."""

    def test_metadata_corruption_fallback_to_serial(self, sample_series):
        """Test METADATA_CORRUPTION falls back to serial."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # METADATA_CORRUPTION requires series-level coordination
        mutated_ds, records = mutator.mutate_series(
            sample_series,
            SeriesMutationStrategy.METADATA_CORRUPTION,
            parallel=True,  # Will auto-fallback to serial
        )

        # Should still work (serial execution)
        assert len(mutated_ds) == sample_series.slice_count

    def test_inconsistency_injection_fallback_to_serial(self, sample_series):
        """Test INCONSISTENCY_INJECTION falls back to serial."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # INCONSISTENCY_INJECTION has cross-slice dependencies
        mutated_ds, records = mutator.mutate_series(
            sample_series,
            SeriesMutationStrategy.INCONSISTENCY_INJECTION,
            parallel=True,  # Will auto-fallback to serial
        )

        # Should still work (serial execution)
        assert len(mutated_ds) == sample_series.slice_count


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_single_slice_series(self, tmp_path):
        """Test parallel mutation with single-slice series."""
        # Create single-slice series
        series_uid = generate_uid()
        file_meta = FileMetaInformationDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        ds = Dataset()
        ds.file_meta = file_meta
        ds.is_implicit_VR = True
        ds.is_little_endian = True
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SeriesInstanceUID = series_uid
        ds.StudyInstanceUID = generate_uid()
        ds.Modality = "CT"
        ds.PatientName = "Single^Slice"
        ds.InstanceNumber = 1
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]

        # Add pixel data
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.PixelRepresentation = 0
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = b"\x00" * (64 * 64 * 2)

        file_path = tmp_path / "single.dcm"
        ds.save_as(file_path)

        single_series = DicomSeries(
            series_uid=series_uid,
            modality="CT",
            slices=[file_path],
            metadata={"StudyInstanceUID": ds.StudyInstanceUID},
        )

        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # Should handle single slice gracefully (will use serial)
        mutated_ds, records = mutator.mutate_series(
            single_series,
            SeriesMutationStrategy.SLICE_POSITION_ATTACK,
            parallel=False,  # Force serial for single slice
        )

        assert len(mutated_ds) == 1

    def test_zero_workers_raises_error(self):
        """Test that zero workers raises appropriate error."""
        with pytest.raises(ValueError):
            ParallelSeriesMutator(workers=0)


class TestPerformanceCharacteristics:
    """Test performance characteristics (qualitative)."""

    def test_parallel_completes_without_error(self, sample_series):
        """Test that parallel execution completes successfully."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # Should complete without raising exceptions
        mutated_ds, records = mutator.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        assert len(mutated_ds) == sample_series.slice_count
        assert len(records) > 0

    def test_serial_completes_without_error(self, sample_series):
        """Test that serial execution completes successfully."""
        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # Force serial
        mutated_ds, records = mutator._mutate_serial(
            sample_series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        assert len(mutated_ds) == sample_series.slice_count
        assert len(records) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
