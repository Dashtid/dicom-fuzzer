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

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.series.parallel_mutator import (
    ParallelSeriesMutator,
    get_optimal_workers,
)
from dicom_fuzzer.attacks.series.series_mutator import SeriesMutationStrategy
from dicom_fuzzer.core.dicom.series import DicomSeries


@pytest.fixture
def sample_series(tmp_path):
    """Create a sample DICOM series for testing."""
    series_uid = generate_uid()
    study_uid = generate_uid()
    slice_paths = []

    for i in range(10):  # 10 slices
        # Create file meta
        file_meta = FileMetaDataset()
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
        study_uid=study_uid,
        modality="CT",
        slices=slice_paths,
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

    @pytest.mark.flaky(reruns=2, reruns_delay=1)
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
        mutator1 = ParallelSeriesMutator(workers=2, seed=42, severity="moderate")
        mutator2 = ParallelSeriesMutator(workers=2, seed=99, severity="moderate")

        # Run multiple times to account for probabilistic mutations
        differences_found = 0
        for _ in range(5):
            mutated1, _ = mutator1.mutate_series_parallel(
                sample_series, SeriesMutationStrategy.GRADIENT_MUTATION
            )

            mutated2, _ = mutator2.mutate_series_parallel(
                sample_series, SeriesMutationStrategy.GRADIENT_MUTATION
            )

            # Check if any slices differ
            for ds1, ds2 in zip(mutated1, mutated2):
                if hasattr(ds1, "ImagePositionPatient") and hasattr(
                    ds2, "ImagePositionPatient"
                ):
                    if ds1.ImagePositionPatient != ds2.ImagePositionPatient:
                        differences_found += 1
                        break
                if hasattr(ds1, "SliceLocation") and hasattr(ds2, "SliceLocation"):
                    if ds1.SliceLocation != ds2.SliceLocation:
                        differences_found += 1
                        break

        # Should find differences in at least 2 out of 5 runs
        assert differences_found >= 2, (
            f"Different seeds should produce different mutations (found {differences_found}/5 different)"
        )


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
        file_meta = FileMetaDataset()
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
        ds.save_as(file_path, write_like_original=False)

        single_series = DicomSeries(
            series_uid=series_uid,
            study_uid=ds.StudyInstanceUID,
            modality="CT",
            slices=[file_path],
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


# ============================================================================
# In-process tests for _mutate_single_slice worker (subprocess coverage gap)
# ============================================================================
#
# pytest-cov does not instrument ProcessPoolExecutor worker processes, so the
# existing tests that drive _mutate_single_slice through mutate_series_parallel
# leave it as uncovered statements in the merged coverage report even though
# the code does execute. Calling the worker directly from the test process
# exercises the same code path under coverage instrumentation.


class TestMutateSingleSliceDirect:
    """Drive _mutate_single_slice in-process to close the subprocess coverage gap."""

    def test_happy_path_returns_mutated_dataset(self, sample_series):
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        idx, ds, records = _mutate_single_slice(
            file_path=sample_series.slices[0],
            slice_index=0,
            strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
            severity="moderate",
            seed=42,
        )

        assert idx == 0
        assert ds is not None
        # SLICE_POSITION_ATTACK modifies something on most runs; don't assert
        # records are non-empty since randomness can produce 0.

    def test_no_seed_skips_per_slice_offset(self, sample_series):
        """seed=None -> slice_seed stays None (no ``seed + slice_index``)."""
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        idx, ds, _ = _mutate_single_slice(
            file_path=sample_series.slices[1],
            slice_index=1,
            strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
            severity="moderate",
            seed=None,
        )

        assert idx == 1
        assert ds is not None

    def test_boundary_target_first_matches(self, sample_series):
        """target=first with slice_index=0 -> mutation applied."""
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        idx, ds, _ = _mutate_single_slice(
            file_path=sample_series.slices[0],
            slice_index=0,
            strategy=SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value,
            severity="moderate",
            seed=42,
            total_slices=10,
            target="first",
        )

        assert idx == 0
        assert ds is not None

    def test_boundary_target_last_matches(self, sample_series):
        """target=last with slice_index=total_slices-1 -> mutation applied."""
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        idx, ds, _ = _mutate_single_slice(
            file_path=sample_series.slices[-1],
            slice_index=9,
            strategy=SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value,
            severity="moderate",
            seed=42,
            total_slices=10,
            target="last",
        )

        assert idx == 9
        assert ds is not None

    def test_boundary_target_middle_matches(self, sample_series):
        """target=middle with slice_index==total_slices//2 -> mutation applied."""
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        idx, ds, _ = _mutate_single_slice(
            file_path=sample_series.slices[5],
            slice_index=5,
            strategy=SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value,
            severity="moderate",
            seed=42,
            total_slices=10,
            target="middle",
        )

        assert idx == 5
        assert ds is not None

    def test_boundary_non_boundary_returns_early_with_empty_records(
        self, sample_series
    ):
        """Non-boundary slice (index 3, target=first, total_slices=10) -> no mutation."""
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        idx, ds, records = _mutate_single_slice(
            file_path=sample_series.slices[3],
            slice_index=3,
            strategy=SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value,
            severity="moderate",
            seed=42,
            total_slices=10,
            target="first",
        )

        assert idx == 3
        assert ds is not None
        assert records == []  # early-return branch

    def test_dataset_without_series_uid_falls_back_to_generated(self, tmp_path):
        """DICOM missing SeriesInstanceUID / StudyInstanceUID / Modality.

        Hits the hasattr-False branches when pulling metadata out of the
        slice for the temp DicomSeries.
        """
        from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
        from pydicom.uid import generate_uid

        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset("minimal.dcm", {}, file_meta=file_meta, preamble=b"\0" * 128)
        # Deliberately do NOT set SeriesInstanceUID / StudyInstanceUID / Modality.
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.is_implicit_VR = True
        ds.is_little_endian = True
        ds.Rows = 16
        ds.Columns = 16
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.PixelRepresentation = 0
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = b"\x00" * (16 * 16 * 2)
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]

        path = tmp_path / "bare.dcm"
        ds.save_as(str(path), write_like_original=False)
        assert isinstance(ds, Dataset)  # silence unused-import warning

        idx, out, _ = _mutate_single_slice(
            file_path=path,
            slice_index=0,
            strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
            severity="moderate",
            seed=42,
        )

        assert idx == 0
        assert out is not None

    def test_missing_file_hits_exception_branch(self, tmp_path):
        """Unreadable file makes pydicom.dcmread raise -> generic except block.

        The worker catches, logs, and tries to re-read the same file to return
        the 'original'. With a non-existent file the re-read also raises,
        which propagates out (we don't swallow inside the test).
        """
        from dicom_fuzzer.attacks.series.parallel_mutator import _mutate_single_slice

        ghost = tmp_path / "does_not_exist.dcm"

        # Either FileNotFoundError from pydicom OR InvalidDicomError if something
        # weird happens -- either way the except branch at 129-133 has executed.
        with pytest.raises(Exception):
            _mutate_single_slice(
                file_path=ghost,
                slice_index=0,
                strategy=SeriesMutationStrategy.SLICE_POSITION_ATTACK.value,
                severity="moderate",
                seed=42,
            )


class TestGetOptimalWorkersBranches:
    """Cover the three branches of get_optimal_workers (325-330)."""

    def test_low_cpu_count_returns_one(self, monkeypatch):
        from dicom_fuzzer.attacks.series import parallel_mutator

        monkeypatch.setattr(parallel_mutator.multiprocessing, "cpu_count", lambda: 2)
        assert parallel_mutator.get_optimal_workers() == 1

    def test_medium_cpu_count_leaves_one_core(self, monkeypatch):
        from dicom_fuzzer.attacks.series import parallel_mutator

        monkeypatch.setattr(parallel_mutator.multiprocessing, "cpu_count", lambda: 4)
        assert parallel_mutator.get_optimal_workers() == 3

    def test_high_cpu_count_leaves_two_cores(self, monkeypatch):
        from dicom_fuzzer.attacks.series import parallel_mutator

        monkeypatch.setattr(parallel_mutator.multiprocessing, "cpu_count", lambda: 16)
        assert parallel_mutator.get_optimal_workers() == 14


class TestParallelLoopFutureFailure:
    """Cover the exception handler inside the as_completed loop (247-253)."""

    def test_future_result_exception_falls_back_to_original(
        self, sample_series, monkeypatch
    ):
        """If future.result() raises, the loop logs, re-reads original.

        Drive this by monkeypatching ProcessPoolExecutor.submit so the future
        it returns has a broken .result() method.
        """
        from concurrent.futures import Future

        from dicom_fuzzer.attacks.series import parallel_mutator as mod

        class _BrokenPool:
            def __init__(self, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def submit(self, _fn, _path, idx, *_args, **_kwargs):
                future: Future = Future()
                future.set_exception(RuntimeError(f"worker {idx} died"))
                return future

        monkeypatch.setattr(mod, "ProcessPoolExecutor", _BrokenPool)

        mutator = mod.ParallelSeriesMutator(workers=2, seed=42)
        datasets, records = mutator.mutate_series_parallel(
            sample_series, SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING
        )

        # Every slice came back via the fallback pydicom.dcmread branch.
        assert len(datasets) == sample_series.slice_count
        # No records because every worker "failed".
        assert records == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
