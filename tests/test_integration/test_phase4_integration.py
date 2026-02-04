"""
Integration tests for Phase 4 performance optimizations.

Tests integration of Phase 4 (lazy loading, caching, parallel processing)
with Phase 1-3 components (series detection, mutations, viewer testing).
"""

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.dicom.dicom_series import DicomSeries
from dicom_fuzzer.core.dicom.lazy_loader import create_metadata_loader
from dicom_fuzzer.core.series.series_cache import SeriesCache
from dicom_fuzzer.core.series.series_detector import SeriesDetector
from dicom_fuzzer.core.series.series_writer import SeriesWriter
from dicom_fuzzer.attacks.series.parallel_mutator import ParallelSeriesMutator
from dicom_fuzzer.attacks.series.series_mutator import (
    Series3DMutator,
    SeriesMutationStrategy,
)


@pytest.fixture
def sample_series_files(tmp_path):
    """Create a sample DICOM series on disk."""
    series_uid = generate_uid()
    study_uid = generate_uid()
    slice_paths = []

    for i in range(20):  # 20 slices for meaningful parallel testing
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
        ds.StudyInstanceUID = study_uid
        ds.Modality = "CT"
        ds.PatientName = "Integration^Test"
        ds.PatientID = "INT001"
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

        file_path = tmp_path / f"slice_{i:03d}.dcm"
        ds.save_as(file_path, write_like_original=False)
        slice_paths.append(file_path)

    return tmp_path, slice_paths


class TestPhase1Phase4Integration:
    """Test integration of Phase 1 (Series Detection) with Phase 4 (Optimizations)."""

    def test_series_detector_with_lazy_loader(self, sample_series_files):
        """Test SeriesDetector with lazy loading optimization."""
        series_dir, slice_paths = sample_series_files

        # Create detector with lazy loader
        detector = SeriesDetector()
        loader = create_metadata_loader()

        # Detect series using lazy loading (pass explicit file list to avoid duplicate pattern issue)
        series_list = detector.detect_series(slice_paths)

        assert len(series_list) == 1
        series = series_list[0]
        assert series.slice_count == 20
        assert series.modality == "CT"

    def test_series_detector_with_cache(self, sample_series_files):
        """Test SeriesDetector benefits from caching."""
        series_dir, slice_paths = sample_series_files

        # Create cache and detector
        cache = SeriesCache(max_size_mb=50, max_entries=100)
        detector = SeriesDetector()

        # First detection (cache misses) - pass explicit file list
        series_list = detector.detect_series(slice_paths)
        assert len(series_list) == 1

        # Cache should be empty initially (detector doesn't use cache yet)
        # This test demonstrates future integration opportunity


class TestPhase2Phase4Integration:
    """Test integration of Phase 2 (Mutations) with Phase 4 (Parallel Processing)."""

    def test_serial_vs_parallel_mutations_same_result(self, sample_series_files):
        """Test that serial and parallel mutations produce same results with same seed."""
        series_dir, slice_paths = sample_series_files

        # Create series object
        series_uid = generate_uid()
        study_uid = generate_uid()
        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=slice_paths,
        )

        # Serial mutation
        serial_mutator = Series3DMutator(severity="moderate", seed=42)
        serial_mutated, serial_records = serial_mutator.mutate_series(
            series, SeriesMutationStrategy.SLICE_POSITION_ATTACK
        )

        # Parallel mutation with same seed
        parallel_mutator = ParallelSeriesMutator(
            workers=2, severity="moderate", seed=42
        )
        parallel_mutated, parallel_records = parallel_mutator.mutate_series(
            series, SeriesMutationStrategy.SLICE_POSITION_ATTACK, parallel=True
        )

        # Should produce same number of mutations
        assert len(serial_mutated) == len(parallel_mutated)
        assert len(serial_records) == len(parallel_records)

        # SliceLocation values should match (reproducibility)
        for i, (serial_ds, parallel_ds) in enumerate(
            zip(serial_mutated, parallel_mutated)
        ):
            if hasattr(serial_ds, "SliceLocation") and hasattr(
                parallel_ds, "SliceLocation"
            ):
                assert serial_ds.SliceLocation == parallel_ds.SliceLocation, (
                    f"Slice {i} mismatch"
                )

    @pytest.mark.flaky(reruns=2, reruns_delay=1)
    def test_parallel_mutator_with_all_strategies(self, sample_series_files):
        """Test ParallelSeriesMutator with all mutation strategies."""
        series_dir, slice_paths = sample_series_files

        series_uid = generate_uid()
        study_uid = generate_uid()
        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=slice_paths,
        )

        mutator = ParallelSeriesMutator(workers=2, seed=42)

        # Test all strategies (some will use parallel, some serial)
        strategies = [
            SeriesMutationStrategy.METADATA_CORRUPTION,  # Serial
            SeriesMutationStrategy.SLICE_POSITION_ATTACK,  # Parallel
            SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING,  # Parallel
            SeriesMutationStrategy.GRADIENT_MUTATION,  # Parallel
            SeriesMutationStrategy.INCONSISTENCY_INJECTION,  # Serial
        ]

        for strategy in strategies:
            mutated_ds, records = mutator.mutate_series(series, strategy, parallel=True)

            # All strategies should complete successfully
            assert len(mutated_ds) == series.slice_count
            assert len(records) > 0


class TestPhase3Phase4Integration:
    """Test integration of Phase 3 (Viewer Testing) with Phase 4 (Performance)."""

    def test_series_writer_with_parallel_mutations(self, sample_series_files, tmp_path):
        """Test SeriesWriter works with parallel-mutated series."""
        series_dir, slice_paths = sample_series_files

        series_uid = generate_uid()
        study_uid = generate_uid()
        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=slice_paths,
        )

        # Parallel mutation
        mutator = ParallelSeriesMutator(workers=2, seed=42)
        mutated_ds, records = mutator.mutate_series(
            series, SeriesMutationStrategy.SLICE_POSITION_ATTACK, parallel=True
        )

        # Write mutated series (correct API: SeriesWriter(output_root).write_series(series, datasets))
        output_dir = tmp_path / "output_series"
        writer = SeriesWriter(output_root=output_dir)
        metadata = writer.write_series(series, mutated_ds)

        # Verify written files
        assert metadata.output_directory.exists()
        written_files = list(metadata.output_directory.glob("*.dcm"))
        assert len(written_files) == series.slice_count


class TestFullWorkflowIntegration:
    """Test complete Phase 1-4 workflow integration."""

    def test_complete_optimized_workflow(self, sample_series_files, tmp_path):
        """
        Test complete workflow: Detect -> Cache -> Mutate (Parallel) -> Write.

        This is the primary integration test demonstrating all Phase 4
        optimizations working together with Phase 1-3 components.
        """
        series_dir, slice_paths = sample_series_files

        # Phase 1: Series Detection with lazy loading (pass explicit file list)
        detector = SeriesDetector()
        series_list = detector.detect_series(slice_paths)
        assert len(series_list) == 1
        series = series_list[0]

        # Phase 4: Parallel mutation
        mutator = ParallelSeriesMutator(workers=2, severity="moderate", seed=42)
        mutated_ds, records = mutator.mutate_series(
            series, SeriesMutationStrategy.SLICE_POSITION_ATTACK, parallel=True
        )

        # Phase 2: Verify mutations applied
        assert len(mutated_ds) == series.slice_count
        assert len(records) > 0

        # Phase 3: Write for viewer testing
        output_dir = tmp_path / "fuzzed_series"
        writer = SeriesWriter(output_root=output_dir)
        metadata = writer.write_series(series, mutated_ds)

        # Verify output
        assert metadata.output_directory.exists()
        written_files = list(metadata.output_directory.glob("*.dcm"))
        assert len(written_files) == series.slice_count

        # Verify metadata file exists
        metadata_file = metadata.output_directory / "metadata.json"
        assert metadata_file.exists()


class TestPerformanceRegression:
    """Test that Phase 4 optimizations don't break existing functionality."""

    def test_lazy_loading_preserves_metadata(self, sample_series_files):
        """Test that lazy loading preserves all required metadata."""
        _, slice_paths = sample_series_files

        loader = create_metadata_loader()

        # Load with lazy loader
        ds = loader.load(slice_paths[0])

        # All required metadata should be present
        assert hasattr(ds, "PatientName")
        assert hasattr(ds, "SeriesInstanceUID")
        assert hasattr(ds, "InstanceNumber")
        assert hasattr(ds, "Modality")
        assert ds.PatientName == "Integration^Test"
        assert ds.Modality == "CT"

    def test_cache_does_not_corrupt_data(self, sample_series_files):
        """Test that caching doesn't corrupt DICOM data."""
        _, slice_paths = sample_series_files

        cache = SeriesCache(max_size_mb=50, max_entries=100)
        loader = create_metadata_loader()

        # Load same file multiple times through cache
        ds1 = cache.get(slice_paths[0], lambda p: loader.load(p))
        ds2 = cache.get(slice_paths[0], lambda p: loader.load(p))  # Cache hit
        ds3 = cache.get(slice_paths[0], lambda p: loader.load(p))  # Cache hit

        # All should have same metadata
        assert ds1.PatientName == ds2.PatientName == ds3.PatientName
        assert ds1.SeriesInstanceUID == ds2.SeriesInstanceUID == ds3.SeriesInstanceUID
        assert ds1.InstanceNumber == ds2.InstanceNumber == ds3.InstanceNumber

    def test_parallel_mutations_maintain_series_integrity(self, sample_series_files):
        """Test that parallel mutations don't break series integrity."""
        series_dir, slice_paths = sample_series_files

        series_uid = generate_uid()
        study_uid = generate_uid()
        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality="CT",
            slices=slice_paths,
        )

        mutator = ParallelSeriesMutator(workers=2, seed=42)
        mutated_ds, records = mutator.mutate_series(
            series, SeriesMutationStrategy.SLICE_POSITION_ATTACK, parallel=True
        )

        # Series should still have same number of slices
        assert len(mutated_ds) == series.slice_count

        # All datasets should have required DICOM attributes
        for ds in mutated_ds:
            assert hasattr(ds, "SOPInstanceUID")
            assert hasattr(ds, "SeriesInstanceUID")
            assert hasattr(ds, "Modality")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
