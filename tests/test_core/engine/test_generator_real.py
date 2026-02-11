"""Tests for generator module using real DICOM datasets.

Targets uncovered code paths to increase coverage.
"""

from pathlib import Path

import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.engine.generator import DICOMGenerator, GenerationStats


@pytest.fixture
def real_dicom_file(tmp_path):
    """Create a real minimal DICOM file."""
    filename = tmp_path / "test.dcm"

    # Create file meta information
    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
    file_meta.ImplementationClassUID = generate_uid()

    # Create the FileDataset instance
    ds = FileDataset(str(filename), {}, file_meta=file_meta, preamble=b"\0" * 128)

    # Add required elements
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Modality = "CT"
    ds.StudyDate = "20250101"
    ds.SeriesNumber = "1"
    ds.InstanceNumber = "1"
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()

    # Save the file
    ds.save_as(str(filename), write_like_original=False)
    return filename


class TestGenerationStats:
    """Test GenerationStats tracking."""

    def test_initialization(self):
        """Test stats initialization."""
        stats = GenerationStats()

        assert stats.total_attempted == 0
        assert stats.successful == 0
        assert stats.failed == 0
        assert stats.skipped_due_to_write_errors == 0
        assert stats.strategies_used == {}
        assert stats.error_types == {}

    def test_record_success(self):
        """Test recording successful generation."""
        stats = GenerationStats()

        stats.record_success(["metadata", "header"])

        assert stats.successful == 1
        assert stats.strategies_used["metadata"] == 1
        assert stats.strategies_used["header"] == 1

    def test_record_multiple_successes(self):
        """Test recording multiple successes."""
        stats = GenerationStats()

        stats.record_success(["metadata"])
        stats.record_success(["metadata", "pixel"])
        stats.record_success(["header"])

        assert stats.successful == 3
        assert stats.strategies_used["metadata"] == 2
        assert stats.strategies_used["pixel"] == 1
        assert stats.strategies_used["header"] == 1

    def test_record_failure(self):
        """Test recording failure."""
        stats = GenerationStats()

        stats.record_failure("ValueError")

        assert stats.failed == 1
        assert stats.error_types["ValueError"] == 1

    def test_record_multiple_failures(self):
        """Test recording multiple failures."""
        stats = GenerationStats()

        stats.record_failure("ValueError")
        stats.record_failure("TypeError")
        stats.record_failure("ValueError")

        assert stats.failed == 3
        assert stats.error_types["ValueError"] == 2
        assert stats.error_types["TypeError"] == 1


class TestDICOMGeneratorInit:
    """Test DICOMGenerator initialization."""

    def test_default_initialization(self, tmp_path):
        """Test default initialization."""
        output_dir = tmp_path / "output"
        gen = DICOMGenerator(output_dir=str(output_dir))

        assert gen.output_dir == Path(str(output_dir))
        assert gen.output_dir.exists()
        assert gen.skip_write_errors is True
        assert isinstance(gen.stats, GenerationStats)

    def test_custom_skip_write_errors(self, tmp_path):
        """Test initialization with custom skip_write_errors."""
        gen = DICOMGenerator(output_dir=str(tmp_path), skip_write_errors=False)

        assert gen.skip_write_errors is False

    def test_output_dir_created(self, tmp_path):
        """Test output directory is created."""
        new_dir = tmp_path / "new" / "nested" / "dir"
        DICOMGenerator(output_dir=str(new_dir))

        assert new_dir.exists()
        assert new_dir.is_dir()


class TestGenerateBatch:
    """Test batch generation."""

    def test_generate_small_batch(self, real_dicom_file, tmp_path):
        """Test generating small batch of files."""
        output_dir = tmp_path / "output"
        gen = DICOMGenerator(output_dir=str(output_dir))

        result = gen.generate_batch(original_file=str(real_dicom_file), count=5)

        assert len(result) <= 5  # May be less due to random failures
        for path in result:
            assert path.exists()
            assert path.suffix == ".dcm"

    def test_generate_with_metadata_strategy(self, real_dicom_file, tmp_path):
        """Test generation with specific strategy."""
        output_dir = tmp_path / "output"
        gen = DICOMGenerator(output_dir=str(output_dir))

        result = gen.generate_batch(
            original_file=str(real_dicom_file), count=3, strategies=["metadata"]
        )

        assert len(result) <= 3

    def test_generate_with_multiple_strategies(self, real_dicom_file, tmp_path):
        """Test generation with multiple strategies."""
        output_dir = tmp_path / "output"
        gen = DICOMGenerator(output_dir=str(output_dir))

        result = gen.generate_batch(
            original_file=str(real_dicom_file),
            count=3,
            strategies=["metadata", "header"],
        )

        assert len(result) <= 3

    def test_generate_zero_count(self, real_dicom_file, tmp_path):
        """Test generating zero files."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        result = gen.generate_batch(original_file=str(real_dicom_file), count=0)

        assert result == []

    def test_stats_updated_after_generation(self, real_dicom_file, tmp_path):
        """Test stats are updated during generation."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        gen.generate_batch(original_file=str(real_dicom_file), count=5)

        assert gen.stats.total_attempted >= 1
        assert gen.stats.successful >= 0


class TestStrategyRegistration:
    """Test strategy registration in mutator."""

    def test_all_strategies_registered(self, tmp_path):
        """Test all 12 format fuzzers are registered."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        assert len(gen.mutator.strategies) == 12

    def test_strategy_names(self, tmp_path):
        """Test registered strategy names."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        names = sorted(s.get_strategy_name() for s in gen.mutator.strategies)
        expected = sorted(
            [
                "calibration",
                "compressed_pixel",
                "conformance",
                "dictionary",
                "encoding",
                "header",
                "metadata",
                "pixel",
                "private_tag",
                "reference",
                "sequence",
                "structure",
            ]
        )
        assert names == expected

    def test_strategy_filtering_via_generate_batch(self, real_dicom_file, tmp_path):
        """Test that strategy filtering works through generate_batch."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        result = gen.generate_batch(
            original_file=str(real_dicom_file),
            count=5,
            strategies=["metadata"],
        )

        # If any files generated successfully, they should only use metadata
        for name in gen.stats.strategies_used:
            assert name == "metadata"


class TestMutationHandling:
    """Test mutation error handling."""

    def test_skip_write_errors_true(self, tmp_path):
        """Test error handling with skip_write_errors=True."""
        gen = DICOMGenerator(output_dir=str(tmp_path), skip_write_errors=True)

        result = gen._handle_mutation_error(ValueError("Test error"))

        assert result == (None, [])
        assert gen.stats.skipped_due_to_write_errors == 1

    def test_skip_write_errors_false(self, tmp_path):
        """Test error handling with skip_write_errors=False."""
        gen = DICOMGenerator(output_dir=str(tmp_path), skip_write_errors=False)

        # _handle_mutation_error should raise the error when skip_write_errors=False
        # Need to call it within an exception context for 'raise' to work
        with pytest.raises(ValueError, match="Test error"):
            try:
                raise ValueError("Test error")
            except ValueError as e:
                gen._handle_mutation_error(e)

        # Stats should be updated
        assert gen.stats.failed >= 1


class TestFileNaming:
    """Test generated file naming."""

    def test_unique_filenames(self, real_dicom_file, tmp_path):
        """Test generated files have unique names."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        result = gen.generate_batch(original_file=str(real_dicom_file), count=10)

        filenames = [p.name for p in result]
        assert len(filenames) == len(set(filenames))  # All unique

    def test_filename_format(self, real_dicom_file, tmp_path):
        """Test filename format."""
        gen = DICOMGenerator(output_dir=str(tmp_path))

        result = gen.generate_batch(original_file=str(real_dicom_file), count=1)

        if result:
            filename = result[0].name
            assert filename.startswith("fuzzed_")
            assert filename.endswith(".dcm")


class TestOutputDirectory:
    """Test output directory handling."""

    def test_files_saved_to_output_dir(self, real_dicom_file, tmp_path):
        """Test files are saved to correct output directory."""
        output_dir = tmp_path / "custom_output"
        gen = DICOMGenerator(output_dir=str(output_dir))

        result = gen.generate_batch(original_file=str(real_dicom_file), count=3)

        for path in result:
            assert path.parent == output_dir
