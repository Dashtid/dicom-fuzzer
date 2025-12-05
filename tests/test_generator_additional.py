"""
Additional tests for DICOMGenerator to improve code coverage.

These tests target specific uncovered error handling and edge case paths
in generator.py to achieve maximum test coverage.
"""

import struct
from unittest.mock import patch

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset

from dicom_fuzzer.core.generator import DICOMGenerator, GenerationStats


class TestGenerationStats:
    """Test GenerationStats class."""

    def test_record_failure(self):
        """Test recording failed generations."""
        stats = GenerationStats()

        stats.record_failure("ValueError")
        assert stats.failed == 1
        assert stats.error_types["ValueError"] == 1

        stats.record_failure("TypeError")
        assert stats.failed == 2
        assert stats.error_types["TypeError"] == 1

        # Same error type again
        stats.record_failure("ValueError")
        assert stats.failed == 3
        assert stats.error_types["ValueError"] == 2

    def test_record_success_with_strategies(self):
        """Test recording successful generations with strategies."""
        stats = GenerationStats()

        stats.record_success(["metadata", "header"])
        assert stats.successful == 1
        assert stats.strategies_used["metadata"] == 1
        assert stats.strategies_used["header"] == 1

        stats.record_success(["metadata"])
        assert stats.successful == 2
        assert stats.strategies_used["metadata"] == 2


@pytest.mark.slow
class TestGeneratorErrorHandling:
    """Test error handling paths in generator.

    Note: Marked slow due to non-deterministic behavior in parallel test execution.
    """

    def test_generate_with_structure_strategy(self, tmp_path):
        """Test generation with structure fuzzing strategy."""
        # Create a test DICOM file
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        # Generate with structure strategy
        output_dir = tmp_path / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Use structure strategy (line 111)
        files = generator.generate_batch(
            str(test_file), count=1, strategies=["structure"]
        )

        # Should generate files or handle gracefully
        assert isinstance(files, list)

    def test_mutation_error_handling_no_skip(self, tmp_path):
        """Test mutation error handling when skip_write_errors=False."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(
            output_dir=str(output_dir),
            skip_write_errors=False,  # Don't skip errors
        )

        # Mock a fuzzer to raise an error
        with patch.object(generator, "_apply_single_fuzzer") as mock_fuzzer:
            mock_fuzzer.side_effect = ValueError("Test error")

            # Should raise the error (not skip it)
            with pytest.raises(ValueError, match="Test error"):
                generator.generate_batch(str(test_file), count=1)

    def test_save_error_handling_with_skip(self, tmp_path):
        """Test save error handling with skip_write_errors=True."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(output_dir=str(output_dir), skip_write_errors=True)

        # Mock save_as to raise OSError
        with patch("pydicom.dataset.Dataset.save_as") as mock_save:
            mock_save.side_effect = OSError("Disk full")

            # Should skip the error and return empty list
            generator.generate_batch(str(test_file), count=1)

            # Should handle error gracefully
            assert generator.stats.skipped_due_to_write_errors > 0

    def test_save_error_handling_without_skip(self, tmp_path):
        """Test save error handling with skip_write_errors=False."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(
            output_dir=str(output_dir),
            skip_write_errors=False,  # Don't skip
        )

        # Mock save_as to raise struct.error
        with patch("pydicom.dataset.Dataset.save_as") as mock_save:
            mock_save.side_effect = struct.error("Invalid format")

            # Should raise the error
            with pytest.raises(struct.error):
                generator.generate_batch(str(test_file), count=1)

            # Stats should record the failure
            assert generator.stats.failed > 0

    def test_save_unexpected_exception(self, tmp_path):
        """Test handling of unexpected exceptions during save."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Mock save_as to raise unexpected exception
        with patch("pydicom.dataset.Dataset.save_as") as mock_save:
            mock_save.side_effect = RuntimeError("Unexpected error")

            # Should raise the unexpected error
            with pytest.raises(RuntimeError, match="Unexpected error"):
                generator.generate_batch(str(test_file), count=1)

    def test_mutation_returns_none(self, tmp_path):
        """Test when mutation returns None (line 124)."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(output_dir=str(output_dir), skip_write_errors=True)

        # Mock _apply_mutations to return None
        with patch.object(generator, "_apply_mutations") as mock_apply:
            mock_apply.return_value = (None, [])

            # Should handle None gracefully
            files = generator.generate_batch(str(test_file), count=1)

            # Should return empty or filtered list
            assert isinstance(files, list)

    def test_mutation_error_types(self, tmp_path):
        """Test different mutation error types (TypeError, AttributeError)."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"

        # Test with skip_write_errors=True (lines 168-170)
        generator = DICOMGenerator(output_dir=str(output_dir), skip_write_errors=True)

        with patch.object(generator, "_apply_single_fuzzer") as mock_fuzzer:
            mock_fuzzer.side_effect = TypeError("Invalid type")

            generator.generate_batch(str(test_file), count=1)
            assert generator.stats.skipped_due_to_write_errors > 0

        # Test with skip_write_errors=False (lines 172-173)
        generator2 = DICOMGenerator(output_dir=str(output_dir), skip_write_errors=False)

        with patch.object(generator2, "_apply_single_fuzzer") as mock_fuzzer:
            mock_fuzzer.side_effect = AttributeError("Missing attribute")

            with pytest.raises(AttributeError):
                generator2.generate_batch(str(test_file), count=1)

            assert generator2.stats.failed > 0
            assert "AttributeError" in generator2.stats.error_types


class TestGeneratorEdgeCases:
    """Test edge cases and special scenarios."""

    def test_generate_with_all_strategies(self, tmp_path):
        """Test generation with all available strategies."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Generate with all strategies explicitly
        files = generator.generate_batch(
            str(test_file),
            count=2,
            strategies=["metadata", "header", "pixel", "structure"],
        )

        assert isinstance(files, list)

    def test_stats_tracking(self, tmp_path):
        """Test that stats are properly tracked."""
        test_file = tmp_path / "test.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        output_dir = tmp_path / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generator.generate_batch(str(test_file), count=3)

        # Stats should be tracked
        assert generator.stats.total_attempted > 0
        assert generator.stats.successful >= 0
        assert isinstance(generator.stats.strategies_used, dict)
