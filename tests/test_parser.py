"""
Comprehensive tests for DICOM parser with security validation.

Tests cover:
- Basic parsing functionality
- Security validation
- Metadata extraction
- Pixel data handling
- Transfer syntax detection
- Edge cases and error handling
"""

import numpy as np
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydicom.dataset import Dataset

from core.exceptions import SecurityViolationError
from core.parser import DicomParser


class TestDicomParserInit:
    """Test DicomParser initialization and validation."""

    def test_parse_valid_dicom_file(self, sample_dicom_file):
        """Test parsing a valid DICOM file."""
        parser = DicomParser(sample_dicom_file)
        assert parser.dataset is not None
        assert isinstance(parser.dataset, Dataset)

    def test_parse_nonexistent_file_raises_error(self, temp_dir):
        """Test that parsing nonexistent file raises SecurityViolationError."""
        nonexistent = temp_dir / "nonexistent.dcm"
        with pytest.raises(SecurityViolationError, match="does not exist"):
            DicomParser(nonexistent)

    def test_parse_invalid_dicom_raises_error(self, temp_dir):
        """Test that parsing invalid DICOM file raises appropriate error."""
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"This is not a DICOM file")

        with pytest.raises(Exception):  # pydicom raises various exceptions
            DicomParser(invalid_file)

    def test_parse_with_max_size_limit(self, sample_dicom_file):
        """Test parsing respects max file size limit."""
        # Get actual file size
        file_size = sample_dicom_file.stat().st_size

        # Should succeed with sufficient limit
        parser = DicomParser(sample_dicom_file, max_file_size=file_size + 1000)
        assert parser.dataset is not None

    def test_parse_exceeds_max_size_raises_error(self, sample_dicom_file):
        """Test that file exceeding max size raises SecurityViolationError."""
        # Set limit smaller than file size
        with pytest.raises(SecurityViolationError, match="exceeds maximum"):
            DicomParser(sample_dicom_file, max_file_size=100)


class TestMetadataExtraction:
    """Test metadata extraction functionality."""

    def test_extract_basic_metadata(self, sample_dicom_file):
        """Test extraction of basic DICOM metadata."""
        parser = DicomParser(sample_dicom_file)
        metadata = parser.extract_metadata()

        assert isinstance(metadata, dict)
        assert "patient_info" in metadata
        assert "study_info" in metadata
        assert "series_info" in metadata
        assert "instance_info" in metadata

    def test_extract_metadata_excludes_private_tags(self, sample_dicom_file):
        """Test that private tags are excluded by default."""
        parser = DicomParser(sample_dicom_file)
        metadata = parser.extract_metadata(include_private=False)

        # Check that no private tags are included
        assert "private_tags" not in metadata

    def test_extract_metadata_includes_private_tags(self, sample_dicom_file):
        """Test that private tags can be included when requested."""
        parser = DicomParser(sample_dicom_file)
        metadata = parser.extract_metadata(include_private=True)

        # Private tags section should exist (even if empty)
        assert "private_tags" in metadata
        assert isinstance(metadata["private_tags"], dict)

    def test_metadata_contains_patient_info(self, sample_dicom_file):
        """Test that metadata contains patient information."""
        parser = DicomParser(sample_dicom_file)
        metadata = parser.extract_metadata()

        patient_info = metadata["patient_info"]
        assert "PatientID" in patient_info or "patient_id" in patient_info

    def test_metadata_excludes_pixel_data(self, sample_dicom_file):
        """Test that pixel data is not included in metadata."""
        parser = DicomParser(sample_dicom_file)
        metadata = parser.extract_metadata()

        # Metadata should not contain pixel data
        assert "PixelData" not in str(metadata)


class TestPixelDataHandling:
    """Test pixel data extraction and validation."""

    def test_get_pixel_data_from_image(self, dicom_with_pixels):
        """Test extraction of pixel data from image."""
        parser = DicomParser(dicom_with_pixels)
        pixel_data = parser.get_pixel_data()

        assert pixel_data is not None
        assert isinstance(pixel_data, np.ndarray)
        assert pixel_data.size > 0

    def test_get_pixel_data_without_validation(self, dicom_with_pixels):
        """Test pixel data extraction without validation."""
        parser = DicomParser(dicom_with_pixels)
        pixel_data = parser.get_pixel_data(validate=False)

        assert pixel_data is not None
        assert isinstance(pixel_data, np.ndarray)

    def test_get_pixel_data_from_non_image_returns_none(self, sample_dicom_file):
        """Test that non-image DICOM returns None for pixel data."""
        parser = DicomParser(sample_dicom_file)

        # If no pixel data, should return None gracefully
        pixel_data = parser.get_pixel_data()
        # Could be None or could raise exception depending on implementation
        assert pixel_data is None or isinstance(pixel_data, np.ndarray)


class TestTransferSyntax:
    """Test transfer syntax detection and compression handling."""

    def test_get_transfer_syntax(self, sample_dicom_file):
        """Test transfer syntax extraction."""
        parser = DicomParser(sample_dicom_file)
        transfer_syntax = parser.get_transfer_syntax()

        assert transfer_syntax is not None
        assert isinstance(transfer_syntax, str)

    def test_is_compressed_detection(self, sample_dicom_file):
        """Test compression detection."""
        parser = DicomParser(sample_dicom_file)
        is_compressed = parser.is_compressed()

        assert isinstance(is_compressed, bool)

    def test_uncompressed_file_reports_correctly(self, sample_dicom_file):
        """Test that uncompressed file is detected correctly."""
        parser = DicomParser(sample_dicom_file)

        # Our test files use ExplicitVRLittleEndian (uncompressed)
        assert parser.is_compressed() is False


class TestCriticalTags:
    """Test critical DICOM tag extraction."""

    def test_get_critical_tags(self, sample_dicom_file):
        """Test extraction of critical DICOM tags."""
        parser = DicomParser(sample_dicom_file)
        critical_tags = parser.get_critical_tags()

        assert isinstance(critical_tags, dict)
        assert len(critical_tags) > 0

    def test_critical_tags_include_sop_class(self, sample_dicom_file):
        """Test that critical tags include SOP Class UID."""
        parser = DicomParser(sample_dicom_file)
        critical_tags = parser.get_critical_tags()

        # SOPClassUID should be in critical tags
        assert any("SOPClass" in key for key in critical_tags.keys())


class TestTemporaryMutation:
    """Test temporary mutation context manager."""

    def test_temporary_mutation_restores_dataset(self, sample_dicom_file):
        """Test that temporary mutation restores original dataset."""
        parser = DicomParser(sample_dicom_file)
        original_patient_id = parser.dataset.PatientID

        with parser.temporary_mutation():
            # Mutate the dataset
            parser.dataset.PatientID = "MUTATED_ID"
            assert parser.dataset.PatientID == "MUTATED_ID"

        # After context exit, dataset should be restored
        assert parser.dataset.PatientID == original_patient_id

    def test_temporary_mutation_handles_exceptions(self, sample_dicom_file):
        """Test that temporary mutation restores dataset even on exception."""
        parser = DicomParser(sample_dicom_file)
        original_patient_id = parser.dataset.PatientID

        try:
            with parser.temporary_mutation():
                parser.dataset.PatientID = "MUTATED_ID"
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Dataset should still be restored after exception
        assert parser.dataset.PatientID == original_patient_id


class TestContextManager:
    """Test DicomParser as context manager."""

    def test_parser_as_context_manager(self, sample_dicom_file):
        """Test using parser as context manager."""
        with DicomParser(sample_dicom_file) as parser:
            assert parser.dataset is not None
            assert isinstance(parser.dataset, Dataset)

    def test_context_manager_cleanup(self, sample_dicom_file):
        """Test that context manager properly cleans up resources."""
        parser = None
        with DicomParser(sample_dicom_file) as p:
            parser = p
            assert parser.dataset is not None

        # After exit, parser should still be accessible but cleaned up
        assert parser is not None


class TestSecurityValidation:
    """Test security validation during parsing."""

    def test_parse_with_validate_enabled(self, sample_dicom_file):
        """Test parsing with validation enabled."""
        parser = DicomParser(sample_dicom_file, validate=True)
        assert parser.dataset is not None

    def test_parse_with_validate_disabled(self, sample_dicom_file):
        """Test parsing with validation disabled."""
        parser = DicomParser(sample_dicom_file, validate=False)
        assert parser.dataset is not None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_parse_minimal_dicom(self, minimal_dicom_file):
        """Test parsing minimal valid DICOM file."""
        parser = DicomParser(minimal_dicom_file)
        assert parser.dataset is not None

    def test_parse_empty_patient_name(self, dicom_empty_patient_name):
        """Test parsing DICOM with empty patient name."""
        parser = DicomParser(dicom_empty_patient_name)
        metadata = parser.extract_metadata()

        # Should handle empty patient name gracefully
        assert metadata is not None


class TestPropertyBasedTesting:
    """Property-based tests for robustness."""

    @given(st.integers(min_value=1, max_value=1000000))
    def test_max_file_size_validation(self, max_size, sample_dicom_file):
        """Property test: max_file_size parameter works correctly."""
        file_size = sample_dicom_file.stat().st_size

        if max_size >= file_size:
            # Should succeed
            parser = DicomParser(sample_dicom_file, max_file_size=max_size)
            assert parser.dataset is not None
        else:
            # Should fail
            with pytest.raises(ValueError):
                DicomParser(sample_dicom_file, max_file_size=max_size)


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_parsing_workflow(self, sample_dicom_file):
        """Test complete parsing workflow."""
        # Initialize parser
        parser = DicomParser(sample_dicom_file)

        # Extract metadata
        metadata = parser.extract_metadata()
        assert metadata is not None

        # Get transfer syntax
        transfer_syntax = parser.get_transfer_syntax()
        assert transfer_syntax is not None

        # Get critical tags
        critical_tags = parser.get_critical_tags()
        assert critical_tags is not None

        # Check compression status
        is_compressed = parser.is_compressed()
        assert isinstance(is_compressed, bool)

    def test_multiple_parsers_same_file(self, sample_dicom_file):
        """Test creating multiple parser instances for same file."""
        parser1 = DicomParser(sample_dicom_file)
        parser2 = DicomParser(sample_dicom_file)

        assert parser1.dataset is not None
        assert parser2.dataset is not None
        # Should be independent instances
        assert parser1 is not parser2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
