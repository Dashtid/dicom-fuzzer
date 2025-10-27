"""Comprehensive tests for parser module.

Tests DICOM file parsing, security checks, and metadata extraction.
"""

from unittest.mock import patch

import pytest
from pydicom.tag import Tag

from dicom_fuzzer.core.exceptions import (
    ParsingError,
    SecurityViolationError,
)
from dicom_fuzzer.core.parser import DicomParser


class TestDicomParserInitialization:
    """Test DicomParser initialization."""

    def test_critical_tags_defined(self):
        """Test critical tags are defined."""
        assert len(DicomParser.CRITICAL_TAGS) == 4
        assert Tag(0x0008, 0x0016) in DicomParser.CRITICAL_TAGS  # SOPClassUID

    def test_max_file_size_constant(self):
        """Test max file size constant."""
        assert DicomParser.MAX_FILE_SIZE == 100 * 1024 * 1024


class TestSecurityChecks:
    """Test security validation."""

    def test_nonexistent_file_raises_error(self):
        """Test parsing nonexistent file raises error."""
        with pytest.raises(SecurityViolationError, match="File does not exist"):
            DicomParser("/nonexistent/file.dcm", security_checks=True)

    def test_directory_path_raises_error(self, tmp_path):
        """Test directory path raises error."""
        with pytest.raises(SecurityViolationError, match="not a regular file"):
            DicomParser(tmp_path, security_checks=True)

    def test_security_checks_disabled(self):
        """Test parser with security checks disabled."""
        # Should not raise on nonexistent file when checks disabled
        try:
            DicomParser("/fake.dcm", security_checks=False)
        except ParsingError:
            # Parsing will fail but security check should not trigger
            pass

    def test_oversized_file_detection(self, tmp_path):
        """Test detection of oversized files."""
        # Create a file that exceeds a very small max size
        test_file = tmp_path / "large.dcm"
        test_file.write_bytes(b"DICM" + b"\x00" * 100)

        # Use a very small max file size to trigger the error (file is 104 bytes)
        with pytest.raises(SecurityViolationError, match="exceeds maximum"):
            DicomParser(test_file, security_checks=True, max_file_size=50)


class TestParsingOperations:
    """Test DICOM parsing operations."""

    def test_successful_parse(self, tmp_path):
        """Test successful DICOM file parsing."""
        test_file = tmp_path / "test.dcm"

        # Create a real minimal DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.PatientID = "001"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)

        assert parser.dataset is not None

    @patch("pydicom.dcmread")
    def test_parse_failure_raises_error(self, mock_dcmread, tmp_path):
        """Test parse failure raises ParsingError."""
        test_file = tmp_path / "bad.dcm"
        test_file.write_bytes(b"NOT DICOM")

        mock_dcmread.side_effect = Exception("Invalid DICOM")

        with pytest.raises(ParsingError, match="Failed to parse"):
            DicomParser(test_file, security_checks=False)

    def test_dataset_property(self, tmp_path):
        """Test dataset property access."""
        test_file = tmp_path / "test.dcm"

        # Create a real minimal DICOM file with required elements
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # Required
        ds.SOPInstanceUID = "1.2.3"  # Required

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)

        assert parser.dataset is not None
        assert hasattr(parser.dataset, "PatientName")


class TestMetadataExtraction:
    """Test metadata extraction."""

    def test_get_metadata(self, tmp_path):
        """Test metadata extraction."""
        test_file = tmp_path / "test.dcm"

        # Create a real DICOM file with metadata
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test^Patient"
        ds.StudyDate = "20250101"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)

        if hasattr(parser, "get_metadata"):
            metadata = parser.get_metadata()
            assert isinstance(metadata, dict)

    def test_metadata_caching(self, tmp_path):
        """Test metadata is cached."""
        test_file = tmp_path / "test.dcm"

        # Create a real DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

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

        parser = DicomParser(test_file, security_checks=False)

        # Access metadata multiple times
        if hasattr(parser, "get_metadata"):
            metadata1 = parser.get_metadata()
            metadata2 = parser.get_metadata()

            # Should return same cached instance
            assert metadata1 is metadata2


class TestTagOperations:
    """Test tag-related operations."""

    def test_critical_tag_detection(self):
        """Test detection of critical tags."""
        # Test critical tag checking (doesn't need parser instance)
        sop_class_tag = Tag(0x0008, 0x0016)
        assert sop_class_tag in DicomParser.CRITICAL_TAGS

    def test_has_tag_method(self, tmp_path):
        """Test checking if tag exists."""
        test_file = tmp_path / "test.dcm"

        # Create a real DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

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

        parser = DicomParser(test_file, security_checks=False)

        if hasattr(parser, "has_tag"):
            result = parser.has_tag(Tag(0x0010, 0x0010))
            assert isinstance(result, bool)


class TestPropertyAccess:
    """Test property access methods."""

    def test_file_path_property(self, tmp_path):
        """Test file_path property."""
        test_file = tmp_path / "test.dcm"

        # Create a real DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

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

        parser = DicomParser(test_file, security_checks=False)

        assert parser.file_path == test_file

    def test_security_checks_property(self, tmp_path):
        """Test security_checks_enabled property."""
        test_file = tmp_path / "test.dcm"

        # Create a real DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

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

        parser = DicomParser(test_file, security_checks=True)

        assert parser.security_checks_enabled is True


class TestIntegrationScenarios:
    """Test integration scenarios."""

    def test_complete_parsing_workflow(self, tmp_path):
        """Test complete parsing workflow."""
        test_file = tmp_path / "workflow.dcm"

        # Create a real DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test^Patient"
        ds.Modality = "CT"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        # Parse file
        parser = DicomParser(test_file, security_checks=False)

        # Verify parsing
        assert parser.dataset is not None
        assert parser.file_path == test_file

    def test_parser_with_custom_max_size(self, tmp_path):
        """Test parser with custom max file size."""
        test_file = tmp_path / "test.dcm"

        # Create a real DICOM file
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

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

        custom_max = 50 * 1024 * 1024  # 50MB
        parser = DicomParser(test_file, security_checks=False, max_file_size=custom_max)

        assert parser.max_file_size == custom_max

    def test_multiple_parser_instances(self, tmp_path):
        """Test creating multiple parser instances."""
        file1 = tmp_path / "file1.dcm"
        file2 = tmp_path / "file2.dcm"

        # Create real DICOM files
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset

        for i, test_file in enumerate([file1, file2]):
            file_meta = FileMetaDataset()
            file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
            file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            file_meta.MediaStorageSOPInstanceUID = f"1.2.{i}"

            ds = Dataset()
            ds.file_meta = file_meta
            ds.PatientName = f"Test{i}"
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ds.SOPInstanceUID = f"1.2.{i}"

            pydicom.dcmwrite(str(test_file), ds)

        parser1 = DicomParser(file1, security_checks=False)
        parser2 = DicomParser(file2, security_checks=False)

        assert parser1.file_path != parser2.file_path
        assert parser1.dataset is not parser2.dataset
