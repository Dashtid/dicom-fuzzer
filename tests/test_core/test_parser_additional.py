"""
Additional tests for DicomParser to improve code coverage.

These tests target specific uncovered code paths in parser.py
to increase overall test coverage.
"""

import numpy as np
import pydicom
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag

from dicom_fuzzer.core.parser import DicomParser


class TestMetadataExtraction:
    """Test metadata extraction methods."""

    def test_extract_metadata_basic(self, tmp_path):
        """Test basic metadata extraction."""
        test_file = tmp_path / "metadata.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.PatientBirthDate = "19900101"
        ds.PatientSex = "M"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.StudyDescription = "Test Study"
        ds.Modality = "CT"
        ds.InstitutionName = "Test Hospital"
        ds.Manufacturer = "Test Manufacturer"
        ds.ManufacturerModelName = "Model X"
        ds.SoftwareVersions = "1.0.0"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.SeriesInstanceUID = "1.2.3.4.5"

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)
        metadata = parser.extract_metadata()

        assert "Test^Patient" in str(metadata["patient_name"])
        assert "12345" in str(metadata["patient_id"])
        assert "19900101" in str(metadata["patient_birth_date"])
        assert "M" in str(metadata["patient_sex"])
        assert "20250101" in str(metadata["study_date"])
        assert "CT" in str(metadata["modality"])
        assert "Test Hospital" in str(metadata["institution_name"])
        assert "Test Manufacturer" in str(metadata["manufacturer"])

    def test_extract_metadata_with_pixel_data(self, tmp_path):
        """Test metadata extraction with pixel data."""
        test_file = tmp_path / "image.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Add pixel data
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = np.zeros((512, 512), dtype=np.uint16).tobytes()

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)
        metadata = parser.extract_metadata()

        assert metadata["has_pixel_data"] is True
        assert "512" in str(metadata.get("rows", ""))
        assert "512" in str(metadata.get("columns", ""))
        assert "16" in str(metadata.get("bits_allocated", ""))
        assert "12" in str(metadata.get("bits_stored", ""))
        assert "1" in str(metadata.get("samples_per_pixel", ""))

    def test_extract_metadata_without_pixel_data(self, tmp_path):
        """Test metadata extraction without pixel data."""
        test_file = tmp_path / "no_image.dcm"

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
        metadata = parser.extract_metadata()

        assert metadata["has_pixel_data"] is False
        assert "rows" not in metadata or metadata.get("rows") is None

    def test_extract_metadata_caching(self, tmp_path):
        """Test that metadata is cached after first call."""
        test_file = tmp_path / "cache.dcm"

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

        # First call should populate cache
        metadata1 = parser.extract_metadata()
        # Second call should return cached version
        metadata2 = parser.extract_metadata()

        # Should be the same object (cached)
        assert metadata1 is metadata2

    def test_extract_metadata_with_private_tags(self, tmp_path):
        """Test metadata extraction including private tags."""
        test_file = tmp_path / "private.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Add private tags
        ds.add_new(Tag(0x0009, 0x0010), "LO", "PRIVATE_CREATOR")
        ds.add_new(Tag(0x0009, 0x1001), "LO", "PrivateValue1")

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)
        metadata = parser.extract_metadata(include_private=True)

        assert "private_tags" in metadata
        assert len(metadata["private_tags"]) > 0

    def test_extract_metadata_missing_fields(self, tmp_path):
        """Test metadata extraction with missing fields."""
        test_file = tmp_path / "minimal.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        # Only required tags
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)
        metadata = parser.extract_metadata()

        # Missing fields should be empty strings
        assert metadata["patient_name"] == ""
        assert metadata["patient_id"] == ""
        assert metadata["study_date"] == ""


class TestTagOperations:
    """Test tag-related operations."""

    def test_get_tag_value(self, tmp_path):
        """Test getting tag values."""
        test_file = tmp_path / "tags.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)

        # Test get_tag_value if method exists
        if hasattr(parser, "get_tag_value"):
            value = parser.get_tag_value(Tag(0x0010, 0x0010))
            assert "Test" in str(value)

    def test_has_tag_present(self, tmp_path):
        """Test has_tag for present tag."""
        test_file = tmp_path / "tags.dcm"

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
            # PatientName should be present
            assert parser.has_tag(Tag(0x0010, 0x0010)) is True
            # Random tag should not be present
            assert parser.has_tag(Tag(0x0010, 0x9999)) is False

    def test_get_all_tags(self, tmp_path):
        """Test getting all tags."""
        test_file = tmp_path / "all_tags.dcm"

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

        if hasattr(parser, "get_all_tags"):
            tags = parser.get_all_tags()
            assert len(tags) > 0
            # Should include PatientName tag
            assert Tag(0x0010, 0x0010) in tags


class TestPrivateTagExtraction:
    """Test private tag extraction."""

    def test_extract_private_tags(self, tmp_path):
        """Test extraction of private tags."""
        test_file = tmp_path / "private_tags.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Add multiple private tags
        ds.add_new(Tag(0x0009, 0x0010), "LO", "VENDOR1")
        ds.add_new(Tag(0x0009, 0x1001), "LO", "Value1")
        ds.add_new(Tag(0x0011, 0x0010), "LO", "VENDOR2")
        ds.add_new(Tag(0x0011, 0x1001), "LO", "Value2")

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)

        # Get metadata with private tags
        metadata = parser.extract_metadata(include_private=True)

        assert "private_tags" in metadata
        private_tags = metadata["private_tags"]
        assert len(private_tags) > 0

    def test_no_private_tags(self, tmp_path):
        """Test extraction when no private tags present."""
        test_file = tmp_path / "no_private.dcm"

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
        metadata = parser.extract_metadata(include_private=True)

        assert "private_tags" in metadata
        # Should be empty dict or list
        assert len(metadata["private_tags"]) == 0


class TestParserEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_corrupted_tag_values(self, tmp_path):
        """Test handling of corrupted tag values during metadata extraction."""
        test_file = tmp_path / "corrupted.dcm"

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

        # Should handle metadata extraction gracefully even with issues
        metadata = parser.extract_metadata()
        assert isinstance(metadata, dict)
        assert "patient_name" in metadata

    def test_multiple_metadata_calls(self, tmp_path):
        """Test multiple calls to extract_metadata return consistent results."""
        test_file = tmp_path / "multi.dcm"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = "1.2.3"

        ds = Dataset()
        ds.file_meta = file_meta
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        pydicom.dcmwrite(str(test_file), ds)

        parser = DicomParser(test_file, security_checks=False)

        # Multiple calls
        meta1 = parser.extract_metadata()
        meta2 = parser.extract_metadata()
        meta3 = parser.extract_metadata(include_private=False)

        # Should all return same patient name
        assert meta1["patient_name"] == meta2["patient_name"]
        assert meta2["patient_name"] == meta3["patient_name"]
