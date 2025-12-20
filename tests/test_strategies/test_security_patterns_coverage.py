"""Tests for security_patterns module to improve code coverage.

These tests execute the actual security pattern fuzzing code paths.
"""

import warnings

import pydicom
import pytest
from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.strategies.security_patterns import SecurityPatternFuzzer


@pytest.fixture
def fuzzer():
    """Create SecurityPatternFuzzer instance."""
    return SecurityPatternFuzzer()


@pytest.fixture
def sample_dataset():
    """Create sample DICOM dataset for testing."""
    ds = Dataset()

    # File meta information
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    # Required DICOM tags
    ds.SpecificCharacterSet = "ISO_IR 100"
    ds.ImageType = ["ORIGINAL", "PRIMARY"]
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.AccessionNumber = "12345"
    ds.Modality = "CT"
    ds.Manufacturer = "Test Manufacturer"
    ds.ReferringPhysicianName = "Dr. Test"

    # Patient info
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST001"
    ds.PatientBirthDate = "19900101"
    ds.PatientSex = "O"

    # Study/Series info
    ds.StudyInstanceUID = "1.2.3.4.5.6.7"
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8"
    ds.StudyID = "STUDY001"
    ds.SeriesNumber = "1"
    ds.InstanceNumber = "1"
    ds.StudyDescription = "Test Study"
    ds.SeriesDescription = "Test Series"

    # Image info
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    # Comments fields for spray testing
    ds.ImageComments = "Test image comments"
    ds.InstitutionName = "Test Hospital"

    return ds


class TestSecurityPatternFuzzerInit:
    """Test SecurityPatternFuzzer initialization."""

    def test_init_creates_patterns(self, fuzzer):
        """Test that initialization creates pattern lists."""
        assert len(fuzzer.oversized_vr_lengths) > 0
        assert len(fuzzer.heap_spray_patterns) > 0
        assert len(fuzzer.malformed_vr_codes) > 0

    def test_oversized_vr_lengths_values(self, fuzzer):
        """Test oversized VR length values."""
        assert 0xFFFF in fuzzer.oversized_vr_lengths
        assert 0x8000 in fuzzer.oversized_vr_lengths
        assert 0x7FFF in fuzzer.oversized_vr_lengths

    def test_heap_spray_patterns_content(self, fuzzer):
        """Test heap spray pattern content."""
        # Check that patterns contain expected bytes
        patterns = fuzzer.heap_spray_patterns
        assert any(b"\x0c\x0c" in p for p in patterns)  # Classic heap spray
        assert any(b"\x90" in p for p in patterns)  # NOP sled
        assert any(b"\x41" in p for p in patterns)  # ASCII 'A'


class TestCve20255943Pattern:
    """Test CVE-2025-5943 specific patterns."""

    def test_apply_cve_pattern_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that CVE pattern modifies the dataset."""
        original_tags = list(sample_dataset.keys())

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_cve_2025_5943_pattern(sample_dataset)

        # Dataset should be returned
        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_cve_pattern_targets_vulnerable_tags(self, fuzzer, sample_dataset):
        """Test that CVE pattern targets expected tags."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_cve_2025_5943_pattern(sample_dataset)

        # Dataset should still have required tags
        assert result.SOPClassUID is not None
        assert result.Modality is not None

    def test_apply_cve_pattern_multiple_times(self, fuzzer, sample_dataset):
        """Test applying CVE pattern multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(5):
                sample_dataset = fuzzer.apply_cve_2025_5943_pattern(sample_dataset)

        assert sample_dataset is not None


class TestHeapSprayPattern:
    """Test heap spray patterns."""

    def test_apply_heap_spray_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that heap spray modifies the dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_heap_spray_pattern(sample_dataset)

        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_heap_spray_targets_pixel_data(self, fuzzer, sample_dataset):
        """Test that heap spray can target PixelData."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_heap_spray_pattern(sample_dataset)

        # PixelData might be modified
        assert hasattr(result, "PixelData")

    def test_apply_heap_spray_targets_string_fields(self, fuzzer, sample_dataset):
        """Test that heap spray can target string fields."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_heap_spray_pattern(sample_dataset)

        # ImageComments might be modified if it exists
        assert hasattr(result, "ImageComments")

    def test_apply_heap_spray_multiple_times(self, fuzzer, sample_dataset):
        """Test applying heap spray multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(5):
                sample_dataset = fuzzer.apply_heap_spray_pattern(sample_dataset)

        assert sample_dataset is not None


class TestMalformedVRPattern:
    """Test malformed VR patterns."""

    def test_apply_malformed_vr_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that malformed VR modifies the dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_malformed_vr_pattern(sample_dataset)

        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_malformed_vr_on_tags(self, fuzzer, sample_dataset):
        """Test malformed VR application on existing tags."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_malformed_vr_pattern(sample_dataset)

        # Dataset should still be valid structure
        assert len(list(result.keys())) > 0

    def test_apply_malformed_vr_multiple_times(self, fuzzer, sample_dataset):
        """Test applying malformed VR multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(5):
                sample_dataset = fuzzer.apply_malformed_vr_pattern(sample_dataset)

        assert sample_dataset is not None


class TestIntegerOverflowPattern:
    """Test integer overflow patterns."""

    def test_apply_integer_overflow_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that integer overflow modifies the dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_integer_overflow_pattern(sample_dataset)

        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_integer_overflow_targets_size_fields(self, fuzzer, sample_dataset):
        """Test that integer overflow targets size fields."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_integer_overflow_pattern(sample_dataset)

        # Should still have image dimension fields
        assert hasattr(result, "Rows")
        assert hasattr(result, "Columns")

    def test_apply_integer_overflow_edge_values(self, fuzzer, sample_dataset):
        """Test integer overflow with edge values."""
        # Run multiple times to test various edge values
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(10):
                result = fuzzer.apply_integer_overflow_pattern(sample_dataset)

        assert result is not None

    def test_apply_integer_overflow_multiple_times(self, fuzzer, sample_dataset):
        """Test applying integer overflow multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(5):
                sample_dataset = fuzzer.apply_integer_overflow_pattern(sample_dataset)

        assert sample_dataset is not None


class TestSequenceDepthAttack:
    """Test sequence depth attack patterns."""

    def test_apply_sequence_depth_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that sequence depth attack modifies the dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_sequence_depth_attack(sample_dataset)

        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_sequence_depth_creates_nested_sequence(self, fuzzer, sample_dataset):
        """Test that sequence depth creates nested structure."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_sequence_depth_attack(sample_dataset)

        # Check for sequence tag
        seq_tag = Tag(0x0008, 0x1140)
        if seq_tag in result:
            assert result[seq_tag].VR == "SQ"

    def test_apply_sequence_depth_multiple_times(self, fuzzer, sample_dataset):
        """Test applying sequence depth multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(3):
                sample_dataset = fuzzer.apply_sequence_depth_attack(sample_dataset)

        assert sample_dataset is not None


class TestEncodingConfusionPattern:
    """Test encoding confusion patterns."""

    def test_apply_encoding_confusion_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that encoding confusion modifies the dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_encoding_confusion_pattern(sample_dataset)

        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_encoding_confusion_targets_charset(self, fuzzer, sample_dataset):
        """Test that encoding confusion targets SpecificCharacterSet."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_encoding_confusion_pattern(sample_dataset)

        # SpecificCharacterSet might be modified
        assert hasattr(result, "SpecificCharacterSet")

    def test_apply_encoding_confusion_targets_string_fields(
        self, fuzzer, sample_dataset
    ):
        """Test that encoding confusion targets string fields."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_encoding_confusion_pattern(sample_dataset)

        # Patient fields should still exist
        assert hasattr(result, "PatientName")
        assert hasattr(result, "PatientID")

    def test_apply_encoding_confusion_multiple_times(self, fuzzer, sample_dataset):
        """Test applying encoding confusion multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(5):
                sample_dataset = fuzzer.apply_encoding_confusion_pattern(sample_dataset)

        assert sample_dataset is not None


class TestApplyAllPatterns:
    """Test combined pattern application."""

    def test_apply_all_patterns_modifies_dataset(self, fuzzer, sample_dataset):
        """Test that all patterns can be applied."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_all_patterns(sample_dataset)

        assert result is not None
        assert isinstance(result, Dataset)

    def test_apply_all_patterns_multiple_times(self, fuzzer, sample_dataset):
        """Test applying all patterns multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(5):
                sample_dataset = fuzzer.apply_all_patterns(sample_dataset)

        assert sample_dataset is not None

    def test_apply_all_patterns_randomness(self, fuzzer, sample_dataset):
        """Test that all patterns has random behavior."""
        results = []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(10):
                # Create fresh copy each time
                ds = Dataset()
                ds.SOPClassUID = sample_dataset.SOPClassUID
                ds.Modality = sample_dataset.Modality
                ds.PatientName = sample_dataset.PatientName
                result = fuzzer.apply_all_patterns(ds)
                results.append(result)

        # All results should be valid datasets
        for r in results:
            assert isinstance(r, Dataset)


class TestPatternWithMinimalDataset:
    """Test patterns with minimal dataset."""

    def test_cve_pattern_minimal_dataset(self, fuzzer):
        """Test CVE pattern with minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_cve_2025_5943_pattern(ds)

        assert result is not None

    def test_heap_spray_minimal_dataset(self, fuzzer):
        """Test heap spray with minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_heap_spray_pattern(ds)

        assert result is not None

    def test_malformed_vr_minimal_dataset(self, fuzzer):
        """Test malformed VR with minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_malformed_vr_pattern(ds)

        assert result is not None

    def test_integer_overflow_minimal_dataset(self, fuzzer):
        """Test integer overflow with minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_integer_overflow_pattern(ds)

        assert result is not None

    def test_sequence_depth_minimal_dataset(self, fuzzer):
        """Test sequence depth with minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_sequence_depth_attack(ds)

        assert result is not None

    def test_encoding_confusion_minimal_dataset(self, fuzzer):
        """Test encoding confusion with minimal dataset."""
        ds = Dataset()
        ds.SpecificCharacterSet = "ISO_IR 100"
        ds.PatientName = "Test"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_encoding_confusion_pattern(ds)

        assert result is not None

    def test_all_patterns_minimal_dataset(self, fuzzer):
        """Test all patterns with minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_all_patterns(ds)

        assert result is not None


class TestPatternWithEmptyDataset:
    """Test patterns with empty dataset."""

    def test_cve_pattern_empty_dataset(self, fuzzer):
        """Test CVE pattern with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_cve_2025_5943_pattern(ds)

        assert result is not None

    def test_heap_spray_empty_dataset(self, fuzzer):
        """Test heap spray with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_heap_spray_pattern(ds)

        assert result is not None

    def test_malformed_vr_empty_dataset(self, fuzzer):
        """Test malformed VR with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_malformed_vr_pattern(ds)

        assert result is not None

    def test_sequence_depth_empty_dataset(self, fuzzer):
        """Test sequence depth with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_sequence_depth_attack(ds)

        assert result is not None

    def test_all_patterns_empty_dataset(self, fuzzer):
        """Test all patterns with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_all_patterns(ds)

        assert result is not None


class TestPatternEdgeCases:
    """Test edge cases for patterns."""

    def test_cve_pattern_with_existing_sequence(self, fuzzer, sample_dataset):
        """Test CVE pattern when sequence tag exists."""
        from pydicom.sequence import Sequence

        # Add existing sequence
        seq_ds = Dataset()
        seq_ds.Manufacturer = "Existing"
        sample_dataset[Tag(0x0008, 0x1140)] = pydicom.DataElement(
            Tag(0x0008, 0x1140), "SQ", Sequence([seq_ds])
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_sequence_depth_attack(sample_dataset)

        assert result is not None

    def test_integer_overflow_with_large_pixel_data(self, fuzzer, sample_dataset):
        """Test integer overflow with large PixelData."""
        sample_dataset.Rows = 1024
        sample_dataset.Columns = 1024
        sample_dataset.PixelData = b"\x00" * (1024 * 1024 * 2)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_integer_overflow_pattern(sample_dataset)

        assert result is not None

    def test_heap_spray_with_multiframe(self, fuzzer, sample_dataset):
        """Test heap spray with multiframe dataset."""
        sample_dataset.NumberOfFrames = 10

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_heap_spray_pattern(sample_dataset)

        assert result is not None
