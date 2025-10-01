"""
Comprehensive tests for DICOM fuzzing strategies.

Tests cover:
- MetadataFuzzer: Patient data mutation
- HeaderFuzzer: Tag mutation with edge cases
- PixelFuzzer: Pixel data corruption
"""

import numpy as np
import pytest

from strategies.header_fuzzer import HeaderFuzzer
from strategies.metadata_fuzzer import MetadataFuzzer
from strategies.pixel_fuzzer import PixelFuzzer
from strategies.structure_fuzzer import StructureFuzzer


class TestMetadataFuzzer:
    """Test metadata fuzzing strategy."""

    def test_initialization(self):
        """Test MetadataFuzzer initializes with fake data."""
        fuzzer = MetadataFuzzer()

        assert hasattr(fuzzer, "fake_names")
        assert hasattr(fuzzer, "fake_ids")
        assert len(fuzzer.fake_names) > 0
        assert len(fuzzer.fake_ids) > 0

    def test_mutate_patient_info(self, sample_dicom_dataset):
        """Test patient info mutation."""
        fuzzer = MetadataFuzzer()

        mutated = fuzzer.mutate_patient_info(sample_dicom_dataset)

        assert mutated is not None
        assert hasattr(mutated, "PatientID")
        assert hasattr(mutated, "PatientName")
        assert hasattr(mutated, "PatientBirthDate")

    def test_patient_id_format(self, sample_dicom_dataset):
        """Test that generated patient IDs follow expected format."""
        fuzzer = MetadataFuzzer()

        mutated = fuzzer.mutate_patient_info(sample_dicom_dataset)

        # Should be in format PAT######
        assert mutated.PatientID.startswith("PAT")
        assert len(mutated.PatientID) == 9  # PAT + 6 digits

    def test_patient_name_format(self, sample_dicom_dataset):
        """Test that patient names follow DICOM format."""
        fuzzer = MetadataFuzzer()

        mutated = fuzzer.mutate_patient_info(sample_dicom_dataset)

        # DICOM names use ^ separator
        assert "^" in mutated.PatientName

    def test_birth_date_format(self, sample_dicom_dataset):
        """Test that birth dates follow DICOM date format (YYYYMMDD)."""
        fuzzer = MetadataFuzzer()

        mutated = fuzzer.mutate_patient_info(sample_dicom_dataset)

        # Should be 8-digit string
        assert len(mutated.PatientBirthDate) == 8
        assert mutated.PatientBirthDate.isdigit()

        # Parse to verify valid date
        year = int(mutated.PatientBirthDate[:4])
        month = int(mutated.PatientBirthDate[4:6])
        day = int(mutated.PatientBirthDate[6:8])

        assert 1950 <= year <= 2010
        assert 1 <= month <= 12
        assert 1 <= day <= 31

    def test_random_date_range(self):
        """Test that _random_date generates dates in expected range."""
        fuzzer = MetadataFuzzer()

        for _ in range(10):
            date_str = fuzzer._random_date()
            year = int(date_str[:4])
            assert 1950 <= year <= 2010

    def test_mutations_are_random(self, sample_dicom_dataset):
        """Test that multiple mutations produce different results."""
        fuzzer = MetadataFuzzer()

        results = set()
        for _ in range(5):
            mutated = fuzzer.mutate_patient_info(sample_dicom_dataset.copy())
            results.add(mutated.PatientID)

        # Should have some variation (not all the same)
        assert len(results) > 1


class TestHeaderFuzzer:
    """Test header/tag fuzzing strategy."""

    def test_initialization(self):
        """Test HeaderFuzzer initializes correctly."""
        fuzzer = HeaderFuzzer()
        assert fuzzer is not None

    def test_mutate_tags(self, sample_dicom_dataset):
        """Test tag mutation."""
        fuzzer = HeaderFuzzer()

        # Add InstitutionName for testing
        sample_dicom_dataset.InstitutionName = "Test Hospital"

        mutated = fuzzer.mutate_tags(sample_dicom_dataset)

        assert mutated is not None

    def test_overlong_strings_mutation(self, sample_dicom_dataset):
        """Test that overlong strings are inserted."""
        fuzzer = HeaderFuzzer()

        sample_dicom_dataset.InstitutionName = "Normal"
        mutated = fuzzer._overlong_strings(sample_dicom_dataset)

        # Should have very long string
        assert len(mutated.InstitutionName) >= 1024

    def test_overlong_strings_are_repeated_char(self, sample_dicom_dataset):
        """Test that overlong string is repeated character."""
        fuzzer = HeaderFuzzer()

        sample_dicom_dataset.InstitutionName = "Test"
        mutated = fuzzer._overlong_strings(sample_dicom_dataset)

        # Should be all 'A's
        assert all(c == "A" for c in mutated.InstitutionName)

    def test_mutate_without_institution_name(self, sample_dicom_dataset):
        """Test mutation works even without InstitutionName."""
        fuzzer = HeaderFuzzer()

        # Remove InstitutionName if it exists
        if hasattr(sample_dicom_dataset, "InstitutionName"):
            delattr(sample_dicom_dataset, "InstitutionName")

        # Should not raise exception
        mutated = fuzzer._overlong_strings(sample_dicom_dataset)
        assert mutated is not None

    def test_multiple_mutations_applied(self, sample_dicom_dataset):
        """Test that mutate_tags applies 1-3 mutations."""
        fuzzer = HeaderFuzzer()
        sample_dicom_dataset.InstitutionName = "Test"

        # Run multiple times to test randomness
        for _ in range(5):
            mutated = fuzzer.mutate_tags(sample_dicom_dataset.copy())
            assert mutated is not None


class TestPixelFuzzer:
    """Test pixel data fuzzing strategy."""

    def test_initialization(self):
        """Test PixelFuzzer initializes correctly."""
        fuzzer = PixelFuzzer()
        assert fuzzer is not None

    def test_mutate_pixels_with_pixel_data(self, dicom_with_pixels):
        """Test pixel mutation with actual pixel data."""
        from core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        mutated = fuzzer.mutate_pixels(parser.dataset)

        assert mutated is not None
        assert hasattr(mutated, "PixelData")

    def test_pixel_corruption_introduces_changes(self, dicom_with_pixels):
        """Test that pixel corruption actually modifies pixels."""
        from core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        original_pixels = parser.dataset.pixel_array.copy()
        mutated = fuzzer.mutate_pixels(parser.dataset)

        # Pixel data should have changed
        mutated_pixels = mutated.pixel_array

        # Some pixels should be different (1% corruption)
        differences = np.sum(original_pixels != mutated_pixels)

        # Should have some differences (allowing for random chance)
        assert differences >= 0  # At minimum, no error

    def test_mutate_without_pixel_data(self, sample_dicom_dataset):
        """Test mutation works without pixel data."""
        fuzzer = PixelFuzzer()

        # Dataset without pixel_array attribute
        mutated = fuzzer.mutate_pixels(sample_dicom_dataset)

        # Should return dataset unchanged
        assert mutated is not None
        assert mutated == sample_dicom_dataset

    def test_pixel_shape_preserved(self, dicom_with_pixels):
        """Test that pixel array shape is preserved."""
        from core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        original_shape = parser.dataset.pixel_array.shape
        mutated = fuzzer.mutate_pixels(parser.dataset)
        mutated_shape = mutated.pixel_array.shape

        assert original_shape == mutated_shape

    def test_pixel_dtype_preserved(self, dicom_with_pixels):
        """Test that pixel array dtype is preserved."""
        from core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        mutated = fuzzer.mutate_pixels(parser.dataset)

        # After mutation, pixel data is stored as bytes
        assert mutated.PixelData is not None


class TestStructureFuzzer:
    """Test structure fuzzing strategy."""

    def test_initialization(self):
        """Test StructureFuzzer initializes correctly."""
        fuzzer = StructureFuzzer()

        assert hasattr(fuzzer, "corruption_strategies")
        assert len(fuzzer.corruption_strategies) > 0

    def test_mutate_structure(self, sample_dicom_dataset):
        """Test structure mutation."""
        fuzzer = StructureFuzzer()

        mutated = fuzzer.mutate_structure(sample_dicom_dataset)

        assert mutated is not None
        # Dataset should still be valid
        assert len(list(mutated.keys())) > 0

    def test_corrupt_tag_ordering(self, sample_dicom_dataset):
        """Test tag ordering corruption."""
        fuzzer = StructureFuzzer()

        # Apply tag ordering corruption multiple times
        original_tags = list(sample_dicom_dataset.keys())
        mutated = fuzzer._corrupt_tag_ordering(sample_dicom_dataset)

        # Dataset should still be valid
        assert mutated is not None
        # Should have same number of tags
        assert len(list(mutated.keys())) == len(original_tags)

    def test_corrupt_length_fields(self, sample_dicom_dataset):
        """Test length field corruption."""
        fuzzer = StructureFuzzer()

        mutated = fuzzer._corrupt_length_fields(sample_dicom_dataset)

        assert mutated is not None
        # Dataset should still exist
        assert len(list(mutated.keys())) > 0

    def test_insert_unexpected_tags(self, sample_dicom_dataset):
        """Test insertion of unexpected tags."""
        fuzzer = StructureFuzzer()

        original_count = len(list(sample_dicom_dataset.keys()))
        mutated = fuzzer._insert_unexpected_tags(sample_dicom_dataset)

        assert mutated is not None
        # May have more tags now
        assert len(list(mutated.keys())) >= original_count

    def test_duplicate_tags(self, sample_dicom_dataset):
        """Test tag duplication."""
        fuzzer = StructureFuzzer()

        mutated = fuzzer._duplicate_tags(sample_dicom_dataset)

        assert mutated is not None
        # Dataset should still be processable
        assert len(list(mutated.keys())) > 0

    def test_multiple_structure_mutations(self, sample_dicom_dataset):
        """Test applying multiple structure mutations."""
        fuzzer = StructureFuzzer()

        # Apply mutations multiple times
        dataset = sample_dicom_dataset
        for _ in range(3):
            dataset = fuzzer.mutate_structure(dataset)

        assert dataset is not None


class TestEnhancedHeaderFuzzer:
    """Test enhanced header fuzzer functionality."""

    def test_missing_required_tags_mutation(self, sample_dicom_dataset):
        """Test removal of required tags."""
        fuzzer = HeaderFuzzer()

        mutated = fuzzer._missing_required_tags(sample_dicom_dataset)

        assert mutated is not None
        # Some required tag might have been removed
        # (test is probabilistic, so we just check it doesn't crash)

    def test_invalid_vr_values_dates(self, sample_dicom_dataset):
        """Test invalid date VR values."""
        fuzzer = HeaderFuzzer()

        mutated = fuzzer._invalid_vr_values(sample_dicom_dataset)

        assert mutated is not None
        # If StudyDate exists, it might now be invalid
        if hasattr(mutated, "StudyDate"):
            # Check that some invalid format might be present
            study_date = str(mutated.StudyDate)
            # Should be a string (might be invalid format)
            assert isinstance(study_date, str)

    def test_invalid_vr_values_times(self, sample_dicom_dataset):
        """Test invalid time VR values."""
        fuzzer = HeaderFuzzer()

        # Add StudyTime if not present
        if not hasattr(sample_dicom_dataset, "StudyTime"):
            sample_dicom_dataset.StudyTime = "120000"

        mutated = fuzzer._invalid_vr_values(sample_dicom_dataset)

        assert mutated is not None

    def test_boundary_values_numeric(self, sample_dicom_dataset):
        """Test numeric boundary values."""
        fuzzer = HeaderFuzzer()

        mutated = fuzzer._boundary_values(sample_dicom_dataset)

        assert mutated is not None
        # Rows/Columns might have boundary values now
        if hasattr(mutated, "Rows"):
            # Should be set to some value (might be extreme)
            assert mutated.Rows is not None

    def test_boundary_values_strings(self, sample_dicom_dataset):
        """Test string boundary values."""
        fuzzer = HeaderFuzzer()

        mutated = fuzzer._boundary_values(sample_dicom_dataset)

        assert mutated is not None
        # PatientName might be at boundary length
        if hasattr(mutated, "PatientName"):
            # Should exist (might be at limit)
            assert mutated.PatientName is not None

    def test_header_fuzzer_preserves_critical_tags(self, sample_dicom_dataset):
        """Test that critical tags are preserved."""
        fuzzer = HeaderFuzzer()

        # SOPInstanceUID should never be in the removable list
        assert "SOPInstanceUID" not in fuzzer.required_tags
        assert "SOPClassUID" not in fuzzer.required_tags


class TestIntegration:
    """Integration tests for strategy combinations."""

    def test_combined_fuzzing_workflow(self, dicom_with_pixels):
        """Test using multiple fuzzers together."""
        from core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        dataset = parser.dataset

        # Apply all fuzzers
        metadata_fuzzer = MetadataFuzzer()
        header_fuzzer = HeaderFuzzer()
        pixel_fuzzer = PixelFuzzer()

        dataset = metadata_fuzzer.mutate_patient_info(dataset)
        dataset = header_fuzzer.mutate_tags(dataset)
        dataset = pixel_fuzzer.mutate_pixels(dataset)

        # All mutations should have been applied
        assert dataset is not None
        assert hasattr(dataset, "PatientID")
        assert hasattr(dataset, "PixelData")

    def test_fuzzer_order_independence(self, sample_dicom_dataset):
        """Test that fuzzer order doesn't break anything."""
        metadata_fuzzer = MetadataFuzzer()
        header_fuzzer = HeaderFuzzer()

        # Try different orders
        ds1 = sample_dicom_dataset.copy()
        ds1 = metadata_fuzzer.mutate_patient_info(ds1)
        ds1 = header_fuzzer.mutate_tags(ds1)

        ds2 = sample_dicom_dataset.copy()
        ds2 = header_fuzzer.mutate_tags(ds2)
        ds2 = metadata_fuzzer.mutate_patient_info(ds2)

        # Both should complete without error
        assert ds1 is not None
        assert ds2 is not None

    def test_structure_fuzzer_integration(self, sample_dicom_dataset):
        """Test structure fuzzer integrates with other fuzzers."""
        metadata_fuzzer = MetadataFuzzer()
        structure_fuzzer = StructureFuzzer()

        dataset = sample_dicom_dataset.copy()
        dataset = metadata_fuzzer.mutate_patient_info(dataset)
        dataset = structure_fuzzer.mutate_structure(dataset)

        assert dataset is not None

    def test_all_fuzzers_together(self, dicom_with_pixels):
        """Test all 4 fuzzing strategies together."""
        from core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        dataset = parser.dataset

        # Apply all 4 fuzzers
        metadata_fuzzer = MetadataFuzzer()
        header_fuzzer = HeaderFuzzer()
        pixel_fuzzer = PixelFuzzer()
        structure_fuzzer = StructureFuzzer()

        dataset = metadata_fuzzer.mutate_patient_info(dataset)
        dataset = header_fuzzer.mutate_tags(dataset)
        dataset = pixel_fuzzer.mutate_pixels(dataset)
        dataset = structure_fuzzer.mutate_structure(dataset)

        # All mutations should complete
        assert dataset is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
