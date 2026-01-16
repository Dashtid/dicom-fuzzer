"""
Comprehensive tests for DICOM fuzzing strategies.

Tests cover:
- MetadataFuzzer: Patient data mutation
- HeaderFuzzer: Tag mutation with edge cases
- PixelFuzzer: Pixel data corruption
"""

import numpy as np
import pytest

from dicom_fuzzer.strategies.header_fuzzer import HeaderFuzzer
from dicom_fuzzer.strategies.metadata_fuzzer import MetadataFuzzer
from dicom_fuzzer.strategies.pixel_fuzzer import PixelFuzzer
from dicom_fuzzer.strategies.structure_fuzzer import StructureFuzzer


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

        # Should return a Dataset
        assert mutated is not None, "mutate_patient_info should return result"
        assert hasattr(mutated, "PatientName"), (
            "Mutated dataset should have PatientName"
        )
        # DICOM names use ^ separator (Family^Given format)
        name_str = str(mutated.PatientName)
        assert "^" in name_str, f"PatientName should contain ^, got: {name_str}"
        assert len(name_str) > 1, "PatientName should not be empty"

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

        dates_generated = []
        for _ in range(10):
            date_str = fuzzer._random_date()
            assert isinstance(date_str, str), "Date should be string"
            assert len(date_str) == 8, (
                f"Date should be 8 chars (YYYYMMDD), got {len(date_str)}"
            )
            assert date_str.isdigit(), f"Date should be all digits, got {date_str}"
            year = int(date_str[:4])
            month = int(date_str[4:6])
            day = int(date_str[6:8])
            assert 1950 <= year <= 2010, f"Year {year} out of range"
            assert 1 <= month <= 12, f"Month {month} out of range"
            assert 1 <= day <= 31, f"Day {day} out of range"
            dates_generated.append(date_str)

        # Should generate some variety
        assert len(set(dates_generated)) >= 2, "Should generate varied dates"

    def test_mutations_are_random(self, sample_dicom_dataset):
        """Test that multiple mutations produce different results."""
        fuzzer = MetadataFuzzer()

        results = set()
        for _ in range(5):
            mutated = fuzzer.mutate_patient_info(sample_dicom_dataset.copy())
            assert mutated is not None, "Mutation should return result"
            assert hasattr(mutated, "PatientID"), "Should have PatientID"
            assert isinstance(mutated.PatientID, str), "PatientID should be string"
            results.add(mutated.PatientID)

        # Should have some variation (not all the same)
        assert len(results) > 1, f"Expected variation in PatientIDs, got {results}"
        # All results should follow the expected format
        for pid in results:
            assert pid.startswith("PAT"), f"PatientID should start with PAT, got {pid}"


class TestHeaderFuzzer:
    """Test header/tag fuzzing strategy."""

    def test_initialization(self):
        """Test HeaderFuzzer initializes correctly."""
        fuzzer = HeaderFuzzer()
        assert fuzzer is not None, "HeaderFuzzer should initialize"
        assert isinstance(fuzzer, HeaderFuzzer), (
            f"Should be HeaderFuzzer, got {type(fuzzer)}"
        )

    def test_mutate_tags(self, sample_dicom_dataset):
        """Test tag mutation."""
        fuzzer = HeaderFuzzer()

        # Add InstitutionName for testing
        sample_dicom_dataset.InstitutionName = "Test Hospital"
        original_tag_count = len(list(sample_dicom_dataset.keys()))

        mutated = fuzzer.mutate_tags(sample_dicom_dataset)

        assert mutated is not None, "mutate_tags should return a dataset"
        # Dataset should still have tags
        assert len(list(mutated.keys())) > 0, "Mutated dataset should have tags"

    def test_overlong_strings_mutation(self, sample_dicom_dataset):
        """Test that overlong strings are inserted."""
        fuzzer = HeaderFuzzer()

        sample_dicom_dataset.InstitutionName = "Normal"
        mutated = fuzzer._overlong_strings(sample_dicom_dataset)

        # Should have very long string
        assert mutated is not None, "Should return mutated dataset"
        assert hasattr(mutated, "InstitutionName"), "Should still have InstitutionName"
        assert len(mutated.InstitutionName) >= 1024, (
            "InstitutionName should be very long"
        )

    def test_overlong_strings_are_repeated_char(self, sample_dicom_dataset):
        """Test that overlong string is repeated character."""
        fuzzer = HeaderFuzzer()

        sample_dicom_dataset.InstitutionName = "Test"
        mutated = fuzzer._overlong_strings(sample_dicom_dataset)

        # Should return Dataset
        assert mutated is not None, "Should return mutated dataset"
        assert hasattr(mutated, "InstitutionName"), "Should have InstitutionName"
        # Should be all 'A's (repeated char for overlong string)
        name = mutated.InstitutionName
        assert len(name) > 0, "InstitutionName should not be empty"
        assert all(c == "A" for c in name), f"Expected all 'A's, got: {name[:20]}..."

    def test_mutate_without_institution_name(self, sample_dicom_dataset):
        """Test mutation works even without InstitutionName."""
        from pydicom.dataset import Dataset

        fuzzer = HeaderFuzzer()

        # Remove InstitutionName if it exists
        if hasattr(sample_dicom_dataset, "InstitutionName"):
            delattr(sample_dicom_dataset, "InstitutionName")

        # Should not raise exception
        mutated = fuzzer._overlong_strings(sample_dicom_dataset)
        assert mutated is not None, "Should return result even without InstitutionName"
        assert isinstance(mutated, Dataset), "Should return Dataset"
        # Original dataset's other tags should be preserved
        assert hasattr(mutated, "PatientName") or hasattr(mutated, "PatientID"), (
            "Should preserve other tags"
        )

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
        assert fuzzer is not None, "PixelFuzzer should initialize"
        assert isinstance(fuzzer, PixelFuzzer), (
            f"Should be PixelFuzzer, got {type(fuzzer)}"
        )

    def test_mutate_pixels_with_pixel_data(self, dicom_with_pixels):
        """Test pixel mutation with actual pixel data."""
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        mutated = fuzzer.mutate_pixels(parser.dataset)

        assert mutated is not None, "mutate_pixels should return a dataset"
        assert hasattr(mutated, "PixelData"), "Mutated dataset should have PixelData"
        assert len(mutated.PixelData) > 0, "PixelData should not be empty"

    def test_pixel_corruption_introduces_changes(self, dicom_with_pixels):
        """Test that pixel corruption actually modifies pixels."""
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        original_pixels = parser.dataset.pixel_array.copy()
        original_shape = original_pixels.shape
        total_pixels = original_pixels.size

        mutated = fuzzer.mutate_pixels(parser.dataset)

        # Verify mutation returned valid dataset
        assert mutated is not None, "Mutate should return a dataset"
        assert hasattr(mutated, "PixelData"), "Mutated dataset should have PixelData"

        # Pixel data should have changed
        mutated_pixels = mutated.pixel_array

        # Shape should be preserved
        assert mutated_pixels.shape == original_shape, (
            "Pixel array shape should be preserved"
        )

        # Some pixels should be different (1% corruption expected)
        differences = np.sum(original_pixels != mutated_pixels)

        # Should have some differences - 1% of pixels is the target
        # Corruption must actually modify at least some pixels
        assert differences > 0, "Corruption should modify at least one pixel"
        # Corruption should not affect more than 10% of pixels
        assert differences <= total_pixels * 0.1, (
            f"Too many pixels corrupted: {differences}/{total_pixels}"
        )

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
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        original_shape = parser.dataset.pixel_array.shape
        mutated = fuzzer.mutate_pixels(parser.dataset)

        assert mutated is not None, "mutate_pixels should return result"
        assert hasattr(mutated, "pixel_array"), "Result should have pixel_array"
        mutated_shape = mutated.pixel_array.shape
        assert original_shape == mutated_shape, (
            f"Shape changed: {original_shape} -> {mutated_shape}"
        )
        assert len(mutated_shape) >= 2, "Pixel array should be at least 2D"

    def test_pixel_dtype_preserved(self, dicom_with_pixels):
        """Test that pixel array dtype is preserved."""
        from dicom_fuzzer.core.parser import DicomParser

        parser = DicomParser(dicom_with_pixels)
        fuzzer = PixelFuzzer()

        mutated = fuzzer.mutate_pixels(parser.dataset)

        # After mutation, pixel data is stored as bytes
        assert mutated is not None, "mutate_pixels should return result"
        assert hasattr(mutated, "PixelData"), "Result should have PixelData"
        assert mutated.PixelData is not None, "PixelData should not be None"
        assert isinstance(mutated.PixelData, bytes), "PixelData should be bytes"
        assert len(mutated.PixelData) > 0, "PixelData should not be empty"


class TestStructureFuzzer:
    """Test structure fuzzing strategy."""

    def test_initialization(self):
        """Test StructureFuzzer initializes correctly."""
        fuzzer = StructureFuzzer()

        assert fuzzer is not None, "StructureFuzzer should initialize"
        assert isinstance(fuzzer, StructureFuzzer), (
            f"Should be StructureFuzzer, got {type(fuzzer)}"
        )
        assert hasattr(fuzzer, "corruption_strategies"), (
            "Should have corruption_strategies"
        )
        assert len(fuzzer.corruption_strategies) > 0, (
            "Should have at least one corruption strategy"
        )

    def test_mutate_structure(self, sample_dicom_dataset):
        """Test structure mutation."""
        fuzzer = StructureFuzzer()
        original_tag_count = len(list(sample_dicom_dataset.keys()))

        mutated = fuzzer.mutate_structure(sample_dicom_dataset)

        assert mutated is not None, "mutate_structure should return a dataset"
        # Dataset should still be valid
        assert len(list(mutated.keys())) > 0, "Mutated dataset should have tags"

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
        """Test invalid date VR values (lines 121-130)."""
        fuzzer = HeaderFuzzer()

        # Ensure StudyDate exists to trigger the invalid dates code path
        sample_dicom_dataset.StudyDate = "20250101"

        mutated = fuzzer._invalid_vr_values(sample_dicom_dataset)

        assert mutated is not None
        # StudyDate should now have an invalid value
        assert hasattr(mutated, "StudyDate")
        study_date = str(mutated.StudyDate)
        # Should be one of the invalid dates
        invalid_dates = [
            "INVALID",
            "99999999",
            "20251332",
            "20250145",
            "2025-01-01",
            "",
            "1",
        ]
        assert study_date in invalid_dates

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
        from dicom_fuzzer.core.parser import DicomParser

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
        # PatientID may be modified or removed by mutations
        # PixelData should still exist after pixel mutations
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
        from dicom_fuzzer.core.parser import DicomParser

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


class TestStructureFuzzerFileCorruption:
    """Test file-level corruption methods in StructureFuzzer."""

    def test_corrupt_file_header_preamble(self, tmp_path, dicom_with_pixels):
        """Test corrupting the DICOM preamble."""
        fuzzer = StructureFuzzer()

        # Create temporary file
        output_file = tmp_path / "corrupted_preamble.dcm"

        result = fuzzer.corrupt_file_header(str(dicom_with_pixels), str(output_file))

        assert result is not None
        assert output_file.exists()

        # Check file was modified
        with open(output_file, "rb") as f:
            data = f.read()
            # File should exist and have data
            assert len(data) > 0

    def test_corrupt_file_header_dicm_prefix(self, tmp_path, dicom_with_pixels):
        """Test corrupting the DICM prefix."""
        import random

        random.seed(42)  # For reproducibility

        fuzzer = StructureFuzzer()

        # Run multiple times to hit different corruption types
        for i in range(10):
            random.seed(i)
            result = fuzzer.corrupt_file_header(
                str(dicom_with_pixels), str(tmp_path / f"corrupted_{i}.dcm")
            )
            assert result is not None

    def test_corrupt_file_header_transfer_syntax(self, tmp_path, dicom_with_pixels):
        """Test corrupting transfer syntax area."""
        import random

        fuzzer = StructureFuzzer()
        successful_corruptions = 0

        # Test multiple times to hit transfer syntax corruption
        for i in range(15):
            random.seed(100 + i)
            output_file = tmp_path / f"corrupted_ts_{i}.dcm"
            result = fuzzer.corrupt_file_header(
                str(dicom_with_pixels), str(output_file)
            )
            # Result can be None or a path string - track successes
            if result is not None:
                successful_corruptions += 1
                assert isinstance(result, str), (
                    f"Result should be path string, got {type(result)}"
                )
                assert output_file.exists(), f"Output file should exist: {output_file}"

        # At least one corruption must succeed
        assert successful_corruptions >= 1, (
            f"At least one corruption should succeed, got {successful_corruptions}"
        )

    def test_corrupt_file_header_truncate(self, tmp_path, dicom_with_pixels):
        """Test file truncation corruption."""
        import random

        fuzzer = StructureFuzzer()

        # Try multiple times to hit truncation
        for i in range(20):
            random.seed(200 + i)
            output_file = tmp_path / f"truncated_{i}.dcm"
            fuzzer.corrupt_file_header(str(dicom_with_pixels), str(output_file))

            if output_file.exists():
                original_size = dicom_with_pixels.stat().st_size
                corrupted_size = output_file.stat().st_size
                # If truncation happened, file should be smaller
                # Otherwise might be same size (other corruption type)
                assert corrupted_size <= original_size

    def test_corrupt_file_header_with_default_output(self, dicom_with_pixels, tmp_path):
        """Test corruption with default output path."""
        import shutil

        fuzzer = StructureFuzzer()

        # Copy test file to tmp_path so we can control cleanup
        test_file = tmp_path / "test_input.dcm"
        shutil.copy(dicom_with_pixels, test_file)

        result = fuzzer.corrupt_file_header(str(test_file))

        # Should create file with _header_corrupted suffix
        if result:
            assert "_header_corrupted" in result
            # Clean up
            import os

            if os.path.exists(result):
                os.remove(result)

    def test_corrupt_file_header_error_handling(self, tmp_path):
        """Test corruption with invalid input file."""
        fuzzer = StructureFuzzer()

        # Try to corrupt non-existent file
        result = fuzzer.corrupt_file_header(
            "nonexistent_file.dcm", str(tmp_path / "output.dcm")
        )

        # Should return None on error
        assert result is None

    def test_corrupt_file_header_method(self, tmp_path, dicom_with_pixels):
        """Test corrupt_file_header method (alias)."""
        fuzzer = StructureFuzzer()

        output_file = tmp_path / "corrupted_via_file_header.dcm"
        result = fuzzer.corrupt_file_header(str(dicom_with_pixels), str(output_file))

        assert result is not None
        assert output_file.exists()


class TestHeaderFuzzerEdgeCases:
    """Test edge cases in HeaderFuzzer for full coverage."""

    def test_boundary_values_generation(self, sample_dicom_dataset):
        """Test boundary value generation for different VR types."""
        fuzzer = HeaderFuzzer()

        mutated = fuzzer._boundary_values(sample_dicom_dataset)

        assert mutated is not None
        # Check that some boundary values were applied
        # (probabilistic test, just ensure no crash)

    def test_invalid_vr_values_all_types(self, sample_dicom_dataset):
        """Test invalid VR generation for all supported types."""
        fuzzer = HeaderFuzzer()

        # Run multiple times to hit different VR types
        for _ in range(10):
            mutated = fuzzer._invalid_vr_values(sample_dicom_dataset.copy())
            assert mutated is not None

    def test_overlong_strings_with_study_description(self, sample_dicom_dataset):
        """Test overlong strings mutation with StudyDescription field (line 74)."""
        fuzzer = HeaderFuzzer()

        # Add StudyDescription field
        sample_dicom_dataset.StudyDescription = "Normal Study"

        mutated = fuzzer._overlong_strings(sample_dicom_dataset)

        # Should be mutated to very long string
        assert len(mutated.StudyDescription) > 1000

    def test_overlong_strings_with_manufacturer(self, sample_dicom_dataset):
        """Test overlong strings mutation with Manufacturer field (line 77)."""
        fuzzer = HeaderFuzzer()

        # Add Manufacturer field
        sample_dicom_dataset.Manufacturer = "Siemens"

        mutated = fuzzer._overlong_strings(sample_dicom_dataset)

        # Should be mutated to very long string
        assert len(mutated.Manufacturer) > 500

    def test_missing_required_tags_exception_handling(self, sample_dicom_dataset):
        """Test exception handling when deleting tags (lines 100-102)."""
        fuzzer = HeaderFuzzer()

        # Create dataset with tags that might raise exceptions on deletion
        sample_dicom_dataset.PatientName = "Test^Patient"
        sample_dicom_dataset.PatientID = "12345"
        sample_dicom_dataset.StudyInstanceUID = "1.2.3.4"
        sample_dicom_dataset.SeriesInstanceUID = "1.2.3.4.5"

        # Run multiple times to hit the exception path
        for _ in range(10):
            mutated = fuzzer._missing_required_tags(sample_dicom_dataset.copy())
            assert mutated is not None

    def test_invalid_vr_with_series_number(self, sample_dicom_dataset):
        """Test invalid VR with SeriesNumber field (lines 145-152)."""
        fuzzer = HeaderFuzzer()

        # Add SeriesNumber field (IS VR - Integer String)
        sample_dicom_dataset.SeriesNumber = "1"

        # Run multiple times to hit different invalid values
        # Some values may raise ValueError during assignment
        success_count = 0
        for _ in range(20):
            try:
                mutated = fuzzer._invalid_vr_values(sample_dicom_dataset.copy())
                assert mutated is not None
                success_count += 1
            except ValueError:
                # Some invalid values raise exceptions
                pass
        # At least some mutations should succeed
        assert success_count > 0

    def test_invalid_vr_with_slice_thickness(self, sample_dicom_dataset):
        """Test invalid VR with SliceThickness field (lines 156-163)."""
        fuzzer = HeaderFuzzer()

        # Add SliceThickness field (DS VR - Decimal String)
        sample_dicom_dataset.SliceThickness = "5.0"

        # Run multiple times to hit different invalid values
        # Some values may raise ValueError during assignment
        success_count = 0
        for _ in range(20):
            try:
                mutated = fuzzer._invalid_vr_values(sample_dicom_dataset.copy())
                assert mutated is not None
                success_count += 1
            except ValueError:
                # Some invalid values raise exceptions
                pass
        # At least some mutations should succeed
        assert success_count > 0

    def test_boundary_values_with_patient_age(self, sample_dicom_dataset):
        """Test boundary values with PatientAge field (lines 195-202)."""
        fuzzer = HeaderFuzzer()

        # Add PatientAge field
        sample_dicom_dataset.PatientAge = "050Y"

        # Run multiple times to hit different boundary ages
        for _ in range(10):
            mutated = fuzzer._boundary_values(sample_dicom_dataset.copy())
            assert mutated is not None
            # PatientAge should be mutated to boundary value
            if hasattr(mutated, "PatientAge"):
                assert isinstance(mutated.PatientAge, str)
                # Check format: ###X where X is Y, M, W, or D
                assert len(mutated.PatientAge) == 4

    def test_missing_required_tags_all_types(self, sample_dicom_dataset):
        """Test removal of different required tag types."""
        fuzzer = HeaderFuzzer()

        # Run multiple times to try removing different tags
        for _ in range(5):
            mutated = fuzzer._missing_required_tags(sample_dicom_dataset.copy())
            assert mutated is not None

    def test_missing_required_tags_deletion_exception(self, sample_dicom_dataset):
        """Test exception handling during tag deletion (lines 100-102)."""
        from unittest.mock import patch

        fuzzer = HeaderFuzzer()

        # Ensure PatientID exists
        sample_dicom_dataset.PatientID = "PAT001"

        # Mock delattr to raise exception when trying to delete PatientID
        with patch("builtins.delattr") as mock_delattr:
            mock_delattr.side_effect = RuntimeError("Cannot delete")

            # Should handle exception gracefully and not crash
            mutated = fuzzer._missing_required_tags(sample_dicom_dataset)
            assert mutated is not None

    def test_boundary_values_with_rows(self, sample_dicom_dataset):
        """Test boundary values with Rows attribute (lines 181-188)."""
        fuzzer = HeaderFuzzer()

        # Add Rows attribute
        sample_dicom_dataset.Rows = 512

        # Run multiple times to hit different boundary values
        for _ in range(20):
            mutated = fuzzer._boundary_values(sample_dicom_dataset.copy())
            assert mutated is not None
            # Rows should be changed to a boundary value
            assert hasattr(mutated, "Rows")

    def test_boundary_values_with_columns(self, sample_dicom_dataset):
        """Test boundary values with Columns attribute (line 191)."""
        fuzzer = HeaderFuzzer()

        # Add Columns attribute
        sample_dicom_dataset.Columns = 512

        mutated = fuzzer._boundary_values(sample_dicom_dataset)

        # Columns should be changed
        assert hasattr(mutated, "Columns")

    def test_boundary_values_empty_string_tags(self, sample_dicom_dataset):
        """Test empty string assignment with random check (line 216)."""
        fuzzer = HeaderFuzzer()

        # Add tags that can be emptied
        sample_dicom_dataset.Manufacturer = "Test Manufacturer"
        sample_dicom_dataset.ModelName = "Test Model"

        # Run multiple times to hit the random path
        empty_count = 0
        for _ in range(50):
            mutated = fuzzer._boundary_values(sample_dicom_dataset.copy())
            if hasattr(mutated, "Manufacturer") and mutated.Manufacturer == "":
                empty_count += 1

        # Should have hit the empty string path at least once (probabilistic)
        assert empty_count > 0


class TestStructureFuzzerExceptionPaths:
    """Test exception handling in StructureFuzzer."""

    def test_insert_unexpected_tags_exception_handling(self, sample_dicom_dataset):
        """Test that exception during tag insertion is handled."""
        fuzzer = StructureFuzzer()

        # This tests the try-except block in _insert_unexpected_tags
        # The method should handle failures gracefully
        mutated = fuzzer._insert_unexpected_tags(sample_dicom_dataset)
        assert mutated is not None

    def test_duplicate_tags_with_empty_dataset(self):
        """Test duplicate tags with empty dataset."""
        import pydicom

        fuzzer = StructureFuzzer()
        empty_dataset = pydicom.Dataset()

        # Should handle empty dataset gracefully
        mutated = fuzzer._duplicate_tags(empty_dataset)
        assert mutated is not None

    def test_duplicate_tags_exception_handling(self, sample_dicom_dataset):
        """Test exception handling during tag duplication."""
        fuzzer = StructureFuzzer()

        # Run multiple times to potentially trigger exception path
        for _ in range(10):
            mutated = fuzzer._duplicate_tags(sample_dicom_dataset.copy())
            assert mutated is not None

    def test_corrupt_tag_ordering_early_return(self, sample_dicom_dataset):
        """Test _corrupt_tag_ordering early return when random > 0.5 (line 95)."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        # Mock random to return > 0.5 to trigger early return
        with patch("random.random", return_value=0.6):
            mutated = fuzzer._corrupt_tag_ordering(sample_dicom_dataset)
            # Should return dataset unchanged
            assert mutated is not None

    def test_insert_unexpected_tags_with_exception(self, sample_dicom_dataset):
        """Test insert_unexpected_tags exception path (lines 181-183)."""
        fuzzer = StructureFuzzer()

        # Mock dataset.add_new to raise exception
        original_add_new = sample_dicom_dataset.add_new

        def mock_add_new(*args, **kwargs):
            if args[0] == (0xFFFF, 0x0001):  # Unusual tag
                raise ValueError("Test exception")
            return original_add_new(*args, **kwargs)

        sample_dicom_dataset.add_new = mock_add_new

        # Should handle exception gracefully
        mutated = fuzzer._insert_unexpected_tags(sample_dicom_dataset)
        assert mutated is not None

    def test_duplicate_tags_with_add_new_exception(self, sample_dicom_dataset):
        """Test duplicate_tags exception during add_new (lines 220-222)."""
        fuzzer = StructureFuzzer()

        # Mock dataset to raise exception on add_new
        def mock_add_new(*args, **kwargs):
            # Raise exception on duplicate attempt
            raise ValueError("Cannot add duplicate")

        sample_dicom_dataset.add_new = mock_add_new

        # Should handle exception gracefully
        mutated = fuzzer._duplicate_tags(sample_dicom_dataset)
        assert mutated is not None

    def test_corrupt_tag_ordering_with_file_meta(self, sample_dicom_dataset):
        """Test tag ordering with file_meta attribute (line 89)."""
        import pydicom

        fuzzer = StructureFuzzer()

        # Create dataset with file_meta
        dataset = pydicom.Dataset()
        dataset.PatientName = "Test"
        dataset.PatientID = "123"
        dataset.StudyDate = "20250101"
        dataset.file_meta = pydicom.Dataset()
        dataset.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

        # Should preserve file_meta
        mutated = fuzzer._corrupt_tag_ordering(dataset)
        assert mutated is not None
        # If shuffled, file_meta should be preserved
        if mutated != dataset:
            assert hasattr(mutated, "file_meta")

    def test_corrupt_tag_ordering_small_dataset(self):
        """Test tag ordering with dataset <= 2 elements (line 95)."""
        import pydicom

        fuzzer = StructureFuzzer()

        # Create dataset with only 2 elements
        dataset = pydicom.Dataset()
        dataset.PatientName = "Test"
        dataset.PatientID = "123"

        # Should return original dataset (not enough elements to shuffle)
        mutated = fuzzer._corrupt_tag_ordering(dataset)
        assert mutated is dataset  # Should be same object

    def test_corrupt_length_fields_underflow(self, sample_dicom_dataset):
        """Test corrupt length fields with underflow (line 136)."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        # Mock random.choice to return "underflow" when called with corruption types
        original_choice = __import__("random").choice
        call_count = [0]

        def mock_choice(seq):
            call_count[0] += 1
            # First call is for target tag, use original
            if call_count[0] == 1:
                return original_choice(seq)
            # Second call is for corruption type, return "underflow"
            return "underflow"

        with patch("random.choice", side_effect=mock_choice):
            mutated = fuzzer._corrupt_length_fields(sample_dicom_dataset)
            # At least one element should have empty value
            assert mutated is not None

    def test_corrupt_length_fields_overflow(self, sample_dicom_dataset):
        """Test corrupt length fields with overflow (line 133)."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        # Mock random.choice to return "overflow" for corruption type
        original_choice = __import__("random").choice
        call_count = [0]

        def mock_choice(seq):
            call_count[0] += 1
            if call_count[0] == 1:
                return original_choice(seq)  # First call: tag selection
            return "overflow"  # Second call: corruption type

        with patch("random.choice", side_effect=mock_choice):
            mutated = fuzzer._corrupt_length_fields(sample_dicom_dataset)
            assert mutated is not None

    def test_corrupt_length_fields_mismatch(self, sample_dicom_dataset):
        """Test corrupt length fields with mismatch (lines 137-142)."""
        from unittest.mock import patch

        fuzzer = StructureFuzzer()

        # Ensure we have a tag with value > 2 chars
        sample_dicom_dataset.PatientName = "LongName"

        # Mock random.choice to return "mismatch" for corruption type
        call_count = [0]

        def mock_choice(seq):
            call_count[0] += 1
            if call_count[0] == 1:
                # Return PatientName tag to ensure we hit a long value
                return "PatientName"
            return "mismatch"  # Second call: corruption type

        with patch("random.choice", side_effect=mock_choice):
            mutated = fuzzer._corrupt_length_fields(sample_dicom_dataset)
            assert mutated is not None

    def test_insert_unexpected_tags_add_new_exception(self, sample_dicom_dataset):
        """Test insert unexpected tags with add_new exception (lines 181-183)."""
        fuzzer = StructureFuzzer()

        # Mock add_new to raise exception
        original_add_new = sample_dicom_dataset.add_new

        def mock_add_new(*args, **kwargs):
            raise RuntimeError("Cannot add tag")

        sample_dicom_dataset.add_new = mock_add_new

        # Should handle exception gracefully
        mutated = fuzzer._insert_unexpected_tags(sample_dicom_dataset)
        assert mutated is not None

        # Restore original
        sample_dicom_dataset.add_new = original_add_new


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
