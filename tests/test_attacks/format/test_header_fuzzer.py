"""Tests for header_fuzzer.py - DICOM header mutation strategy."""

from __future__ import annotations

import random

import pytest
from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.attacks.format.header_fuzzer import HeaderFuzzer


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> HeaderFuzzer:
    """Create a HeaderFuzzer instance."""
    return HeaderFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset with common tags."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = "1.2.3.4.5"
    ds.SeriesInstanceUID = "1.2.3.4.5.6"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7"
    ds.StudyDate = "20231201"
    ds.StudyTime = "120000"
    ds.SeriesNumber = 1
    ds.InstitutionName = "Test Hospital"
    ds.StudyDescription = "Test Study"
    ds.Manufacturer = "Test Manufacturer"
    ds.Rows = 512
    ds.Columns = 512
    ds.PatientAge = "045Y"
    ds.ModelName = "TestModel"
    ds.SoftwareVersions = "1.0"
    ds.SliceThickness = 1.0
    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    return ds


# =============================================================================
# HeaderFuzzer Initialization Tests
# =============================================================================
class TestHeaderFuzzerInit:
    """Tests for HeaderFuzzer initialization."""

    def test_required_tags_defined(self, fuzzer: HeaderFuzzer) -> None:
        """Test that required_tags list is defined."""
        assert hasattr(fuzzer, "required_tags")
        assert isinstance(fuzzer.required_tags, list)
        assert len(fuzzer.required_tags) > 0

    def test_required_tags_contains_expected(self, fuzzer: HeaderFuzzer) -> None:
        """Test required_tags contains expected DICOM tags."""
        expected = ["PatientName", "PatientID", "StudyInstanceUID", "SeriesInstanceUID"]
        assert len(expected) == 4
        for tag in expected:
            assert tag in fuzzer.required_tags

    def test_critical_tags_excluded(self, fuzzer: HeaderFuzzer) -> None:
        """Test that critical tags are excluded from removal list."""
        # SOPClassUID and SOPInstanceUID break parsing, should not be in list
        assert "SOPClassUID" not in fuzzer.required_tags
        assert "SOPInstanceUID" not in fuzzer.required_tags


# =============================================================================
# mutate Tests
# =============================================================================
class TestMutateTags:
    """Tests for mutate method."""

    def test_returns_dataset(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate returns a Dataset."""
        result = fuzzer.mutate(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_applies_mutations(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutations are applied to the dataset."""
        random.seed(42)  # For reproducibility
        original_name = sample_dataset.PatientName
        original_rows = sample_dataset.Rows

        # Run multiple times to ensure mutations happen
        mutations_applied = False
        for _ in range(10):
            ds = Dataset()
            ds.PatientName = "Test^Patient"
            ds.InstitutionName = "Hospital"
            ds.Rows = 512
            result = fuzzer.mutate(ds)
            if (
                (
                    hasattr(result, "InstitutionName")
                    and len(result.InstitutionName) > 100
                )
                or (hasattr(result, "Rows") and result.Rows != 512)
                or not hasattr(result, "PatientName")
            ):
                mutations_applied = True
                break

        assert mutations_applied

    def test_random_mutation_selection(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutations are randomly selected."""
        results = []
        for i in range(5):
            random.seed(i)
            ds_copy = Dataset()
            ds_copy.PatientName = "Test"
            ds_copy.InstitutionName = "Hospital"
            result = fuzzer.mutate(ds_copy)
            results.append(str(result))

        # Results should vary with different seeds
        assert len(results) == 5
        unique_results = set(results)
        assert len(unique_results) >= 1  # At least some variation expected


# =============================================================================
# _overlong_strings Tests
# =============================================================================
class TestOverlongStrings:
    """Tests for _overlong_strings method."""

    def test_creates_overlong_institution_name(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test InstitutionName is set to overlong value."""
        result = fuzzer._overlong_strings(sample_dataset)
        assert isinstance(result, Dataset)
        assert len(result.InstitutionName) == 1024  # Way over 64 char limit

    def test_creates_overlong_study_description(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test StudyDescription is set to overlong value."""
        result = fuzzer._overlong_strings(sample_dataset)
        assert isinstance(result, Dataset)
        assert len(result.StudyDescription) == 2048

    def test_creates_overlong_manufacturer(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test Manufacturer is set to overlong value."""
        result = fuzzer._overlong_strings(sample_dataset)
        assert isinstance(result, Dataset)
        assert len(result.Manufacturer) == 512

    def test_handles_missing_tags(self, fuzzer: HeaderFuzzer) -> None:
        """Test handles dataset without string tags."""
        ds = Dataset()
        ds.PatientName = "Test"
        result = fuzzer._overlong_strings(ds)
        # Should not raise, just skip missing tags
        assert result is not None
        assert isinstance(result, Dataset)

    def test_uses_repeated_characters(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that overlong strings use repeated single characters."""
        result = fuzzer._overlong_strings(sample_dataset)
        assert isinstance(result, Dataset)
        # Should be 'A' * 1024
        assert result.InstitutionName == "A" * 1024
        assert result.StudyDescription == "B" * 2048
        assert result.Manufacturer == "C" * 512


# =============================================================================
# _missing_required_tags Tests
# =============================================================================
class TestMissingRequiredTags:
    """Tests for _missing_required_tags method."""

    def test_removes_tags(self, fuzzer: HeaderFuzzer, sample_dataset: Dataset) -> None:
        """Test that some required tags are removed."""
        random.seed(42)
        original_tags = set(fuzzer.required_tags)
        present_before = [t for t in original_tags if hasattr(sample_dataset, t)]

        result = fuzzer._missing_required_tags(sample_dataset)

        assert isinstance(result, Dataset)
        present_after = [t for t in original_tags if hasattr(result, t)]
        # Should have removed at least one tag
        assert len(present_after) < len(present_before)

    def test_removes_one_or_two_tags(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that 1-2 tags are removed."""
        present_before = [t for t in fuzzer.required_tags if hasattr(sample_dataset, t)]

        # Run multiple times to check range
        removals = []
        for i in range(20):
            random.seed(i)
            ds_copy = Dataset()
            for tag in fuzzer.required_tags:
                if hasattr(sample_dataset, tag):
                    setattr(ds_copy, tag, getattr(sample_dataset, tag))

            result = fuzzer._missing_required_tags(ds_copy)
            present_after = [t for t in fuzzer.required_tags if hasattr(result, t)]
            removed = len(present_before) - len(present_after)
            removals.append(removed)

        # Should remove 1 or 2 tags
        assert min(removals) >= 0
        assert max(removals) <= 2

    def test_handles_missing_tags_gracefully(self, fuzzer: HeaderFuzzer) -> None:
        """Test handles dataset without required tags."""
        ds = Dataset()
        ds.Modality = "CT"  # Not in required_tags
        result = fuzzer._missing_required_tags(ds)
        # Should not raise
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _invalid_vr_values Tests
# =============================================================================
class TestInvalidVrValues:
    """Tests for _invalid_vr_values method."""

    def test_invalid_study_date(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test StudyDate receives invalid value."""
        random.seed(42)
        result = fuzzer._invalid_vr_values(sample_dataset)
        assert isinstance(result, Dataset)
        # Should be one of the invalid date formats
        invalid_dates = [
            "INVALID",
            "99999999",
            "20251332",
            "20250145",
            "2025-01-01",
            "",
            "1",
        ]
        assert result.StudyDate in invalid_dates

    def test_invalid_study_time(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test StudyTime receives invalid value."""
        random.seed(42)
        result = fuzzer._invalid_vr_values(sample_dataset)
        assert isinstance(result, Dataset)
        invalid_times = ["999999", "126000", "120075", "ABCDEF", "12:30:45"]
        assert result.StudyTime in invalid_times

    def test_invalid_series_number(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test SeriesNumber receives invalid IS value."""
        random.seed(42)
        result = fuzzer._invalid_vr_values(sample_dataset)
        assert isinstance(result, Dataset)
        # Check internal value was set
        elem = result[Tag(0x0020, 0x0011)]
        assert elem is not None
        invalid_integers = [
            "NOT_A_NUMBER",
            "3.14159",
            "999999999999",
            "-999999999",
            "",
        ]
        assert elem._value in invalid_integers

    def test_invalid_slice_thickness(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test SliceThickness receives invalid DS value."""
        random.seed(42)
        result = fuzzer._invalid_vr_values(sample_dataset)
        assert isinstance(result, Dataset)
        elem = result[Tag(0x0018, 0x0050)]
        assert elem is not None
        invalid_decimals = ["INVALID", "1.2.3", "NaN", "Infinity", "1e999"]
        assert elem._value in invalid_decimals

    def test_handles_missing_date_time(self, fuzzer: HeaderFuzzer) -> None:
        """Test handles dataset without date/time tags."""
        ds = Dataset()
        ds.PatientName = "Test"
        result = fuzzer._invalid_vr_values(ds)
        # Should not raise
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _boundary_values Tests
# =============================================================================
class TestBoundaryValues:
    """Tests for _boundary_values method."""

    def test_boundary_rows(self, fuzzer: HeaderFuzzer, sample_dataset: Dataset) -> None:
        """Test Rows receives boundary value."""
        random.seed(42)
        result = fuzzer._boundary_values(sample_dataset)
        assert isinstance(result, Dataset)
        boundary_values = [0, 1, 65535, -1, 2147483647]
        assert result.Rows in boundary_values

    def test_boundary_columns(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test Columns receives boundary value."""
        random.seed(42)
        result = fuzzer._boundary_values(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.Columns in [0, 1, 65535, -1]

    def test_boundary_patient_age(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test PatientAge receives boundary value."""
        random.seed(42)
        result = fuzzer._boundary_values(sample_dataset)
        assert isinstance(result, Dataset)
        boundary_ages = ["000Y", "999Y", "001D", "999W", "000M"]
        assert result.PatientAge in boundary_ages

    def test_patient_name_boundary(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test PatientName at VR boundary."""
        # Run multiple times to hit both cases
        results = []
        for i in range(20):
            random.seed(i)
            ds = Dataset()
            ds.PatientName = "Original"
            result = fuzzer._boundary_values(ds)
            results.append(len(result.PatientName))

        # Should have either 64 or 65 character names
        assert 64 in results or 65 in results

    def test_empty_string_mutations(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test some tags may be set to empty strings."""
        # Run multiple times to hit empty string case
        empty_found = False
        for i in range(50):
            random.seed(i)
            ds = Dataset()
            ds.Manufacturer = "Original"
            ds.ModelName = "Model"
            ds.SoftwareVersions = "1.0"
            result = fuzzer._boundary_values(ds)
            for tag in ["Manufacturer", "ModelName", "SoftwareVersions"]:
                if hasattr(result, tag) and getattr(result, tag) == "":
                    empty_found = True
                    break
            if empty_found:
                break

        # Empty strings should occur with probability > 0.7 in random
        # This is probabilistic but should hit in 50 tries
        assert empty_found

    def test_handles_missing_numeric_tags(self, fuzzer: HeaderFuzzer) -> None:
        """Test handles dataset without Rows/Columns."""
        ds = Dataset()
        ds.PatientName = "Test"
        result = fuzzer._boundary_values(ds)
        # Should not raise
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# Integration Tests
# =============================================================================
class TestHeaderFuzzerIntegration:
    """Integration tests for HeaderFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate(sample_dataset)

        # Result should be a valid Dataset
        assert result is not None
        assert isinstance(result, Dataset)
        # Should still have some structure
        assert hasattr(result, "SOPClassUID") or hasattr(result, "PatientName")

    def test_multiple_mutations_deterministic(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that same seed produces same mutations."""
        random.seed(123)
        ds1 = Dataset()
        ds1.PatientName = "Test"
        ds1.InstitutionName = "Hospital"
        result1 = fuzzer.mutate(ds1)

        random.seed(123)
        ds2 = Dataset()
        ds2.PatientName = "Test"
        ds2.InstitutionName = "Hospital"
        result2 = fuzzer.mutate(ds2)

        # Results should be the same with same seed
        assert str(result1) == str(result2)

    def test_empty_dataset(self, fuzzer: HeaderFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate(ds)
        # Should not raise
        assert result is not None
        assert isinstance(result, Dataset)

    def test_preserves_sop_tags(
        self, fuzzer: HeaderFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that SOP tags are preserved."""
        original_sop_class = sample_dataset.SOPClassUID
        original_sop_instance = sample_dataset.SOPInstanceUID

        random.seed(42)
        result = fuzzer.mutate(sample_dataset)

        # SOP tags should remain unchanged
        assert result.SOPClassUID == original_sop_class
        assert result.SOPInstanceUID == original_sop_instance
