"""Comprehensive tests for dicom_fuzzer.strategies.header_fuzzer module.

This test suite provides thorough coverage of DICOM header fuzzing functionality,
including overlong strings, missing tags, invalid VR values, and boundary testing.
"""

from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.header_fuzzer import HeaderFuzzer


class TestHeaderFuzzerInitialization:
    """Test suite for HeaderFuzzer initialization."""

    def test_initialization(self):
        """Test HeaderFuzzer initialization."""
        fuzzer = HeaderFuzzer()

        assert hasattr(fuzzer, "required_tags")
        assert len(fuzzer.required_tags) == 4

    def test_required_tags_list(self):
        """Test required tags are properly defined."""
        fuzzer = HeaderFuzzer()

        expected_tags = [
            "PatientName",
            "PatientID",
            "StudyInstanceUID",
            "SeriesInstanceUID",
        ]

        assert fuzzer.required_tags == expected_tags


class TestMutateTags:
    """Test suite for mutate_tags method."""

    @pytest.fixture
    def sample_dataset(self):
        """Create sample DICOM dataset."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.InstitutionName = "Test Hospital"
        ds.Manufacturer = "Test Manufacturer"
        return ds

    def test_mutate_tags_returns_dataset(self, sample_dataset):
        """Test mutate_tags returns a dataset."""
        fuzzer = HeaderFuzzer()

        mutated = fuzzer.mutate_tags(sample_dataset)

        assert isinstance(mutated, Dataset)

    def test_mutate_tags_multiple_times(self, sample_dataset):
        """Test applying mutations multiple times."""
        fuzzer = HeaderFuzzer()

        for _ in range(5):
            sample_dataset = fuzzer.mutate_tags(sample_dataset)

        assert isinstance(sample_dataset, Dataset)


class TestOverlongStrings:
    """Test suite for overlong string mutations."""

    def test_overlong_institution_name(self):
        """Test overlong InstitutionName."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.InstitutionName = "Short Name"

        mutated = fuzzer._overlong_strings(ds)

        assert len(mutated.InstitutionName) == 1024
        assert mutated.InstitutionName == "A" * 1024

    def test_overlong_study_description(self):
        """Test overlong StudyDescription."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.StudyDescription = "Normal Description"

        mutated = fuzzer._overlong_strings(ds)

        assert len(mutated.StudyDescription) == 2048
        assert mutated.StudyDescription == "B" * 2048

    def test_overlong_manufacturer(self):
        """Test overlong Manufacturer."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Manufacturer = "ACME Corp"

        mutated = fuzzer._overlong_strings(ds)

        assert len(mutated.Manufacturer) == 512
        assert mutated.Manufacturer == "C" * 512

    def test_overlong_strings_missing_fields(self):
        """Test overlong strings when fields don't exist."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        # Should not raise error
        mutated = fuzzer._overlong_strings(ds)

        assert isinstance(mutated, Dataset)

    def test_overlong_strings_all_fields(self):
        """Test overlong strings with all fields present."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.InstitutionName = "Test"
        ds.StudyDescription = "Test"
        ds.Manufacturer = "Test"

        mutated = fuzzer._overlong_strings(ds)

        assert len(mutated.InstitutionName) == 1024
        assert len(mutated.StudyDescription) == 2048
        assert len(mutated.Manufacturer) == 512


class TestMissingRequiredTags:
    """Test suite for missing required tags mutations."""

    @patch("random.sample")
    @patch("random.randint")
    def test_remove_patient_name(self, mock_randint, mock_sample):
        """Test removing PatientName tag."""
        mock_randint.return_value = 1
        mock_sample.return_value = ["PatientName"]

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"

        mutated = fuzzer._missing_required_tags(ds)

        assert not hasattr(mutated, "PatientName")

    @patch("random.sample")
    @patch("random.randint")
    def test_remove_multiple_tags(self, mock_randint, mock_sample):
        """Test removing multiple required tags."""
        mock_randint.return_value = 2
        mock_sample.return_value = ["PatientName", "PatientID"]

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.StudyInstanceUID = "1.2.3"

        mutated = fuzzer._missing_required_tags(ds)

        assert not hasattr(mutated, "PatientName")
        assert not hasattr(mutated, "PatientID")

    def test_remove_nonexistent_tag(self):
        """Test removing tag that doesn't exist."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Modality = "CT"

        # Should not raise error
        mutated = fuzzer._missing_required_tags(ds)

        assert isinstance(mutated, Dataset)

    @patch("random.sample")
    @patch("random.randint")
    def test_delattr_exception_handling(self, mock_randint, mock_sample):
        """Test exception handling when delattr fails (lines 99-101)."""
        mock_randint.return_value = 1
        mock_sample.return_value = ["PatientName"]

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test^Patient"

        # Mock delattr to raise an exception
        original_delattr = Dataset.__delattr__

        def mock_delattr_raises(self, name):
            if name == "PatientName":
                raise AttributeError("Cannot delete attribute")
            return original_delattr(self, name)

        with patch.object(Dataset, "__delattr__", mock_delattr_raises):
            # Should not raise error due to try/except
            mutated = fuzzer._missing_required_tags(ds)

        assert isinstance(mutated, Dataset)
        # PatientName should still exist since delete failed
        assert hasattr(mutated, "PatientName")


class TestInvalidVRValues:
    """Test suite for invalid VR value mutations."""

    @patch("random.choice")
    def test_invalid_study_date(self, mock_choice):
        """Test invalid StudyDate values."""
        mock_choice.return_value = "INVALID"

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.StudyDate = "20250101"

        mutated = fuzzer._invalid_vr_values(ds)

        assert mutated.StudyDate == "INVALID"

    @patch("random.choice")
    def test_invalid_study_time(self, mock_choice):
        """Test invalid StudyTime values."""
        mock_choice.return_value = "999999"

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.StudyTime = "120000"

        mutated = fuzzer._invalid_vr_values(ds)

        assert mutated.StudyTime == "999999"

    @patch("random.choice")
    def test_invalid_series_number(self, mock_choice):
        """Test invalid SeriesNumber values."""
        mock_choice.return_value = "NOT_A_NUMBER"

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.SeriesNumber = "1"

        mutated = fuzzer._invalid_vr_values(ds)

        assert mutated.SeriesNumber == "NOT_A_NUMBER"

    @patch("random.choice")
    def test_invalid_slice_thickness(self, mock_choice):
        """Test invalid SliceThickness values."""
        mock_choice.return_value = "INVALID"

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.SliceThickness = "5.0"

        mutated = fuzzer._invalid_vr_values(ds)

        assert mutated.SliceThickness == "INVALID"

    def test_invalid_vr_missing_fields(self):
        """Test invalid VR when fields don't exist."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        # Should not raise error
        mutated = fuzzer._invalid_vr_values(ds)

        assert isinstance(mutated, Dataset)

    @patch("random.choice")
    def test_invalid_date_formats(self, mock_choice):
        """Test various invalid date formats."""
        fuzzer = HeaderFuzzer()

        invalid_dates = [
            "INVALID",
            "99999999",
            "20251332",
            "20250145",
            "2025-01-01",
            "",
            "1",
        ]

        for invalid_date in invalid_dates:
            mock_choice.return_value = invalid_date
            ds = Dataset()
            ds.StudyDate = "20250101"

            mutated = fuzzer._invalid_vr_values(ds)
            assert mutated.StudyDate == invalid_date


class TestBoundaryValues:
    """Test suite for boundary value mutations."""

    @patch("random.choice")
    def test_boundary_rows_zero(self, mock_choice):
        """Test Rows with zero value."""
        mock_choice.return_value = 0

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Rows = 512

        mutated = fuzzer._boundary_values(ds)

        assert mutated.Rows == 0

    @patch("random.choice")
    def test_boundary_rows_max(self, mock_choice):
        """Test Rows with maximum value."""
        mock_choice.return_value = 2147483647

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Rows = 512

        mutated = fuzzer._boundary_values(ds)

        assert mutated.Rows == 2147483647

    @patch("random.choice")
    def test_boundary_columns(self, mock_choice):
        """Test Columns with boundary values."""
        mock_choice.return_value = -1

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Columns = 512

        mutated = fuzzer._boundary_values(ds)

        assert mutated.Columns == -1

    @patch("random.choice")
    def test_boundary_patient_age(self, mock_choice):
        """Test PatientAge with boundary values."""
        mock_choice.return_value = "999Y"

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientAge = "050Y"

        mutated = fuzzer._boundary_values(ds)

        assert mutated.PatientAge == "999Y"

    @patch("random.random")
    def test_boundary_patient_name_exact_limit(self, mock_random):
        """Test PatientName at exact VR limit."""
        mock_random.return_value = 0.3  # <= 0.5

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated = fuzzer._boundary_values(ds)

        assert len(mutated.PatientName) == 64
        assert mutated.PatientName == "X" * 64

    @patch("random.random")
    def test_boundary_patient_name_over_limit(self, mock_random):
        """Test PatientName over VR limit."""
        mock_random.return_value = 0.7  # > 0.5

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated = fuzzer._boundary_values(ds)

        assert len(mutated.PatientName) == 65
        assert mutated.PatientName == "X" * 65

    @patch("random.random")
    def test_boundary_empty_strings(self, mock_random):
        """Test empty string boundary values."""
        mock_random.return_value = 0.8  # > 0.7, will set empty

        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Manufacturer = "ACME"
        ds.ModelName = "Model X"
        ds.SoftwareVersions = "1.0"

        mutated = fuzzer._boundary_values(ds)

        assert mutated.Manufacturer == ""

    def test_boundary_values_missing_fields(self):
        """Test boundary values when fields don't exist."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Modality = "CT"

        # Should not raise error
        mutated = fuzzer._boundary_values(ds)

        assert isinstance(mutated, Dataset)


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_complete_fuzzing_workflow(self):
        """Test complete fuzzing workflow."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.InstitutionName = "Hospital"
        ds.Manufacturer = "ACME"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.SeriesNumber = "1"
        ds.Rows = 512
        ds.Columns = 512

        # Apply mutations
        mutated = fuzzer.mutate_tags(ds)

        assert isinstance(mutated, Dataset)

    def test_all_mutation_types_individually(self):
        """Test all mutation types work individually."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.InstitutionName = "Test"
        ds.StudyDate = "20250101"
        ds.Rows = 512

        # Test each mutation type
        mutated1 = fuzzer._overlong_strings(ds)
        mutated2 = fuzzer._missing_required_tags(ds)
        mutated3 = fuzzer._invalid_vr_values(ds)
        mutated4 = fuzzer._boundary_values(ds)

        assert all(
            isinstance(m, Dataset) for m in [mutated1, mutated2, mutated3, mutated4]
        )

    def test_sequential_mutations(self):
        """Test applying mutations sequentially."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.InstitutionName = "Hospital"
        ds.StudyDate = "20250101"
        ds.Rows = 512

        # Apply all mutations in sequence
        ds = fuzzer._overlong_strings(ds)
        ds = fuzzer._missing_required_tags(ds)
        ds = fuzzer._invalid_vr_values(ds)
        ds = fuzzer._boundary_values(ds)

        assert isinstance(ds, Dataset)

    def test_fuzzing_minimal_dataset(self):
        """Test fuzzing with minimal dataset."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()
        ds.Modality = "CT"

        mutated = fuzzer.mutate_tags(ds)

        assert isinstance(mutated, Dataset)

    def test_fuzzing_comprehensive_dataset(self):
        """Test fuzzing with comprehensive dataset."""
        fuzzer = HeaderFuzzer()
        ds = Dataset()

        # Add all potentially targeted fields
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.InstitutionName = "Hospital"
        ds.StudyDescription = "Study Desc"
        ds.Manufacturer = "ACME"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.SeriesNumber = "1"
        ds.SliceThickness = "5.0"
        ds.Rows = 512
        ds.Columns = 512
        ds.PatientAge = "050Y"
        ds.ModelName = "Model X"
        ds.SoftwareVersions = "1.0"

        mutated = fuzzer.mutate_tags(ds)

        assert isinstance(mutated, Dataset)
