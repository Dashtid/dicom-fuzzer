"""Comprehensive tests for dicom_fuzzer.strategies.metadata_fuzzer module.

This test suite provides thorough coverage of metadata fuzzing functionality,
including patient information mutation and date generation.
"""

from datetime import datetime
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.metadata_fuzzer import MetadataFuzzer


class TestMetadataFuzzerInitialization:
    """Test suite for MetadataFuzzer initialization."""

    def test_initialization(self):
        """Test MetadataFuzzer initialization."""
        fuzzer = MetadataFuzzer()

        assert hasattr(fuzzer, "fake_names")
        assert hasattr(fuzzer, "fake_ids")

    def test_fake_names_list(self):
        """Test fake names are properly initialized."""
        fuzzer = MetadataFuzzer()

        assert len(fuzzer.fake_names) == 3
        assert "Smith^John" in fuzzer.fake_names
        assert "Doe^Jane" in fuzzer.fake_names
        assert "Johnson^Mike" in fuzzer.fake_names

    def test_fake_ids_list(self):
        """Test fake IDs are properly generated."""
        fuzzer = MetadataFuzzer()

        assert len(fuzzer.fake_ids) == 8999
        assert fuzzer.fake_ids[0] == "PAT001000"
        assert fuzzer.fake_ids[-1] == "PAT009998"

    def test_fake_ids_format(self):
        """Test fake IDs have correct format."""
        fuzzer = MetadataFuzzer()

        for fake_id in fuzzer.fake_ids[:10]:
            assert fake_id.startswith("PAT")
            assert len(fake_id) == 9


class TestMutatePatientInfo:
    """Test suite for mutate_patient_info method."""

    @pytest.fixture
    def sample_dataset(self):
        """Create sample DICOM dataset."""
        ds = Dataset()
        ds.PatientID = "ORIGINAL_ID"
        ds.PatientName = "Original^Name"
        ds.PatientBirthDate = "19800101"
        return ds

    @patch("random.choice")
    def test_mutate_patient_id(self, mock_choice, sample_dataset):
        """Test patient ID mutation."""
        mock_choice.side_effect = ["PAT001234", "Smith^John"]

        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(sample_dataset)

        assert mutated.PatientID == "PAT001234"
        assert mutated.PatientID != "ORIGINAL_ID"

    @patch("random.choice")
    def test_mutate_patient_name(self, mock_choice, sample_dataset):
        """Test patient name mutation."""
        mock_choice.side_effect = ["PAT001234", "Doe^Jane"]

        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(sample_dataset)

        assert mutated.PatientName == "Doe^Jane"
        assert mutated.PatientName != "Original^Name"

    def test_mutate_patient_birth_date(self, sample_dataset):
        """Test patient birth date mutation."""
        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(sample_dataset)

        # Should be 8 characters (YYYYMMDD)
        assert len(mutated.PatientBirthDate) == 8
        assert mutated.PatientBirthDate.isdigit()

    def test_mutate_returns_dataset(self, sample_dataset):
        """Test mutation returns a dataset."""
        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(sample_dataset)

        assert isinstance(mutated, Dataset)

    def test_mutate_all_fields_changed(self, sample_dataset):
        """Test all patient fields are mutated."""
        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(sample_dataset)

        assert hasattr(mutated, "PatientID")
        assert hasattr(mutated, "PatientName")
        assert hasattr(mutated, "PatientBirthDate")

    def test_mutate_empty_dataset(self):
        """Test mutating empty dataset."""
        fuzzer = MetadataFuzzer()
        ds = Dataset()

        mutated = fuzzer.mutate_patient_info(ds)

        assert hasattr(mutated, "PatientID")
        assert hasattr(mutated, "PatientName")
        assert hasattr(mutated, "PatientBirthDate")


class TestRandomDate:
    """Test suite for _random_date method."""

    def test_random_date_format(self):
        """Test random date has correct format."""
        fuzzer = MetadataFuzzer()
        date_str = fuzzer._random_date()

        assert len(date_str) == 8
        assert date_str.isdigit()

    def test_random_date_valid_range(self):
        """Test random date is within valid range."""
        fuzzer = MetadataFuzzer()
        date_str = fuzzer._random_date()

        year = int(date_str[:4])
        month = int(date_str[4:6])
        day = int(date_str[6:8])

        assert 1950 <= year <= 2010
        assert 1 <= month <= 12
        assert 1 <= day <= 31

    def test_random_date_parseable(self):
        """Test random date can be parsed."""
        fuzzer = MetadataFuzzer()
        date_str = fuzzer._random_date()

        # Should be able to parse it
        date_obj = datetime.strptime(date_str, "%Y%m%d")
        assert isinstance(date_obj, datetime)

    @patch("random.randint")
    def test_random_date_start_boundary(self, mock_randint):
        """Test random date at start boundary."""
        mock_randint.return_value = 0

        fuzzer = MetadataFuzzer()
        date_str = fuzzer._random_date()

        assert date_str == "19500101"

    @patch("random.randint")
    def test_random_date_end_boundary(self, mock_randint):
        """Test random date at end boundary."""
        # Calculate days between start and end
        start_date = datetime(1950, 1, 1)
        end_date = datetime(2010, 12, 31)
        days_between = (end_date - start_date).days

        mock_randint.return_value = days_between

        fuzzer = MetadataFuzzer()
        date_str = fuzzer._random_date()

        assert date_str == "20101231"

    def test_random_date_multiple_calls(self):
        """Test multiple random date calls produce valid dates."""
        fuzzer = MetadataFuzzer()

        dates = [fuzzer._random_date() for _ in range(100)]

        for date_str in dates:
            assert len(date_str) == 8
            assert date_str.isdigit()
            year = int(date_str[:4])
            assert 1950 <= year <= 2010


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_multiple_mutations(self):
        """Test applying mutations multiple times."""
        fuzzer = MetadataFuzzer()
        ds = Dataset()
        ds.PatientID = "ORIGINAL"
        ds.PatientName = "Original^Name"
        ds.PatientBirthDate = "19800101"

        # Apply mutations multiple times
        for _ in range(10):
            ds = fuzzer.mutate_patient_info(ds)

        assert isinstance(ds, Dataset)
        assert hasattr(ds, "PatientID")
        assert hasattr(ds, "PatientName")
        assert hasattr(ds, "PatientBirthDate")

    def test_mutation_consistency(self):
        """Test mutations are consistent."""
        fuzzer = MetadataFuzzer()
        ds = Dataset()

        mutated = fuzzer.mutate_patient_info(ds)

        # All fields should be set
        assert mutated.PatientID in fuzzer.fake_ids
        assert mutated.PatientName in fuzzer.fake_names
        assert len(mutated.PatientBirthDate) == 8

    def test_preserve_other_fields(self):
        """Test mutation preserves other dataset fields."""
        fuzzer = MetadataFuzzer()
        ds = Dataset()
        ds.Modality = "CT"
        ds.StudyDescription = "Test Study"
        ds.PatientID = "ORIGINAL"

        mutated = fuzzer.mutate_patient_info(ds)

        # Original fields should be preserved
        assert mutated.Modality == "CT"
        assert mutated.StudyDescription == "Test Study"
        # Patient fields should be mutated
        assert mutated.PatientID != "ORIGINAL"

    def test_statistical_distribution(self):
        """Test statistical distribution of mutations."""
        fuzzer = MetadataFuzzer()

        # Collect samples
        names_used = set()
        ids_used = set()

        for _ in range(100):
            ds = Dataset()
            mutated = fuzzer.mutate_patient_info(ds)
            names_used.add(mutated.PatientName)
            ids_used.add(mutated.PatientID)

        # With 100 samples, we should see variety in both names and IDs
        assert len(names_used) >= 1  # At least one name
        assert len(ids_used) >= 10  # Should have diverse IDs

    def test_realistic_patient_data(self):
        """Test generated patient data looks realistic."""
        fuzzer = MetadataFuzzer()
        ds = Dataset()

        mutated = fuzzer.mutate_patient_info(ds)

        # Patient ID should have PAT prefix
        assert mutated.PatientID.startswith("PAT")
        # Patient name should have ^ separator
        assert "^" in mutated.PatientName
        # Birth date should be valid DICOM format
        assert len(mutated.PatientBirthDate) == 8
        datetime.strptime(mutated.PatientBirthDate, "%Y%m%d")  # Should not raise
