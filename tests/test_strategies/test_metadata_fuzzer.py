"""Tests for metadata_fuzzer.py - Patient Metadata Mutation.

Tests cover patient info mutation and random date generation.
"""

import random
from unittest.mock import MagicMock, patch

from dicom_fuzzer.strategies.metadata_fuzzer import MetadataFuzzer


class TestMetadataFuzzerInit:
    """Test MetadataFuzzer initialization."""

    def test_init_fake_names(self):
        """Test that fake names are initialized."""
        fuzzer = MetadataFuzzer()
        assert len(fuzzer.fake_names) == 3
        assert "Smith^John" in fuzzer.fake_names
        assert "Doe^Jane" in fuzzer.fake_names
        assert "Johnson^Mike" in fuzzer.fake_names

    def test_init_fake_ids(self):
        """Test that fake IDs are initialized."""
        fuzzer = MetadataFuzzer()
        assert len(fuzzer.fake_ids) == 8999  # 9999 - 1000
        assert "PAT001000" in fuzzer.fake_ids
        assert "PAT009998" in fuzzer.fake_ids

    def test_fake_id_format(self):
        """Test that fake IDs have correct format."""
        fuzzer = MetadataFuzzer()
        for fake_id in fuzzer.fake_ids[:10]:
            assert fake_id.startswith("PAT")
            assert len(fake_id) == 9
            assert fake_id[3:].isdigit()


class TestMutatePatientInfo:
    """Test mutate_patient_info method."""

    def test_mutate_patient_id(self):
        """Test that PatientID is mutated."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()

        with patch.object(random, "choice", side_effect=["PAT005000", "Smith^John"]):
            result = fuzzer.mutate_patient_info(dataset)

        assert result.PatientID == "PAT005000"

    def test_mutate_patient_name(self):
        """Test that PatientName is mutated."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()

        with patch.object(random, "choice", side_effect=["PAT001234", "Doe^Jane"]):
            result = fuzzer.mutate_patient_info(dataset)

        assert result.PatientName == "Doe^Jane"

    def test_mutate_patient_birth_date(self):
        """Test that PatientBirthDate is mutated."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()

        with patch.object(fuzzer, "_random_date", return_value="19800515"):
            result = fuzzer.mutate_patient_info(dataset)

        assert result.PatientBirthDate == "19800515"

    def test_mutate_returns_dataset(self):
        """Test that mutation returns the modified dataset."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()

        result = fuzzer.mutate_patient_info(dataset)

        assert result is dataset


class TestRandomDate:
    """Test _random_date method."""

    def test_random_date_format(self):
        """Test that random date has YYYYMMDD format."""
        fuzzer = MetadataFuzzer()

        date_str = fuzzer._random_date()

        assert len(date_str) == 8
        assert date_str.isdigit()

    def test_random_date_valid_year_range(self):
        """Test that random date year is in valid range."""
        fuzzer = MetadataFuzzer()

        # Generate multiple dates to check range
        for _ in range(10):
            date_str = fuzzer._random_date()
            year = int(date_str[:4])
            assert 1950 <= year <= 2010

    def test_random_date_valid_month(self):
        """Test that random date month is valid."""
        fuzzer = MetadataFuzzer()

        for _ in range(10):
            date_str = fuzzer._random_date()
            month = int(date_str[4:6])
            assert 1 <= month <= 12

    def test_random_date_valid_day(self):
        """Test that random date day is valid."""
        fuzzer = MetadataFuzzer()

        for _ in range(10):
            date_str = fuzzer._random_date()
            day = int(date_str[6:8])
            assert 1 <= day <= 31

    def test_random_date_deterministic_with_seed(self):
        """Test that random date is deterministic with fixed seed."""
        random.seed(42)
        fuzzer = MetadataFuzzer()
        date1 = fuzzer._random_date()

        random.seed(42)
        fuzzer2 = MetadataFuzzer()
        date2 = fuzzer2._random_date()

        assert date1 == date2
