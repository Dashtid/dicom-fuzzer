"""Tests for metadata_fuzzer.py - Patient Metadata Mutation.

Tests cover patient info mutation and random date generation.
"""

import random
from unittest.mock import MagicMock, patch

from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.base import FormatFuzzerBase
from dicom_fuzzer.attacks.format.metadata_fuzzer import MetadataFuzzer


class TestMetadataFuzzerInit:
    """Test MetadataFuzzer initialization."""

    def test_init_fake_names(self):
        """Test that fake names are initialized."""
        fuzzer = MetadataFuzzer()
        assert len(fuzzer.fake_names) == 3
        assert "Smith^John" in fuzzer.fake_names
        assert "Doe^Jane" in fuzzer.fake_names
        assert "Johnson^Mike" in fuzzer.fake_names

    def test_patient_id_generated_on_demand(self):
        """Test that patient IDs are generated on demand with correct format."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()
        result = fuzzer.mutate_patient_info(dataset)
        patient_id = str(result.PatientID)
        assert patient_id.startswith("PAT")
        assert len(patient_id) == 9
        assert patient_id[3:].isdigit()


class TestMutatePatientInfo:
    """Test mutate_patient_info method."""

    def test_mutate_patient_id(self):
        """Test that PatientID is mutated with correct format."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()

        with patch.object(random, "randint", return_value=5000):
            with patch.object(random, "choice", return_value="Smith^John"):
                result = fuzzer.mutate_patient_info(dataset)

        assert result.PatientID == "PAT005000"

    def test_mutate_patient_name(self):
        """Test that PatientName is mutated."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()

        result = fuzzer.mutate_patient_info(dataset)

        assert str(result.PatientName) in fuzzer.fake_names

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


class TestFormatFuzzerBase:
    """Test that MetadataFuzzer conforms to FormatFuzzerBase interface."""

    def test_isinstance_format_fuzzer_base(self):
        """Test that MetadataFuzzer is an instance of FormatFuzzerBase."""
        fuzzer = MetadataFuzzer()
        assert isinstance(fuzzer, FormatFuzzerBase)

    def test_strategy_name(self):
        """Test that strategy_name returns 'metadata'."""
        fuzzer = MetadataFuzzer()
        assert fuzzer.strategy_name == "metadata"

    def test_has_mutate_method(self):
        """Test that MetadataFuzzer has a mutate method."""
        fuzzer = MetadataFuzzer()
        assert hasattr(fuzzer, "mutate")


class TestMutate:
    """Test the mutate() method."""

    def test_mutate_returns_dataset(self):
        """Test that mutate returns the same dataset object."""
        fuzzer = MetadataFuzzer()
        dataset = MagicMock()
        result = fuzzer.mutate(dataset)
        assert result is dataset

    def test_mutate_modifies_dataset(self):
        """Test that mutate adds attributes to the dataset over many calls."""
        fuzzer = MetadataFuzzer()
        all_possible_fields = [
            "PatientID",
            "PatientName",
            "PatientBirthDate",
            "PatientSex",
            "PatientAge",
            "PatientWeight",
            "PatientSize",
            "StudyDate",
            "StudyTime",
            "StudyID",
            "AccessionNumber",
            "ReferringPhysicianName",
            "SeriesDate",
            "SeriesDescription",
            "BodyPartExamined",
            "InstitutionName",
            "InstitutionAddress",
            "StationName",
            "OperatorsName",
            "PerformingPhysicianName",
        ]
        found_any = False
        for _ in range(20):
            dataset = MagicMock()
            fuzzer.mutate(dataset)
            for field in all_possible_fields:
                if hasattr(dataset, field):
                    found_any = True
                    break
            if found_any:
                break
        assert found_any, "mutate() should set at least some DICOM attributes"


class TestPatientDemographicsAttack:
    """Test _patient_demographics_attack method."""

    def test_sets_patient_sex(self):
        """Test that _patient_demographics_attack sets PatientSex."""
        fuzzer = MetadataFuzzer()
        # Call multiple times since the method randomly selects fields
        found = False
        for _ in range(20):
            dataset = Dataset()
            fuzzer._patient_demographics_attack(dataset)
            if hasattr(dataset, "PatientSex"):
                found = True
                break
        assert found, "PatientSex should be set in at least one call"

    def test_sets_patient_age(self):
        """Test that _patient_demographics_attack sets PatientAge."""
        fuzzer = MetadataFuzzer()
        found = False
        for _ in range(20):
            dataset = Dataset()
            fuzzer._patient_demographics_attack(dataset)
            if hasattr(dataset, "PatientAge"):
                found = True
                break
        assert found, "PatientAge should be set in at least one call"

    def test_sets_weight_or_size(self):
        """Test that _patient_demographics_attack sets PatientWeight or PatientSize."""
        fuzzer = MetadataFuzzer()
        found = False
        for _ in range(20):
            dataset = Dataset()
            fuzzer._patient_demographics_attack(dataset)
            if hasattr(dataset, "PatientWeight") or hasattr(dataset, "PatientSize"):
                found = True
                break
        assert found, "PatientWeight or PatientSize should be set in at least one call"


class TestStudyMetadataAttack:
    """Test _study_metadata_attack method."""

    def test_modifies_study_fields(self):
        """Test that _study_metadata_attack sets study-level fields."""
        fuzzer = MetadataFuzzer()
        study_fields = [
            "StudyDate",
            "StudyTime",
            "StudyID",
            "AccessionNumber",
            "ReferringPhysicianName",
        ]
        found = False
        for _ in range(20):
            dataset = Dataset()
            fuzzer._study_metadata_attack(dataset)
            for field in study_fields:
                if hasattr(dataset, field):
                    found = True
                    break
            if found:
                break
        assert found, "At least one study field should be set"


class TestSeriesMetadataAttack:
    """Test _series_metadata_attack method."""

    def test_modifies_series_fields(self):
        """Test that _series_metadata_attack sets series-level fields."""
        fuzzer = MetadataFuzzer()
        series_fields = ["SeriesDate", "SeriesDescription", "BodyPartExamined"]
        found = False
        for _ in range(20):
            dataset = Dataset()
            fuzzer._series_metadata_attack(dataset)
            for field in series_fields:
                if hasattr(dataset, field):
                    found = True
                    break
            if found:
                break
        assert found, "At least one series field should be set"


class TestInstitutionPersonnelAttack:
    """Test _institution_personnel_attack method."""

    def test_modifies_institution_fields(self):
        """Test that _institution_personnel_attack sets institution/personnel fields."""
        fuzzer = MetadataFuzzer()
        institution_fields = [
            "InstitutionName",
            "InstitutionAddress",
            "StationName",
            "OperatorsName",
            "PerformingPhysicianName",
        ]
        found = False
        for _ in range(20):
            dataset = Dataset()
            fuzzer._institution_personnel_attack(dataset)
            for field in institution_fields:
                if hasattr(dataset, field):
                    found = True
                    break
            if found:
                break
        assert found, "At least one institution/personnel field should be set"


class TestRandomPnAttack:
    """Test _random_pn_attack helper method."""

    def test_returns_string(self):
        """Test that _random_pn_attack returns a string."""
        fuzzer = MetadataFuzzer()
        result = fuzzer._random_pn_attack()
        assert isinstance(result, str)

    def test_variety(self):
        """Test that _random_pn_attack produces varied output."""
        fuzzer = MetadataFuzzer()
        results = set()
        for _ in range(50):
            results.add(fuzzer._random_pn_attack())
        assert len(results) > 5, (
            f"Expected more than 5 unique values from 50 calls, got {len(results)}"
        )
