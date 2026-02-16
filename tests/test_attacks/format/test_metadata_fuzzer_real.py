"""Real-world tests for metadata fuzzer strategy.

Tests patient information mutation with actual DICOM datasets.
"""

from datetime import datetime

from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.base import FormatFuzzerBase
from dicom_fuzzer.attacks.format.metadata_fuzzer import MetadataFuzzer


class TestMetadataFuzzerInitialization:
    """Test MetadataFuzzer initialization."""

    def test_initialization(self):
        """Test creating MetadataFuzzer instance."""
        fuzzer = MetadataFuzzer()

        assert fuzzer is not None
        assert hasattr(fuzzer, "fake_names")

    def test_fake_names_populated(self):
        """Test that fake names list is populated."""
        fuzzer = MetadataFuzzer()

        assert len(fuzzer.fake_names) > 0
        assert "Smith^John" in fuzzer.fake_names
        assert "Doe^Jane" in fuzzer.fake_names

    def test_patient_id_generated_format(self):
        """Test that generated patient IDs follow correct format."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        result = fuzzer.mutate_patient_info(dataset)
        patient_id = str(result.PatientID)
        assert patient_id.startswith("PAT")
        assert len(patient_id) == 9  # PAT + 6 digits
        assert patient_id[3:].isdigit()


class TestMutatePatientInfo:
    """Test mutate_patient_info method."""

    def test_mutate_patient_info_basic(self):
        """Test basic patient info mutation."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()
        dataset.PatientID = "ORIGINAL123"
        dataset.PatientName = "Original^Name"
        dataset.PatientBirthDate = "19800101"

        result = fuzzer.mutate_patient_info(dataset)

        # Should have new values
        assert result.PatientID != "ORIGINAL123"
        assert result.PatientName != "Original^Name"
        assert result.PatientBirthDate != "19800101"

    def test_mutate_patient_info_returns_dataset(self):
        """Test that method returns the dataset."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        result = fuzzer.mutate_patient_info(dataset)

        assert result is dataset  # Should be same object

    def test_mutate_patient_info_sets_all_fields(self):
        """Test that all patient fields are set."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        result = fuzzer.mutate_patient_info(dataset)

        assert hasattr(result, "PatientID")
        assert hasattr(result, "PatientName")
        assert hasattr(result, "PatientBirthDate")

    def test_mutate_patient_info_id_format(self):
        """Test that PatientID follows PAT+6digit format."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        result = fuzzer.mutate_patient_info(dataset)
        patient_id = str(result.PatientID)

        assert patient_id.startswith("PAT")
        assert len(patient_id) == 9
        assert patient_id[3:].isdigit()

    def test_mutate_patient_info_name_from_fake_list(self):
        """Test that PatientName comes from fake_names list."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        result = fuzzer.mutate_patient_info(dataset)

        assert result.PatientName in fuzzer.fake_names

    def test_mutate_patient_info_multiple_calls_vary(self):
        """Test that multiple mutations produce different values."""
        fuzzer = MetadataFuzzer()

        ids = set()
        names = set()
        dates = set()

        for _ in range(50):
            dataset = Dataset()
            result = fuzzer.mutate_patient_info(dataset)
            ids.add(result.PatientID)
            names.add(result.PatientName)
            dates.add(result.PatientBirthDate)

        # Should have some variety (not all identical)
        assert len(ids) > 1 or len(names) > 1 or len(dates) > 1


class TestRandomDate:
    """Test _random_date private method."""

    def test_random_date_format(self):
        """Test that random date uses DICOM format (YYYYMMDD)."""
        fuzzer = MetadataFuzzer()

        date = fuzzer._random_date()

        # Should be 8 characters
        assert len(date) == 8
        # Should be all digits
        assert date.isdigit()

    def test_random_date_valid_range(self):
        """Test that random date is in valid range (1950-2010)."""
        fuzzer = MetadataFuzzer()

        for _ in range(20):
            date = fuzzer._random_date()

            # Parse the date
            year = int(date[:4])
            month = int(date[4:6])
            day = int(date[6:8])

            # Year should be in range
            assert 1950 <= year <= 2010
            # Month should be valid
            assert 1 <= month <= 12
            # Day should be valid
            assert 1 <= day <= 31

    def test_random_date_parseable(self):
        """Test that random date can be parsed as datetime."""
        fuzzer = MetadataFuzzer()

        for _ in range(10):
            date = fuzzer._random_date()

            # Should be parseable
            parsed = datetime.strptime(date, "%Y%m%d")
            assert isinstance(parsed, datetime)

    def test_random_date_variety(self):
        """Test that random dates have variety."""
        fuzzer = MetadataFuzzer()

        dates = set()
        for _ in range(100):
            dates.add(fuzzer._random_date())

        # Should generate multiple different dates
        assert len(dates) > 10


class TestIntegrationScenarios:
    """Test realistic usage scenarios."""

    def test_complete_patient_anonymization(self):
        """Test complete patient data anonymization workflow."""
        fuzzer = MetadataFuzzer()

        # Create dataset with real-looking patient data
        dataset = Dataset()
        dataset.PatientID = "REAL12345"
        dataset.PatientName = "RealPerson^John^Q"
        dataset.PatientBirthDate = "19750315"
        dataset.StudyDescription = "CT HEAD"  # Should not be modified

        result = fuzzer.mutate_patient_info(dataset)

        # Patient data should be changed
        assert result.PatientID != "REAL12345"
        assert result.PatientName != "RealPerson^John^Q"
        assert result.PatientBirthDate != "19750315"

        # Other fields should remain
        assert result.StudyDescription == "CT HEAD"

    def test_multiple_mutations_on_same_dataset(self):
        """Test mutating same dataset multiple times."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        first = fuzzer.mutate_patient_info(dataset)
        _ = first.PatientID  # Access attribute to test it exists

        second = fuzzer.mutate_patient_info(dataset)
        _ = second.PatientID  # Access attribute to test it exists

        # Each mutation might produce different values
        # (or same if random picks same value)
        assert first is second  # Same object
        assert hasattr(second, "PatientID")

    def test_batch_mutation(self):
        """Test mutating multiple datasets in batch."""
        fuzzer = MetadataFuzzer()

        datasets = []
        for i in range(10):
            ds = Dataset()
            ds.PatientID = f"ORIG{i}"
            datasets.append(ds)

        # Mutate all
        for ds in datasets:
            fuzzer.mutate_patient_info(ds)

        # All should have fake patient info
        for ds in datasets:
            patient_id = str(ds.PatientID)
            assert patient_id.startswith("PAT") and len(patient_id) == 9
            assert ds.PatientName in fuzzer.fake_names

    def test_fuzzer_independence(self):
        """Test that multiple fuzzer instances are independent."""
        fuzzer1 = MetadataFuzzer()
        fuzzer2 = MetadataFuzzer()

        # Both should have same fake data
        assert fuzzer1.fake_names == fuzzer2.fake_names


class TestMutateMethod:
    """Test the mutate() method with real Datasets."""

    # All attribute names that the 5 attack categories can set
    _ALL_ATTACK_ATTRIBUTES = {
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
    }

    def test_mutate_returns_dataset(self):
        """Test that mutate() returns the same dataset object."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()

        result = fuzzer.mutate(dataset)

        assert result is dataset

    def test_mutate_adds_attributes(self):
        """Test that mutate() adds attributes from multiple categories."""
        fuzzer = MetadataFuzzer()

        seen_attributes = set()
        for _ in range(30):
            dataset = Dataset()
            fuzzer.mutate(dataset)
            for attr in self._ALL_ATTACK_ATTRIBUTES:
                if hasattr(dataset, attr):
                    seen_attributes.add(attr)

        # Across 30 runs with 1-3 categories each, we should see
        # attributes from at least 3 different fields
        assert len(seen_attributes) >= 3, (
            f"Expected at least 3 different attribute types across 30 runs, "
            f"but only saw {len(seen_attributes)}: {seen_attributes}"
        )

    def test_mutate_does_not_affect_pixel_data(self):
        """Test that mutate() leaves PixelData unchanged."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()
        dataset.PixelData = b"\x00\x01"

        fuzzer.mutate(dataset)

        assert dataset.PixelData == b"\x00\x01"

    def test_mutate_preserves_existing_fields(self):
        """Test that mutate() preserves fields it does not target."""
        fuzzer = MetadataFuzzer()
        dataset = Dataset()
        dataset.Modality = "CT"

        fuzzer.mutate(dataset)

        assert dataset.Modality == "CT"


class TestFormatFuzzerBaseCompliance:
    """Verify MetadataFuzzer complies with FormatFuzzerBase interface."""

    def test_is_format_fuzzer_base(self):
        """Test that MetadataFuzzer is an instance of FormatFuzzerBase."""
        assert isinstance(MetadataFuzzer(), FormatFuzzerBase)

    def test_strategy_name(self):
        """Test that strategy_name returns 'metadata'."""
        assert MetadataFuzzer().strategy_name == "metadata"
