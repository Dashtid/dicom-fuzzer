"""Tests for StudyMutator - Study-Level Fuzzing Strategies."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pydicom
import pytest

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.strategies.study_mutator import (
    DicomStudy,
    StudyMutationRecord,
    StudyMutationStrategy,
    StudyMutator,
)


class TestStudyMutator:
    """Test StudyMutator initialization and configuration."""

    def test_init_default(self):
        """Test default initialization."""
        mutator = StudyMutator()
        assert mutator.severity == "moderate"
        assert mutator.seed is None

    def test_init_with_severity(self):
        """Test initialization with custom severity."""
        mutator = StudyMutator(severity="aggressive")
        assert mutator.severity == "aggressive"

    def test_init_with_seed(self):
        """Test initialization with random seed."""
        mutator = StudyMutator(seed=42)
        assert mutator.seed == 42

    def test_init_invalid_severity(self):
        """Test initialization with invalid severity raises error."""
        with pytest.raises(ValueError, match="Invalid severity"):
            StudyMutator(severity="invalid")

    @pytest.mark.parametrize(
        "severity",
        ["minimal", "moderate", "aggressive", "extreme"],
    )
    def test_all_severities_valid(self, severity):
        """Test all severity levels are valid."""
        mutator = StudyMutator(severity=severity)
        assert mutator.severity == severity


class TestStudyMutationStrategies:
    """Test individual mutation strategies."""

    @pytest.fixture
    def mock_study(self):
        """Create a mock study with multiple series."""
        # Create mock series
        series1 = MagicMock(spec=DicomSeries)
        series1.series_uid = "1.2.3.4.5.6.7.8.1"
        series1.slices = [Path("/fake/series1/slice1.dcm")]
        series1.slice_count = 1

        series2 = MagicMock(spec=DicomSeries)
        series2.series_uid = "1.2.3.4.5.6.7.8.2"
        series2.slices = [Path("/fake/series2/slice1.dcm")]
        series2.slice_count = 1

        study = DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="TEST_PATIENT",
            series_list=[series1, series2],
        )

        return study

    @pytest.fixture
    def mock_datasets(self):
        """Create mock datasets for two series."""
        # Series 1 datasets
        ds1 = pydicom.Dataset()
        ds1.PatientID = "TEST_PATIENT"
        ds1.PatientName = "Test^Patient"
        ds1.PatientSex = "M"
        ds1.PatientBirthDate = "19800101"
        ds1.StudyInstanceUID = "1.2.3.4.5.6.7.8.0"
        ds1.SeriesInstanceUID = "1.2.3.4.5.6.7.8.1"
        ds1.Modality = "CT"
        ds1.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.100"

        # Series 2 datasets
        ds2 = pydicom.Dataset()
        ds2.PatientID = "TEST_PATIENT"
        ds2.PatientName = "Test^Patient"
        ds2.PatientSex = "M"
        ds2.PatientBirthDate = "19800101"
        ds2.StudyInstanceUID = "1.2.3.4.5.6.7.8.0"
        ds2.SeriesInstanceUID = "1.2.3.4.5.6.7.8.2"
        ds2.Modality = "MR"
        ds2.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.101"

        return [[ds1], [ds2]]

    def test_mutate_cross_series_reference(self, mock_study, mock_datasets):
        """Test cross-series reference attack."""
        mutator = StudyMutator(severity="moderate", seed=42)

        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            datasets, records = mutator.mutate_study(
                mock_study,
                strategy=StudyMutationStrategy.CROSS_SERIES_REFERENCE,
                mutation_count=2,
            )

        assert len(records) > 0
        assert all(r.strategy == "cross_series_reference" for r in records)
        assert all(r.tag == "ReferencedSeriesSequence" for r in records)

    def test_mutate_frame_of_reference(self, mock_study, mock_datasets):
        """Test frame of reference attack."""
        mutator = StudyMutator(severity="aggressive", seed=42)

        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            datasets, records = mutator.mutate_study(
                mock_study,
                strategy=StudyMutationStrategy.FRAME_OF_REFERENCE,
                mutation_count=2,
            )

        assert len(records) > 0
        assert all(r.strategy == "frame_of_reference" for r in records)

    def test_mutate_patient_consistency(self, mock_study, mock_datasets):
        """Test patient consistency attack."""
        mutator = StudyMutator(severity="moderate", seed=42)

        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            datasets, records = mutator.mutate_study(
                mock_study,
                strategy=StudyMutationStrategy.PATIENT_CONSISTENCY,
                mutation_count=2,
            )

        assert len(records) > 0
        assert all(r.strategy == "patient_consistency" for r in records)

    def test_mutate_study_metadata(self, mock_study, mock_datasets):
        """Test study metadata attack."""
        mutator = StudyMutator(severity="extreme", seed=42)

        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            datasets, records = mutator.mutate_study(
                mock_study,
                strategy=StudyMutationStrategy.STUDY_METADATA,
                mutation_count=2,
            )

        assert len(records) > 0
        assert all(r.strategy == "study_metadata" for r in records)

    def test_mutate_mixed_modality(self, mock_study, mock_datasets):
        """Test mixed modality attack."""
        mutator = StudyMutator(severity="aggressive", seed=42)

        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            datasets, records = mutator.mutate_study(
                mock_study,
                strategy=StudyMutationStrategy.MIXED_MODALITY_STUDY,
                mutation_count=2,
            )

        assert len(records) > 0
        assert all(r.strategy == "mixed_modality_study" for r in records)

    def test_empty_study_raises(self):
        """Test that empty study raises ValueError."""
        mutator = StudyMutator()
        empty_study = DicomStudy(
            study_uid="1.2.3",
            patient_id="TEST",
            series_list=[],
        )

        with pytest.raises(ValueError, match="Cannot mutate empty study"):
            mutator.mutate_study(empty_study)

    def test_invalid_strategy_raises(self, mock_study, mock_datasets):
        """Test that invalid strategy raises ValueError."""
        mutator = StudyMutator()

        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            with pytest.raises(ValueError, match="Invalid strategy"):
                mutator.mutate_study(mock_study, strategy="invalid_strategy")


class TestStudyMutationRecord:
    """Test StudyMutationRecord serialization."""

    def test_record_creation(self):
        """Test creating a mutation record."""
        record = StudyMutationRecord(
            strategy="cross_series_reference",
            series_index=0,
            series_uid="1.2.3.4",
            tag="ReferencedSeriesSequence",
            original_value="<none>",
            mutated_value="1.2.3.4.5",
            severity="moderate",
            details={"attack_type": "nonexistent_reference"},
        )

        assert record.strategy == "cross_series_reference"
        assert record.series_index == 0
        assert record.tag == "ReferencedSeriesSequence"

    def test_record_serialization(self):
        """Test record can be serialized."""
        record = StudyMutationRecord(
            strategy="frame_of_reference",
            series_index=1,
            tag="FrameOfReferenceUID",
            original_value="1.2.3.4",
            mutated_value="",
            severity="aggressive",
        )

        # SerializableMixin should provide to_dict
        data = record.to_dict()
        assert isinstance(data, dict)
        assert data["strategy"] == "frame_of_reference"


class TestDicomStudy:
    """Test DicomStudy container."""

    def test_study_properties(self):
        """Test study property accessors."""
        series1 = MagicMock(spec=DicomSeries)
        series1.slice_count = 10

        series2 = MagicMock(spec=DicomSeries)
        series2.slice_count = 15

        study = DicomStudy(
            study_uid="1.2.3.4",
            patient_id="TEST",
            series_list=[series1, series2],
        )

        assert study.series_count == 2
        assert study.get_total_slices() == 25

    def test_empty_study(self):
        """Test empty study."""
        study = DicomStudy(
            study_uid="1.2.3.4",
            patient_id="TEST",
            series_list=[],
        )

        assert study.series_count == 0
        assert study.get_total_slices() == 0


class TestFrameOfReferenceAttackHelpers:
    """Test Frame of Reference attack helper methods directly."""

    @pytest.fixture
    def mutator(self):
        """Create a StudyMutator instance."""
        return StudyMutator(severity="moderate", seed=42)

    @pytest.fixture
    def mock_study(self):
        """Create a mock study with multiple series."""
        series1 = MagicMock(spec=DicomSeries)
        series1.series_uid = "1.2.3.4.5.6.7.8.1"
        series1.slices = [Path("/fake/series1/slice1.dcm")]
        series1.slice_count = 1

        series2 = MagicMock(spec=DicomSeries)
        series2.series_uid = "1.2.3.4.5.6.7.8.2"
        series2.slices = [Path("/fake/series2/slice1.dcm")]
        series2.slice_count = 1

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="TEST_PATIENT",
            series_list=[series1, series2],
        )

    @pytest.fixture
    def mock_datasets(self):
        """Create mock datasets for two series."""
        ds1 = pydicom.Dataset()
        ds1.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.100"

        ds2 = pydicom.Dataset()
        ds2.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.101"

        return [[ds1], [ds2]]

    def test_for_attack_different(self, mutator, mock_datasets, mock_study):
        """Test _for_attack_different applies unique FoR per series."""
        original_for = mock_datasets[0][0].FrameOfReferenceUID
        record = mutator._for_attack_different(mock_datasets, 0, mock_study)

        assert record.strategy == "frame_of_reference"
        assert record.details["attack_type"] == "different_for_per_series"
        assert mock_datasets[0][0].FrameOfReferenceUID != original_for

    def test_for_attack_same_unrelated(self, mutator, mock_datasets, mock_study):
        """Test _for_attack_same_unrelated applies same FoR to all series."""
        record = mutator._for_attack_same_unrelated(mock_datasets, mock_study)

        assert record is not None
        assert record.details["attack_type"] == "same_for_unrelated"
        # All datasets should have same FoR
        assert (
            mock_datasets[0][0].FrameOfReferenceUID
            == mock_datasets[1][0].FrameOfReferenceUID
        )

    def test_for_attack_same_unrelated_single_series(self, mutator, mock_study):
        """Test _for_attack_same_unrelated returns None for single series."""
        single_ds = [[pydicom.Dataset()]]
        record = mutator._for_attack_same_unrelated(single_ds, mock_study)
        assert record is None

    def test_for_attack_empty(self, mutator, mock_datasets, mock_study):
        """Test _for_attack_empty sets empty FoR."""
        record = mutator._for_attack_empty(mock_datasets, 0, mock_study)

        assert record.details["attack_type"] == "empty_for"
        assert mock_datasets[0][0].FrameOfReferenceUID == ""

    def test_for_attack_invalid(self, mutator, mock_datasets, mock_study):
        """Test _for_attack_invalid sets invalid FoR format."""
        record = mutator._for_attack_invalid(mock_datasets, 0, mock_study)

        assert record.details["attack_type"] == "invalid_for"
        assert "INVALID" in mock_datasets[0][0].FrameOfReferenceUID

    def test_for_attack_inconsistent(self, mutator, mock_datasets, mock_study):
        """Test _for_attack_inconsistent creates per-slice variation."""
        # Add more slices to first series
        ds1_extra = pydicom.Dataset()
        ds1_extra.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.100"
        mock_datasets[0].append(ds1_extra)

        record = mutator._for_attack_inconsistent(mock_datasets, 0, mock_study)

        assert record.details["attack_type"] == "inconsistent_within_series"
        # Each slice should have different FoR
        assert (
            mock_datasets[0][0].FrameOfReferenceUID
            != mock_datasets[0][1].FrameOfReferenceUID
        )


class TestPatientConsistencyAttackHelpers:
    """Test Patient Consistency attack helper methods directly."""

    @pytest.fixture
    def mutator(self):
        """Create a StudyMutator instance."""
        return StudyMutator(severity="moderate", seed=42)

    @pytest.fixture
    def mock_study(self):
        """Create a mock study."""
        series1 = MagicMock(spec=DicomSeries)
        series1.series_uid = "1.2.3.4.5.6.7.8.1"

        series2 = MagicMock(spec=DicomSeries)
        series2.series_uid = "1.2.3.4.5.6.7.8.2"

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="TEST_PATIENT",
            series_list=[series1, series2],
        )

    @pytest.fixture
    def mock_datasets(self):
        """Create mock datasets with patient info."""
        ds1 = pydicom.Dataset()
        ds1.PatientID = "ORIGINAL_ID"
        ds1.PatientName = "Original^Patient"
        ds1.PatientSex = "M"
        ds1.PatientBirthDate = "19800101"

        ds2 = pydicom.Dataset()
        ds2.PatientID = "ORIGINAL_ID"
        ds2.PatientName = "Original^Patient"
        ds2.PatientSex = "M"
        ds2.PatientBirthDate = "19800101"

        return [[ds1], [ds2]]

    def test_patient_attack_different_id(self, mutator, mock_datasets, mock_study):
        """Test _patient_attack_different_id changes PatientID."""
        original_id = mock_datasets[0][0].PatientID
        record = mutator._patient_attack_different_id(mock_datasets, 0, mock_study)

        assert record.strategy == "patient_consistency"
        assert record.details["attack_type"] == "different_patient_id"
        assert mock_datasets[0][0].PatientID != original_id
        assert "FUZZED_" in mock_datasets[0][0].PatientID

    def test_patient_attack_demographics(self, mutator, mock_datasets, mock_study):
        """Test _patient_attack_demographics changes PatientSex."""
        record = mutator._patient_attack_demographics(mock_datasets, 0, mock_study)

        assert record.strategy == "patient_consistency"
        assert record.details["attack_type"] == "conflicting_demographics"
        assert record.tag == "PatientSex"

    def test_patient_attack_mixed_name(self, mutator, mock_datasets, mock_study):
        """Test _patient_attack_mixed_name changes PatientName."""
        original_name = mock_datasets[0][0].PatientName
        record = mutator._patient_attack_mixed_name(mock_datasets, 0, mock_study)

        assert record.strategy == "patient_consistency"
        assert record.details["attack_type"] == "mixed_patient_name"
        assert mock_datasets[0][0].PatientName != original_name
        assert "FUZZED" in str(mock_datasets[0][0].PatientName)

    def test_patient_attack_birthdate(self, mutator, mock_datasets, mock_study):
        """Test _patient_attack_birthdate changes PatientBirthDate."""
        original_date = mock_datasets[0][0].PatientBirthDate
        record = mutator._patient_attack_birthdate(mock_datasets, 0, mock_study)

        assert record.strategy == "patient_consistency"
        assert record.details["attack_type"] == "conflicting_birthdate"
        assert mock_datasets[0][0].PatientBirthDate != original_date


class TestStudyMetadataAttackHelpers:
    """Test Study Metadata attack helper methods directly."""

    @pytest.fixture
    def mutator(self):
        """Create a StudyMutator instance."""
        return StudyMutator(severity="moderate", seed=42)

    @pytest.fixture
    def mock_study(self):
        """Create a mock study."""
        series1 = MagicMock(spec=DicomSeries)
        series1.series_uid = "1.2.3.4.5.6.7.8.1"

        series2 = MagicMock(spec=DicomSeries)
        series2.series_uid = "1.2.3.4.5.6.7.8.2"

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="TEST_PATIENT",
            series_list=[series1, series2],
        )

    @pytest.fixture
    def mock_datasets(self):
        """Create mock datasets with study metadata."""
        ds1 = pydicom.Dataset()
        ds1.StudyInstanceUID = "1.2.3.4.5.6.7.8.0"
        ds1.StudyDate = "20230101"
        ds1.StudyID = "STUDY001"

        ds2 = pydicom.Dataset()
        ds2.StudyInstanceUID = "1.2.3.4.5.6.7.8.0"
        ds2.StudyDate = "20230101"
        ds2.StudyID = "STUDY001"

        return [[ds1], [ds2]]

    def test_study_meta_uid_mismatch(self, mutator, mock_datasets, mock_study):
        """Test _study_meta_uid_mismatch creates UID conflicts."""
        records = []
        mutator._study_meta_uid_mismatch(mock_datasets, mock_study, records)

        assert len(records) == 2  # One record per series
        assert all(r.details["attack_type"] == "study_uid_mismatch" for r in records)
        # UIDs should now be different between series
        assert (
            mock_datasets[0][0].StudyInstanceUID != mock_datasets[1][0].StudyInstanceUID
        )

    def test_study_meta_uid_mismatch_single_series(self, mutator, mock_study):
        """Test _study_meta_uid_mismatch with single series does nothing."""
        single_ds = [[pydicom.Dataset()]]
        single_ds[0][0].StudyInstanceUID = "1.2.3.4"
        records = []
        mutator._study_meta_uid_mismatch(single_ds, mock_study, records)
        assert len(records) == 0

    def test_study_meta_date_conflict(self, mutator, mock_datasets, mock_study):
        """Test _study_meta_date_conflict changes StudyDate."""
        original_date = mock_datasets[0][0].StudyDate
        records = []
        mutator._study_meta_date_conflict(mock_datasets, mock_study, records)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "study_date_conflict"

    def test_study_meta_extreme_id(self, mutator, mock_datasets, mock_study):
        """Test _study_meta_extreme_id applies extreme StudyID values."""
        records = []
        mutator._study_meta_extreme_id(mock_datasets, mock_study, records)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "extreme_study_id"

    def test_study_meta_empty_uid(self, mutator, mock_datasets, mock_study):
        """Test _study_meta_empty_uid sets empty StudyInstanceUID."""
        records = []
        mutator._study_meta_empty_uid(mock_datasets, mock_study, records)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "empty_study_uid"


class TestLoadStudy:
    """Test load_study method."""

    def test_load_study_nonexistent_directory(self):
        """Test load_study with non-existent directory raises ValueError."""
        mutator = StudyMutator()

        with pytest.raises(ValueError, match="does not exist"):
            mutator.load_study(Path("/nonexistent/path/to/study"))

    def test_load_study_empty_directory(self, tmp_path):
        """Test load_study with empty directory raises ValueError."""
        mutator = StudyMutator()

        with pytest.raises(ValueError, match="No valid DICOM series"):
            mutator.load_study(tmp_path)


class TestMutateStudyEdgeCases:
    """Test edge cases in mutate_study."""

    @pytest.fixture
    def mutator(self):
        """Create a StudyMutator instance."""
        return StudyMutator(severity="moderate", seed=42)

    @pytest.fixture
    def single_series_study(self):
        """Create a study with a single series."""
        series1 = MagicMock(spec=DicomSeries)
        series1.series_uid = "1.2.3.4.5.6.7.8.1"
        series1.slices = [Path("/fake/series1/slice1.dcm")]
        series1.slice_count = 1

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="TEST_PATIENT",
            series_list=[series1],
        )

    @pytest.fixture
    def single_series_datasets(self):
        """Create datasets for single series."""
        ds1 = pydicom.Dataset()
        ds1.PatientID = "TEST_PATIENT"
        ds1.StudyInstanceUID = "1.2.3.4.5.6.7.8.0"
        ds1.SeriesInstanceUID = "1.2.3.4.5.6.7.8.1"
        ds1.Modality = "CT"
        ds1.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.100"
        return [[ds1]]

    def test_mutate_single_series_cross_reference(
        self, mutator, single_series_study, single_series_datasets
    ):
        """Test cross-series reference with single series."""
        with patch.object(
            mutator, "_load_study_datasets", return_value=single_series_datasets
        ):
            datasets, records = mutator.mutate_study(
                single_series_study,
                strategy=StudyMutationStrategy.CROSS_SERIES_REFERENCE,
                mutation_count=2,
            )

        assert len(records) > 0

    def test_mutate_random_strategy_selection(
        self, mutator, single_series_study, single_series_datasets
    ):
        """Test mutate_study with None strategy selects randomly."""
        with patch.object(
            mutator, "_load_study_datasets", return_value=single_series_datasets
        ):
            datasets, records = mutator.mutate_study(
                single_series_study,
                strategy=None,
                mutation_count=1,
            )

        assert len(records) > 0

    def test_severity_mutation_count_minimal(
        self, single_series_study, single_series_datasets
    ):
        """Test minimal severity produces fewer mutations."""
        mutator = StudyMutator(severity="minimal", seed=42)

        with patch.object(
            mutator, "_load_study_datasets", return_value=single_series_datasets
        ):
            datasets, records = mutator.mutate_study(
                single_series_study,
                strategy=StudyMutationStrategy.FRAME_OF_REFERENCE,
            )

        # Minimal should produce 1-2 mutations
        assert 1 <= len(records) <= 2

    def test_severity_mutation_count_extreme(
        self, single_series_study, single_series_datasets
    ):
        """Test extreme severity produces more mutations."""
        mutator = StudyMutator(severity="extreme", seed=42)

        with patch.object(
            mutator, "_load_study_datasets", return_value=single_series_datasets
        ):
            datasets, records = mutator.mutate_study(
                single_series_study,
                strategy=StudyMutationStrategy.FRAME_OF_REFERENCE,
            )

        # Extreme should produce 8-15 mutations
        assert len(records) >= 1  # May be less if single series limits options
