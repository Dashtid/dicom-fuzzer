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
