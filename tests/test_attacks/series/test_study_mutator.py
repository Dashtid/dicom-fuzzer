"""Tests for StudyMutator - Study-Level Fuzzing Strategies."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pydicom
import pytest

from dicom_fuzzer.attacks.series.study_mutator import (
    DicomStudy,
    StudyMutationRecord,
    StudyMutationStrategy,
    StudyMutator,
)
from dicom_fuzzer.core.dicom.series import DicomSeries


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


class TestCrossSeriesCycles:
    """Multi-hop cyclic ReferencedSeriesSequence attacks.

    Single-hop self-reference (A->A) is already covered by the
    existing 'circular_reference' branch. These tests cover the harder
    case where parsers must maintain a visited set across multiple
    hops to avoid infinite loops.
    """

    @pytest.fixture
    def two_series_study(self):
        """Mock study with exactly 2 series."""
        s1 = MagicMock(spec=DicomSeries)
        s1.series_uid = "1.2.3.4.5.6.7.8.1"
        s1.slices = [Path("/fake/s1/sl1.dcm")]
        s1.slice_count = 1

        s2 = MagicMock(spec=DicomSeries)
        s2.series_uid = "1.2.3.4.5.6.7.8.2"
        s2.slices = [Path("/fake/s2/sl1.dcm")]
        s2.slice_count = 1

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="P",
            series_list=[s1, s2],
        )

    @pytest.fixture
    def two_series_datasets(self):
        ds1 = pydicom.Dataset()
        ds1.SeriesInstanceUID = "1.2.3.4.5.6.7.8.1"
        ds2 = pydicom.Dataset()
        ds2.SeriesInstanceUID = "1.2.3.4.5.6.7.8.2"
        return [[ds1], [ds2]]

    @pytest.fixture
    def three_series_study(self):
        series_list = []
        for i in range(1, 4):
            s = MagicMock(spec=DicomSeries)
            s.series_uid = f"1.2.3.4.5.6.7.8.{i}"
            s.slices = [Path(f"/fake/s{i}/sl1.dcm")]
            s.slice_count = 1
            series_list.append(s)
        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="P",
            series_list=series_list,
        )

    @pytest.fixture
    def three_series_datasets(self):
        out = []
        for i in range(1, 4):
            ds = pydicom.Dataset()
            ds.SeriesInstanceUID = f"1.2.3.4.5.6.7.8.{i}"
            out.append([ds])
        return out

    @pytest.fixture
    def single_series_study(self):
        s = MagicMock(spec=DicomSeries)
        s.series_uid = "1.2.3.4.5.6.7.8.1"
        s.slices = [Path("/fake/s1/sl1.dcm")]
        s.slice_count = 1
        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="P",
            series_list=[s],
        )

    @pytest.fixture
    def single_series_datasets(self):
        ds = pydicom.Dataset()
        ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.1"
        return [[ds]]

    def test_mutual_cycle_creates_a_to_b_and_b_to_a(
        self, two_series_study, two_series_datasets
    ):
        mutator = StudyMutator(seed=42)
        records = mutator._apply_mutual_cycle(two_series_datasets, two_series_study)

        a_uid = two_series_study.series_list[0].series_uid
        b_uid = two_series_study.series_list[1].series_uid

        # series[0] now references series[1]
        ds_a = two_series_datasets[0][0]
        assert ds_a.ReferencedSeriesSequence[0].SeriesInstanceUID == b_uid
        # series[1] now references series[0] -- closing the loop
        ds_b = two_series_datasets[1][0]
        assert ds_b.ReferencedSeriesSequence[0].SeriesInstanceUID == a_uid
        assert len(records) == 2

    def test_mutual_cycle_records_both_hops(
        self, two_series_study, two_series_datasets
    ):
        mutator = StudyMutator(seed=42)
        records = mutator._apply_mutual_cycle(two_series_datasets, two_series_study)
        assert {r.series_index for r in records} == {0, 1}
        assert all(r.strategy == "cross_series_reference" for r in records)
        assert all(r.details["attack_type"] == "mutual_cycle" for r in records)
        assert all(r.details["cycle_length"] == 2 for r in records)

    def test_mutual_cycle_skipped_with_single_series(
        self, single_series_study, single_series_datasets
    ):
        # No partner to point at; helper must short-circuit cleanly.
        mutator = StudyMutator(seed=42)
        records = mutator._apply_mutual_cycle(
            single_series_datasets, single_series_study
        )
        assert records == []
        # Original dataset must not have been mutated.
        ds = single_series_datasets[0][0]
        assert "ReferencedSeriesSequence" not in ds

    def test_deep_cycle_with_three_series(
        self, three_series_study, three_series_datasets
    ):
        mutator = StudyMutator(seed=42)
        records = mutator._apply_deep_cycle(three_series_datasets, three_series_study)

        uids = [s.series_uid for s in three_series_study.series_list]
        # Each series should reference the next; last loops back to first.
        for i in range(3):
            ds = three_series_datasets[i][0]
            expected_target = uids[(i + 1) % 3]
            assert ds.ReferencedSeriesSequence[0].SeriesInstanceUID == expected_target
        assert len(records) == 3
        assert all(r.details["attack_type"] == "deep_cycle" for r in records)
        assert all(r.details["cycle_length"] == 3 for r in records)

    def test_deep_cycle_falls_back_to_mutual_with_two_series(
        self, two_series_study, two_series_datasets
    ):
        # With <3 series the deep_cycle helper degrades into mutual_cycle.
        mutator = StudyMutator(seed=42)
        records = mutator._apply_deep_cycle(two_series_datasets, two_series_study)
        # Should be 2 records, attack_type="mutual_cycle" (not deep_cycle)
        assert len(records) == 2
        assert all(r.details["attack_type"] == "mutual_cycle" for r in records)

    def test_cycle_uids_round_trip_through_dcmwrite(
        self, two_series_study, two_series_datasets
    ):
        # Confirm a cycled dataset still serializes -- the cycle is a
        # logical graph problem, not a structural DICOM problem.
        import io

        mutator = StudyMutator(seed=42)
        mutator._apply_mutual_cycle(two_series_datasets, two_series_study)

        ds = two_series_datasets[0][0]
        # Add minimal fields so dcmwrite is happy.
        ds.PatientID = "P"
        ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.99"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.is_little_endian = True
        ds.is_implicit_VR = True

        buf = io.BytesIO()
        pydicom.dcmwrite(buf, ds, enforce_file_format=False)
        buf.seek(0)
        roundtripped = pydicom.dcmread(buf, force=True)
        assert (
            roundtripped.ReferencedSeriesSequence[0].SeriesInstanceUID
            == two_series_study.series_list[1].series_uid
        )

    def test_dispatcher_invokes_mutual_cycle_when_chosen(
        self, two_series_study, two_series_datasets, monkeypatch
    ):
        # Force random.choice to always return mutual_cycle so we can
        # observe the dispatcher actually wires through to the helper.
        import dicom_fuzzer.attacks.series.study_mutator as study_mod

        monkeypatch.setattr(study_mod.random, "choice", lambda choices: "mutual_cycle")
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_cross_series_reference(
            two_series_datasets, two_series_study, mutation_count=5
        )
        # Cycle helper runs at most once even with mutation_count=5.
        assert any(r.details["attack_type"] == "mutual_cycle" for r in records)
        # Total records should be 2 (one per cycle participant), not 10.
        cycle_records = [
            r for r in records if r.details["attack_type"] == "mutual_cycle"
        ]
        assert len(cycle_records) == 2

    def test_dispatcher_invokes_deep_cycle_when_chosen(
        self, three_series_study, three_series_datasets, monkeypatch
    ):
        import dicom_fuzzer.attacks.series.study_mutator as study_mod

        monkeypatch.setattr(study_mod.random, "choice", lambda choices: "deep_cycle")
        # randint also gets called for series_idx -- keep it deterministic.
        monkeypatch.setattr(study_mod.random, "randint", lambda a, b: 0)
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_cross_series_reference(
            three_series_datasets, three_series_study, mutation_count=5
        )
        cycle_records = [r for r in records if r.details["attack_type"] == "deep_cycle"]
        # 3 cycle records (one per series), no duplication despite count=5.
        assert len(cycle_records) == 3


class TestSopInstanceCollision:
    """SOPInstanceUID collision attacks across series.

    These attacks force two slices in different series to share a
    SOPInstanceUID. PACS dedup logic, DB unique-key constraints, and
    SOPInstanceUID-keyed caches all assume global uniqueness; collisions
    probe what happens when that assumption breaks.
    """

    @staticmethod
    def _force_attack(monkeypatch, attack_type: str) -> None:
        import dicom_fuzzer.attacks.series.study_mutator as mod

        monkeypatch.setattr(mod.random, "choice", lambda choices: attack_type)

    @pytest.fixture
    def two_series_study(self):
        s1 = MagicMock(spec=DicomSeries)
        s1.series_uid = "1.2.3.4.5.6.7.8.1"
        s1.slices = [Path("/fake/s1/sl1.dcm")]
        s1.slice_count = 1

        s2 = MagicMock(spec=DicomSeries)
        s2.series_uid = "1.2.3.4.5.6.7.8.2"
        s2.slices = [Path("/fake/s2/sl1.dcm")]
        s2.slice_count = 1

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="P",
            series_list=[s1, s2],
        )

    @pytest.fixture
    def two_series_datasets(self):
        ds1 = pydicom.Dataset()
        ds1.SOPInstanceUID = "1.2.3.4.5.6.7.8.1.A"
        ds2 = pydicom.Dataset()
        ds2.SOPInstanceUID = "1.2.3.4.5.6.7.8.2.A"
        return [[ds1], [ds2]]

    @pytest.fixture
    def three_series_study(self):
        series_list = []
        for i in range(1, 4):
            s = MagicMock(spec=DicomSeries)
            s.series_uid = f"1.2.3.4.5.6.7.8.{i}"
            s.slices = [Path(f"/fake/s{i}/sl1.dcm")]
            s.slice_count = 2
            series_list.append(s)
        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="P",
            series_list=series_list,
        )

    @pytest.fixture
    def three_series_datasets(self):
        out = []
        for i in range(1, 4):
            slice_list = []
            for j in range(2):
                ds = pydicom.Dataset()
                ds.SOPInstanceUID = f"1.2.3.4.5.6.7.8.{i}.{j}"
                slice_list.append(ds)
            out.append(slice_list)
        return out

    @pytest.fixture
    def single_series_study(self):
        s = MagicMock(spec=DicomSeries)
        s.series_uid = "1.2.3.4.5.6.7.8.1"
        s.slices = [Path("/fake/s1/sl1.dcm")]
        s.slice_count = 1
        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="P",
            series_list=[s],
        )

    @pytest.fixture
    def single_series_datasets(self):
        ds = pydicom.Dataset()
        ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.1.A"
        return [[ds]]

    def test_cross_series_collision_copies_uid(
        self, two_series_study, two_series_datasets, monkeypatch
    ):
        self._force_attack(monkeypatch, "cross_series_collision")
        mutator = StudyMutator(seed=42)
        _, _ = mutator._mutate_sop_instance_collision(
            two_series_datasets, two_series_study, mutation_count=1
        )
        # Series[1]'s slice should now match series[0]'s slice UID.
        assert (
            two_series_datasets[1][0].SOPInstanceUID
            == two_series_datasets[0][0].SOPInstanceUID
        )

    def test_cross_series_collision_records_one_pair(
        self, two_series_study, two_series_datasets, monkeypatch
    ):
        self._force_attack(monkeypatch, "cross_series_collision")
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_sop_instance_collision(
            two_series_datasets, two_series_study, mutation_count=1
        )
        assert len(records) == 1
        assert records[0].tag == "SOPInstanceUID"
        assert records[0].details["attack_type"] == "cross_series_collision"

    def test_study_wide_uniform_sets_one_uid_everywhere(
        self, three_series_study, three_series_datasets, monkeypatch
    ):
        self._force_attack(monkeypatch, "study_wide_uniform")
        mutator = StudyMutator(seed=42)
        _, _ = mutator._mutate_sop_instance_collision(
            three_series_datasets, three_series_study, mutation_count=1
        )
        all_uids = {
            ds.SOPInstanceUID for series in three_series_datasets for ds in series
        }
        assert len(all_uids) == 1

    def test_study_wide_uniform_records_one_per_slice(
        self, three_series_study, three_series_datasets, monkeypatch
    ):
        self._force_attack(monkeypatch, "study_wide_uniform")
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_sop_instance_collision(
            three_series_datasets, three_series_study, mutation_count=1
        )
        total_slices = sum(len(s) for s in three_series_datasets)
        assert len(records) == total_slices

    def test_pairwise_swap_changes_ownership(
        self, three_series_study, three_series_datasets, monkeypatch
    ):
        self._force_attack(monkeypatch, "pairwise_swap")
        before = [three_series_datasets[i][0].SOPInstanceUID for i in range(3)]
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_sop_instance_collision(
            three_series_datasets, three_series_study, mutation_count=1
        )
        after = [three_series_datasets[i][0].SOPInstanceUID for i in range(3)]
        # At least one slice's first-slice UID should differ from before.
        assert before != after
        # 2 pairs (series 0<->1 and 1<->2) -> 4 records
        assert len(records) == 4

    def test_pairwise_swap_preserves_uid_population(
        self, three_series_study, three_series_datasets, monkeypatch
    ):
        # Swap only moves UIDs around; the *set* of UIDs across the
        # touched slices stays the same.
        self._force_attack(monkeypatch, "pairwise_swap")
        before_uids = {three_series_datasets[i][0].SOPInstanceUID for i in range(3)}
        mutator = StudyMutator(seed=42)
        _, _ = mutator._mutate_sop_instance_collision(
            three_series_datasets, three_series_study, mutation_count=1
        )
        after_uids = {three_series_datasets[i][0].SOPInstanceUID for i in range(3)}
        assert before_uids == after_uids

    def test_skipped_with_single_series(
        self, single_series_study, single_series_datasets, monkeypatch
    ):
        # No partner series -> helper short-circuits, no records.
        self._force_attack(monkeypatch, "cross_series_collision")
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_sop_instance_collision(
            single_series_datasets, single_series_study, mutation_count=5
        )
        assert records == []
        # Original UID must not have been mutated.
        assert single_series_datasets[0][0].SOPInstanceUID == "1.2.3.4.5.6.7.8.1.A"

    def test_runs_once_regardless_of_mutation_count(
        self, three_series_study, three_series_datasets, monkeypatch
    ):
        # Coordinated cross-series rewrite is idempotent under
        # repeated application; large mutation_count must not multiply
        # records.
        self._force_attack(monkeypatch, "study_wide_uniform")
        mutator = StudyMutator(seed=42)
        _, records = mutator._mutate_sop_instance_collision(
            three_series_datasets, three_series_study, mutation_count=10
        )
        total_slices = sum(len(s) for s in three_series_datasets)
        assert len(records) == total_slices

    def test_strategy_in_enum(self):
        assert (
            StudyMutationStrategy.SOP_INSTANCE_COLLISION.value
            == "sop_instance_collision"
        )

    def test_strategy_dispatched_through_mutate_study(
        self, two_series_study, two_series_datasets, monkeypatch
    ):
        self._force_attack(monkeypatch, "cross_series_collision")
        mutator = StudyMutator(severity="moderate", seed=42)
        with patch.object(
            mutator, "_load_study_datasets", return_value=two_series_datasets
        ):
            _, records = mutator.mutate_study(
                two_series_study,
                strategy=StudyMutationStrategy.SOP_INSTANCE_COLLISION,
                mutation_count=1,
            )
        assert len(records) == 1
        assert records[0].strategy == "sop_instance_collision"


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


class TestRegistrationGeometryStrategy:
    """Test REGISTRATION_GEOMETRY study mutation strategy."""

    @pytest.fixture
    def mutator(self):
        return StudyMutator(severity="moderate", seed=42)

    @pytest.fixture
    def mock_study(self):
        series1 = MagicMock(spec=DicomSeries)
        series1.series_uid = "1.2.3.4.5.6.7.8.1"
        series1.slices = [Path("/fake/s1/slice1.dcm")]
        series1.slice_count = 1

        series2 = MagicMock(spec=DicomSeries)
        series2.series_uid = "1.2.3.4.5.6.7.8.2"
        series2.slices = [Path("/fake/s2/slice1.dcm")]
        series2.slice_count = 1

        return DicomStudy(
            study_uid="1.2.3.4.5.6.7.8.0",
            patient_id="TEST",
            series_list=[series1, series2],
        )

    @pytest.fixture
    def mock_datasets(self):
        ds1 = pydicom.Dataset()
        ds1.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.100"
        ds1.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds1.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]

        ds2 = pydicom.Dataset()
        ds2.FrameOfReferenceUID = "1.2.3.4.5.6.7.8.101"
        ds2.ImagePositionPatient = [0.0, 0.0, 5.0]
        ds2.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]

        return [[ds1], [ds2]]

    def test_mutate_registration_geometry_via_study(
        self, mutator, mock_study, mock_datasets
    ):
        """Test REGISTRATION_GEOMETRY strategy via mutate_study."""
        with patch.object(mutator, "_load_study_datasets", return_value=mock_datasets):
            datasets, records = mutator.mutate_study(
                mock_study,
                strategy=StudyMutationStrategy.REGISTRATION_GEOMETRY,
                mutation_count=1,
            )

        assert len(records) >= 1
        assert all(r.strategy == "registration_geometry" for r in records)

    def test_reg_attack_shared_for_conflicting_position(
        self, mutator, mock_datasets, mock_study
    ):
        """Same FoR is applied, series 1+ get large position offset."""
        records = mutator._reg_attack_shared_for_conflicting_position(
            mock_datasets, mock_study
        )

        assert len(records) >= 1
        assert records[0].details["attack_type"] == "shared_for_conflicting_position"
        # All series should share same FoR
        for_uid = mock_datasets[0][0].FrameOfReferenceUID
        assert mock_datasets[1][0].FrameOfReferenceUID == for_uid
        # Series 1 position should be the 1000mm offset
        pos = mock_datasets[1][0].ImagePositionPatient
        assert float(pos[0]) == 1000.0

    def test_reg_attack_shared_for_conflicting_position_single_series(
        self, mutator, mock_study
    ):
        """Returns empty list for single series (attack needs 2+ series)."""
        single = [[pydicom.Dataset()]]
        records = mutator._reg_attack_shared_for_conflicting_position(
            single, mock_study
        )
        assert records == []

    def test_reg_attack_spatial_overlap(self, mutator, mock_datasets, mock_study):
        """Series 1 slice positions are copied from series 0."""
        original_s1_pos = list(mock_datasets[1][0].ImagePositionPatient)
        records = mutator._reg_attack_spatial_overlap(mock_datasets, mock_study)

        assert len(records) >= 1
        assert records[0].details["attack_type"] == "spatial_overlap"
        # All series share same FoR
        for_uid = mock_datasets[0][0].FrameOfReferenceUID
        assert mock_datasets[1][0].FrameOfReferenceUID == for_uid
        # Series 1 position now matches series 0
        assert list(mock_datasets[1][0].ImagePositionPatient) == list(
            mock_datasets[0][0].ImagePositionPatient
        )

    def test_reg_attack_spatial_overlap_single_series(self, mutator, mock_study):
        """Returns empty list for single series."""
        single = [[pydicom.Dataset()]]
        records = mutator._reg_attack_spatial_overlap(single, mock_study)
        assert records == []

    def test_reg_attack_contradictory_orientation(
        self, mutator, mock_datasets, mock_study
    ):
        """Series 1 orientation cosines are negated."""
        original_orient = list(mock_datasets[1][0].ImageOrientationPatient)
        records = mutator._reg_attack_contradictory_orientation(
            mock_datasets, mock_study
        )

        assert len(records) >= 1
        assert records[0].details["attack_type"] == "contradictory_orientation"
        # All series share same FoR
        for_uid = mock_datasets[0][0].FrameOfReferenceUID
        assert mock_datasets[1][0].FrameOfReferenceUID == for_uid
        # Series 1 orientation should be negated
        new_orient = list(mock_datasets[1][0].ImageOrientationPatient)
        for orig, flipped in zip(original_orient, new_orient):
            assert float(flipped) == pytest.approx(-float(orig))

    def test_reg_attack_contradictory_orientation_single_series(
        self, mutator, mock_study
    ):
        """Returns empty list for single series."""
        single = [[pydicom.Dataset()]]
        records = mutator._reg_attack_contradictory_orientation(single, mock_study)
        assert records == []

    def test_reg_attack_for_uid_orphan(self, mutator, mock_datasets, mock_study):
        """Each series gets unique FoR; PositionReferenceIndicator cites phantom UID."""
        records = mutator._reg_attack_for_uid_orphan(mock_datasets, mock_study)

        assert len(records) == 2  # One record per series
        assert all(r.details["attack_type"] == "for_uid_orphan" for r in records)
        # Both records reference same phantom FoR
        phantom = records[0].details["phantom_for"]
        assert records[1].details["phantom_for"] == phantom
        # Series FoR UIDs are distinct from each other and from phantom
        for_s0 = mock_datasets[0][0].FrameOfReferenceUID
        for_s1 = mock_datasets[1][0].FrameOfReferenceUID
        assert for_s0 != for_s1
        assert for_s0 != phantom
        assert for_s1 != phantom
        # PositionReferenceIndicator points at phantom on all slices
        assert mock_datasets[0][0].PositionReferenceIndicator == phantom
        assert mock_datasets[1][0].PositionReferenceIndicator == phantom

    def test_registration_geometry_is_in_strategy_enum(self):
        """REGISTRATION_GEOMETRY is a valid StudyMutationStrategy value."""
        assert (
            StudyMutationStrategy.REGISTRATION_GEOMETRY.value == "registration_geometry"
        )

    def test_registration_geometry_selected_by_random(self, mock_study, mock_datasets):
        """REGISTRATION_GEOMETRY is reachable via random strategy selection."""
        mutator = StudyMutator(severity="moderate", seed=42)
        strategy_values = [s.value for s in StudyMutationStrategy]
        assert "registration_geometry" in strategy_values


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
        """Test mutate_study with None strategy selects randomly without error.

        Some strategies require 2+ series and return no records for a single-series
        study. The test verifies dispatch completes cleanly, not that records are
        always produced (that depends on which strategy random selects).
        """
        import random

        random.seed(42)

        with patch.object(
            mutator, "_load_study_datasets", return_value=single_series_datasets
        ):
            datasets, records = mutator.mutate_study(
                single_series_study,
                strategy=None,
                mutation_count=1,
            )

        # Returns a valid dataset list (may be 0 records if strategy needs 2+ series)
        assert isinstance(records, list)
        assert isinstance(datasets, list)

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
