"""Test Temporal and Cross-Slice Attack Strategies.

This module tests the TemporalAttacksMixin class that provides
specialized mutation strategies for cross-slice references and
temporal ordering vulnerabilities.
"""

import random
from unittest.mock import MagicMock

import pytest
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.series.series_temporal_attacks import TemporalAttacksMixin


class MockSeriesMutator(TemporalAttacksMixin):
    """Mock class that uses the TemporalAttacksMixin."""

    def __init__(self, severity: str = "moderate"):
        self.severity = severity


@pytest.fixture
def mutator():
    """Create a mock mutator with the mixin."""
    return MockSeriesMutator(severity="moderate")


@pytest.fixture
def mock_series():
    """Create a mock DicomSeries."""
    return MagicMock()


@pytest.fixture
def sample_datasets():
    """Create a list of sample DICOM datasets for testing."""
    datasets = []
    for i in range(5):
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        ds.Modality = "CT"
        ds.InstanceNumber = i + 1
        ds.AcquisitionTime = f"10{i:02d}00.000000"
        ds.AcquisitionDate = "20231215"
        ds.AcquisitionDateTime = f"20231215{10 + i:02d}0000.000000"
        ds.ContentTime = f"10{i:02d}30.000000"
        datasets.append(ds)
    return datasets


# --- Cross-Slice Reference Strategy Tests ---


class TestCrossSliceReference:
    """Test _mutate_cross_slice_reference method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that cross-slice reference attack produces mutation records."""
        result, records = mutator._mutate_cross_slice_reference(
            sample_datasets, mock_series, mutation_count=5
        )

        assert result is not None
        assert len(records) >= 1
        assert all(r.strategy == "cross_slice_reference" for r in records)

    def test_reference_nonexistent_attack(self, mutator, sample_datasets, mock_series):
        """Test reference_nonexistent attack type."""

        def mock_choice(x):
            if isinstance(x, list) and "reference_nonexistent" in x:
                return "reference_nonexistent"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_cross_slice_reference(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "reference_nonexistent"
        assert "NONEXISTENT" in records[0].details["fake_uid"]

    def test_circular_reference_attack(self, mutator, sample_datasets, mock_series):
        """Test circular_reference attack type."""

        def mock_choice(x):
            if isinstance(x, list) and "circular_reference" in x:
                return "circular_reference"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_cross_slice_reference(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "circular_reference"
        assert "circular" in records[0].mutated_value

    def test_circular_reference_requires_min_datasets(self, mutator, mock_series):
        """Test circular reference with too few datasets."""
        datasets = [Dataset(), Dataset()]
        for ds in datasets:
            ds.SOPInstanceUID = generate_uid()

        record = mutator._handle_circular_reference(
            datasets, [ds.SOPInstanceUID for ds in datasets]
        )

        # Should return None when fewer than 3 datasets
        assert record is None

    def test_invalid_uid_format_attack(self, mutator, sample_datasets, mock_series):
        """Test invalid_uid_format attack type."""

        def mock_choice(x):
            if isinstance(x, list) and "invalid_uid_format" in x:
                return "invalid_uid_format"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_cross_slice_reference(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "invalid_uid_format"
        assert records[0].tag == "ReferencedSOPInstanceUID"

    def test_self_reference_attack(self, mutator, sample_datasets, mock_series):
        """Test self_reference attack type."""

        def mock_choice(x):
            if isinstance(x, list) and "self_reference" in x:
                return "self_reference"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_cross_slice_reference(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "self_reference"
        assert records[0].mutated_value == "<self_reference>"

    def test_duplicate_references_attack(self, mutator, sample_datasets, mock_series):
        """Test duplicate_references attack type."""

        def mock_choice(x):
            if isinstance(x, list) and "duplicate_references" in x:
                return "duplicate_references"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_cross_slice_reference(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "duplicate_references"
        assert "10x duplicate" in records[0].mutated_value

    def test_missing_reference_chain_attack(
        self, mutator, sample_datasets, mock_series
    ):
        """Test missing_reference_chain attack type."""

        def mock_choice(x):
            if isinstance(x, list) and "missing_reference_chain" in x:
                return "missing_reference_chain"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_cross_slice_reference(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "missing_reference_chain"
        assert "broken chain" in records[0].mutated_value

    def test_missing_reference_chain_requires_min_datasets(self, mutator, mock_series):
        """Test missing reference chain with single dataset."""
        datasets = [Dataset()]
        datasets[0].SOPInstanceUID = generate_uid()

        record = mutator._handle_missing_reference_chain(
            datasets, [datasets[0].SOPInstanceUID]
        )

        # Should return None when fewer than 2 datasets
        assert record is None


# --- Cross-Slice Reference Helper Tests ---


class TestCrossSliceHelpers:
    """Test cross-slice reference helper methods."""

    def test_create_ref_record(self, mutator):
        """Test _create_ref_record helper."""
        record = mutator._create_ref_record(
            attack_type="test_attack",
            slice_index=3,
            mutated_value="test value",
            tag="TestTag",
            details={"extra": "info"},
        )

        assert record.strategy == "cross_slice_reference"
        assert record.slice_index == 3
        assert record.tag == "TestTag"
        assert record.mutated_value == "test value"
        assert record.details["attack_type"] == "test_attack"
        assert record.details["extra"] == "info"

    def test_create_ref_record_default_tag(self, mutator):
        """Test _create_ref_record with default tag."""
        record = mutator._create_ref_record(
            attack_type="basic",
            slice_index=None,
            mutated_value="value",
        )

        assert record.tag == "ReferencedImageSequence"

    def test_add_reference(self, mutator):
        """Test _add_reference helper."""
        ds = Dataset()

        mutator._add_reference(ds, "1.2.3.4.5")

        assert hasattr(ds, "ReferencedImageSequence")
        assert len(ds.ReferencedImageSequence) == 1
        assert ds.ReferencedImageSequence[0].ReferencedSOPInstanceUID == "1.2.3.4.5"
        assert (
            ds.ReferencedImageSequence[0].ReferencedSOPClassUID
            == "1.2.840.10008.5.1.4.1.1.2"
        )

    def test_add_reference_custom_class_uid(self, mutator):
        """Test _add_reference with custom class UID."""
        ds = Dataset()

        mutator._add_reference(ds, "1.2.3.4.5", "1.2.3.custom")

        assert ds.ReferencedImageSequence[0].ReferencedSOPClassUID == "1.2.3.custom"

    def test_add_reference_appends(self, mutator):
        """Test _add_reference appends to existing sequence."""
        ds = Dataset()

        mutator._add_reference(ds, "1.2.3.first")
        mutator._add_reference(ds, "1.2.3.second")

        assert len(ds.ReferencedImageSequence) == 2


# --- Temporal Inconsistency Strategy Tests ---


class TestTemporalInconsistency:
    """Test _mutate_temporal_inconsistency method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that temporal inconsistency produces mutation records."""
        result, records = mutator._mutate_temporal_inconsistency(
            sample_datasets, mock_series, mutation_count=5
        )

        assert result is not None
        assert len(records) >= 1
        assert all(r.strategy == "temporal_inconsistency" for r in records)

    def test_randomize_attack(self, mutator, sample_datasets, mock_series):
        """Test randomize acquisition time attack."""

        def mock_choice(x):
            if isinstance(x, list) and "randomize" in x:
                return "randomize"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "randomize_acquisition_time"
        assert records[0].mutated_value == "<randomized>"

    def test_duplicate_attack(self, mutator, sample_datasets, mock_series):
        """Test duplicate timestamps attack."""

        def mock_choice(x):
            if isinstance(x, list) and "duplicate" in x:
                return "duplicate"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "duplicate_timestamps"
        # All datasets should have same time
        times = {ds.AcquisitionTime for ds in sample_datasets}
        assert len(times) == 1
        assert "120000" in times.pop()

    def test_extreme_past_date_attack(self, mutator, sample_datasets, mock_series):
        """Test extreme past date attack."""

        def mock_choice(x):
            if isinstance(x, list) and "past" in x:
                return "past"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "extreme_past_date"
        assert records[0].mutated_value == "19000101"
        # At least one dataset should have the extreme date
        assert any(ds.AcquisitionDate == "19000101" for ds in sample_datasets)

    def test_extreme_future_date_attack(self, mutator, sample_datasets, mock_series):
        """Test extreme future date attack."""

        def mock_choice(x):
            if isinstance(x, list) and "future" in x:
                return "future"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "extreme_future_date"
        assert records[0].mutated_value == "99991231"

    def test_invalid_time_format_attack(self, mutator, sample_datasets, mock_series):
        """Test invalid time format attack."""

        def mock_choice(x):
            if isinstance(x, list) and "invalid" in x:
                return "invalid"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "invalid_time_format"

    def test_temporal_order_reversal_attack(
        self, mutator, sample_datasets, mock_series
    ):
        """Test temporal order reversal attack."""

        def mock_choice(x):
            if isinstance(x, list) and "reversal" in x:
                return "reversal"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "temporal_order_reversal"
        # Times should be reversed relative to instance numbers
        times = [ds.AcquisitionTime for ds in sample_datasets]
        # Verify time values decrease as instance numbers increase
        assert times[0] > times[-1]

    def test_subsecond_conflicts_attack(self, mutator, sample_datasets, mock_series):
        """Test subsecond conflicts attack."""

        def mock_choice(x):
            if isinstance(x, list) and "subsecond" in x:
                return "subsecond"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "subsecond_conflicts"
        # All times should start with same HHMMSS
        times = [ds.AcquisitionTime[:6] for ds in sample_datasets]
        assert len(set(times)) == 1
        assert times[0] == "120000"


# --- Temporal Helper Tests ---


class TestTemporalHelpers:
    """Test temporal inconsistency helper methods."""

    def test_temporal_randomize(self, mutator, sample_datasets):
        """Test _temporal_randomize helper."""
        records = []
        original_times = [ds.AcquisitionTime for ds in sample_datasets]

        mutator._temporal_randomize(sample_datasets, records)

        assert len(records) == 1
        new_times = [ds.AcquisitionTime for ds in sample_datasets]
        # At least some times should change (very likely with randomization)
        assert new_times != original_times or len(sample_datasets) == 0

    def test_temporal_duplicate(self, mutator, sample_datasets):
        """Test _temporal_duplicate helper."""
        records = []

        mutator._temporal_duplicate(sample_datasets, records)

        assert len(records) == 1
        # All should have identical times
        times = {ds.AcquisitionTime for ds in sample_datasets}
        assert len(times) == 1

    def test_temporal_extreme_date_past(self, mutator, sample_datasets):
        """Test _temporal_extreme_date with past=True."""
        records = []

        mutator._temporal_extreme_date(sample_datasets, records, past=True)

        assert len(records) == 1
        assert any(ds.AcquisitionDate == "19000101" for ds in sample_datasets)

    def test_temporal_extreme_date_future(self, mutator, sample_datasets):
        """Test _temporal_extreme_date with past=False."""
        records = []

        mutator._temporal_extreme_date(sample_datasets, records, past=False)

        assert len(records) == 1
        assert any(ds.AcquisitionDate == "99991231" for ds in sample_datasets)

    def test_temporal_invalid_format(self, mutator, sample_datasets):
        """Test _temporal_invalid_format helper."""
        records = []

        mutator._temporal_invalid_format(sample_datasets, records)

        assert len(records) == 1

    def test_temporal_reversal(self, mutator, sample_datasets):
        """Test _temporal_reversal helper."""
        records = []

        mutator._temporal_reversal(sample_datasets, records)

        assert len(records) == 1
        # Check instance numbers are ascending
        instances = [ds.InstanceNumber for ds in sample_datasets]
        assert instances == sorted(instances)
        # Check times are descending
        times = [ds.AcquisitionTime for ds in sample_datasets]
        assert times == sorted(times, reverse=True)

    def test_temporal_subsecond(self, mutator, sample_datasets):
        """Test _temporal_subsecond helper."""
        records = []

        mutator._temporal_subsecond(sample_datasets, records)

        assert len(records) == 1
        # All times should differ only in microseconds
        base_times = {ds.AcquisitionTime[:6] for ds in sample_datasets}
        assert base_times == {"120000"}


# --- Severity and Edge Case Tests ---


class TestSeverityLevels:
    """Test that severity levels are correctly propagated."""

    def test_low_severity(self, sample_datasets, mock_series):
        """Test low severity level."""
        mutator = MockSeriesMutator(severity="low")
        result, records = mutator._mutate_cross_slice_reference(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "low"

    def test_high_severity(self, sample_datasets, mock_series):
        """Test high severity level."""
        mutator = MockSeriesMutator(severity="high")
        result, records = mutator._mutate_temporal_inconsistency(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "high"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_datasets_cross_ref(self, mutator, mock_series):
        """Test cross-slice reference with empty datasets."""
        datasets = []

        result, records = mutator._mutate_cross_slice_reference(
            datasets, mock_series, mutation_count=1
        )

        # Should handle gracefully
        assert result == []

    def test_empty_datasets_temporal(self, mutator, mock_series):
        """Test temporal inconsistency with empty datasets.

        Note: Some attack types (extreme_date) don't handle empty datasets.
        This tests that non-failing attacks work on empty lists.
        """
        datasets = []

        # Test with attacks that handle empty datasets
        def mock_choice(x):
            if isinstance(x, list) and "randomize" in x:
                return "randomize"  # Handles empty datasets gracefully
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_temporal_inconsistency(
                datasets, mock_series, mutation_count=1
            )

        # Should handle gracefully for attacks that iterate over datasets
        assert result == []

    def test_single_dataset_cross_ref(self, mutator, mock_series):
        """Test cross-slice reference with single dataset."""
        ds = Dataset()
        ds.SOPInstanceUID = generate_uid()
        datasets = [ds]

        result, records = mutator._mutate_cross_slice_reference(
            datasets, mock_series, mutation_count=3
        )

        # Should produce some records even with single dataset
        assert result is not None

    def test_datasets_without_sop_uid(self, mutator, mock_series):
        """Test cross-slice reference with datasets missing SOPInstanceUID."""
        datasets = [Dataset() for _ in range(3)]
        for ds in datasets:
            ds.PatientName = "Test"

        result, records = mutator._mutate_cross_slice_reference(
            datasets, mock_series, mutation_count=3
        )

        # Should handle gracefully (existing_uids will be empty)
        assert result is not None

    def test_zero_mutation_count(self, mutator, sample_datasets, mock_series):
        """Test with zero mutation count."""
        result, records = mutator._mutate_temporal_inconsistency(
            sample_datasets, mock_series, mutation_count=0
        )

        assert len(records) == 0

    def test_large_mutation_count(self, mutator, sample_datasets, mock_series):
        """Test with large mutation count."""
        result, records = mutator._mutate_cross_slice_reference(
            sample_datasets, mock_series, mutation_count=100
        )

        # Should produce many records
        assert len(records) >= 50  # Most attacks should succeed


class TestRandomness:
    """Test randomness handling."""

    def test_reproducible_with_seed(self, mutator, sample_datasets, mock_series):
        """Test that results are reproducible with same seed."""
        random.seed(12345)
        datasets1 = [Dataset() for _ in sample_datasets]
        for ds in datasets1:
            ds.SOPInstanceUID = generate_uid()
            ds.AcquisitionTime = "100000.000000"

        result1, records1 = mutator._mutate_temporal_inconsistency(
            datasets1, mock_series, mutation_count=3
        )

        random.seed(12345)
        datasets2 = [Dataset() for _ in sample_datasets]
        for ds in datasets2:
            ds.SOPInstanceUID = generate_uid()
            ds.AcquisitionTime = "100000.000000"

        result2, records2 = mutator._mutate_temporal_inconsistency(
            datasets2, mock_series, mutation_count=3
        )

        # Same number of records with same seed
        assert len(records1) == len(records2)
