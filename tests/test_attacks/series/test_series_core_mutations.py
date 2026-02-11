"""Test Core Series Mutation Strategies.

This module tests the CoreMutationsMixin class that provides
the original five mutation strategies for series-level DICOM fuzzing.
"""

import random
from unittest.mock import MagicMock

import pytest
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.series.series_core_mutations import CoreMutationsMixin


class MockSeriesMutator(CoreMutationsMixin):
    """Mock class that uses the CoreMutationsMixin."""

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
    base_z = 0.0
    for i in range(5):
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()
        ds.SOPInstanceUID = generate_uid()
        ds.Modality = "CT"
        ds.Rows = 512
        ds.Columns = 512
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        ds.ImagePositionPatient = [0.0, 0.0, base_z + i * 5.0]
        ds.PixelSpacing = [1.0, 1.0]
        ds.SliceThickness = 5.0
        datasets.append(ds)
    return datasets


# --- Metadata Corruption Strategy Tests ---


class TestMetadataCorruption:
    """Test _mutate_metadata_corruption method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that metadata corruption produces mutation records."""
        result, records = mutator._mutate_metadata_corruption(
            sample_datasets, mock_series, mutation_count=5
        )

        assert result is not None
        assert len(records) >= 1
        assert all(r.strategy == "metadata_corruption" for r in records)

    def test_invalid_series_uid_handler(self, mutator, sample_datasets):
        """Test _corrupt_invalid_series_uid handler."""
        ds = sample_datasets[0]
        original_uid = ds.SeriesInstanceUID

        record = mutator._corrupt_invalid_series_uid(ds, 0)

        assert record.strategy == "metadata_corruption"
        assert record.tag == "SeriesInstanceUID"
        assert ds.SeriesInstanceUID != original_uid
        assert "FUZZED" in ds.SeriesInstanceUID
        assert record.details["corruption_type"] == "invalid_series_uid"

    def test_invalid_study_uid_handler(self, mutator, sample_datasets):
        """Test _corrupt_invalid_study_uid handler."""
        ds = sample_datasets[0]

        record = mutator._corrupt_invalid_study_uid(ds, 0)

        assert record.strategy == "metadata_corruption"
        assert record.tag == "StudyInstanceUID"
        assert "!@#$%INVALID_UID" in ds.StudyInstanceUID
        assert record.details["corruption_type"] == "invalid_study_uid"

    def test_missing_modality_handler(self, mutator, sample_datasets):
        """Test _corrupt_missing_modality handler."""
        ds = sample_datasets[0]
        assert hasattr(ds, "Modality")

        record = mutator._corrupt_missing_modality(ds, 0)

        assert record.strategy == "metadata_corruption"
        assert record.tag == "Modality"
        assert record.mutated_value == "<deleted>"
        assert not hasattr(ds, "Modality")

    def test_empty_series_uid_handler(self, mutator, sample_datasets):
        """Test _corrupt_empty_series_uid handler."""
        ds = sample_datasets[0]

        record = mutator._corrupt_empty_series_uid(ds, 0)

        assert ds.SeriesInstanceUID == ""
        assert record.details["corruption_type"] == "empty_series_uid"

    def test_extreme_uid_length_handler(self, mutator, sample_datasets):
        """Test _corrupt_extreme_uid_length handler."""
        ds = sample_datasets[0]

        record = mutator._corrupt_extreme_uid_length(ds, 0)

        assert len(ds.SeriesInstanceUID) > 50
        assert record.details["corruption_type"] == "extreme_uid_length"
        assert "length" in record.details

    def test_invalid_uid_chars_handler(self, mutator, sample_datasets):
        """Test _corrupt_invalid_uid_chars handler."""
        ds = sample_datasets[0]

        record = mutator._corrupt_invalid_uid_chars(ds, 0)

        assert "ABC" in ds.SeriesInstanceUID
        assert record.details["corruption_type"] == "uid_with_invalid_chars"

    def test_type_confusion_modality_handler(self, mutator, sample_datasets):
        """Test _corrupt_type_confusion_modality handler."""
        ds = sample_datasets[0]

        record = mutator._corrupt_type_confusion_modality(ds, 0)

        assert record.details["corruption_type"] == "type_confusion_modality"
        # Modality should be one of the invalid values

    def test_dataset_missing_attributes(self, mutator):
        """Test corruption on datasets missing expected attributes."""
        ds = Dataset()
        ds.PatientName = "Test"

        # Should handle missing SeriesInstanceUID gracefully
        record = mutator._corrupt_invalid_series_uid(ds, 0)
        assert record.original_value is None


# --- Slice Position Attack Strategy Tests ---


class TestSlicePositionAttack:
    """Test _mutate_slice_position_attack method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that slice position attack produces mutation records."""
        result, records = mutator._mutate_slice_position_attack(
            sample_datasets, mock_series, mutation_count=5
        )

        assert result is not None
        # May have fewer records if datasets lack ImagePositionPatient
        assert isinstance(records, list)

    def test_randomize_z_attack(self, mutator, sample_datasets):
        """Test _slice_pos_randomize_z helper."""
        ds = sample_datasets[0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_randomize_z(ds, 0, original, sample_datasets, records)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "randomize_z"
        assert ds.ImagePositionPatient[2] != original[2]

    def test_duplicate_position_attack(self, mutator, sample_datasets):
        """Test _slice_pos_duplicate helper."""
        ds = sample_datasets[0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_duplicate(ds, 0, original, sample_datasets, records)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "duplicate_position"

    def test_duplicate_position_single_dataset(self, mutator):
        """Test duplicate position with single dataset (edge case)."""
        ds = Dataset()
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_duplicate(ds, 0, original, [ds], records)

        # Should not produce record for single dataset
        assert len(records) == 0

    def test_extreme_nan_attack(self, mutator, sample_datasets):
        """Test _slice_pos_extreme with NaN."""
        import math

        ds = sample_datasets[0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_extreme(ds, 0, original, sample_datasets, records, "nan")

        assert len(records) == 1
        assert math.isnan(ds.ImagePositionPatient[2])
        assert records[0].details["attack_type"] == "extreme_value_nan"

    def test_extreme_inf_attack(self, mutator, sample_datasets):
        """Test _slice_pos_extreme with Infinity."""
        import math

        ds = sample_datasets[0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_extreme(ds, 0, original, sample_datasets, records, "inf")

        assert len(records) == 1
        assert math.isinf(ds.ImagePositionPatient[2])

    def test_extreme_large_attack(self, mutator, sample_datasets):
        """Test _slice_pos_extreme with large value."""
        ds = sample_datasets[0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_extreme(ds, 0, original, sample_datasets, records, "large")

        assert len(records) == 1
        assert abs(ds.ImagePositionPatient[2]) > 1e300

    def test_negative_position_attack(self, mutator, sample_datasets):
        """Test _slice_pos_negative helper."""
        ds = sample_datasets[2]  # Use middle slice with positive z
        ds.ImagePositionPatient = [10.0, 20.0, 30.0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_negative(ds, 2, original, sample_datasets, records)

        assert len(records) == 1
        assert all(x <= 0 for x in ds.ImagePositionPatient)
        assert records[0].details["attack_type"] == "negative_position"

    def test_zero_position_attack(self, mutator, sample_datasets):
        """Test _slice_pos_zero helper."""
        ds = sample_datasets[0]
        original = tuple(ds.ImagePositionPatient)
        records = []

        mutator._slice_pos_zero(ds, 0, original, sample_datasets, records)

        assert len(records) == 1
        assert ds.ImagePositionPatient == [0.0, 0.0, 0.0]
        assert records[0].details["attack_type"] == "zero_position"

    def test_missing_image_position(self, mutator, mock_series):
        """Test slice position attack on datasets without ImagePositionPatient."""
        datasets = [Dataset() for _ in range(5)]
        for ds in datasets:
            ds.PatientName = "Test"

        result, records = mutator._mutate_slice_position_attack(
            datasets, mock_series, mutation_count=5
        )

        # Should handle gracefully (no records)
        assert len(records) == 0


# --- Boundary Slice Targeting Strategy Tests ---


class TestBoundarySliceTargeting:
    """Test _mutate_boundary_slice_targeting method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that boundary targeting produces mutation records."""
        result, records = mutator._mutate_boundary_slice_targeting(
            sample_datasets, mock_series, mutation_count=3
        )

        assert result is not None
        assert len(records) >= 1
        assert all(r.strategy == "boundary_slice_targeting" for r in records)

    def test_first_slice_targeting(self, mutator, sample_datasets, mock_series):
        """Test first slice boundary targeting."""

        def mock_choice(x):
            if "first" in x:
                return "first"
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_boundary_slice_targeting(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].slice_index == 0
        assert records[0].details["boundary_type"] == "first"

    def test_last_slice_targeting(self, mutator, sample_datasets, mock_series):
        """Test last slice boundary targeting."""

        def mock_choice(x):
            if "last" in x:
                return "last"
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_boundary_slice_targeting(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].slice_index == len(sample_datasets) - 1
        assert records[0].details["boundary_type"] == "last"

    def test_middle_slice_targeting(self, mutator, sample_datasets, mock_series):
        """Test middle slice boundary targeting."""

        def mock_choice(x):
            if "middle" in x:
                return "middle"
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_boundary_slice_targeting(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].slice_index == len(sample_datasets) // 2
        assert records[0].details["boundary_type"] == "middle"

    def test_alternating_pattern(self, mutator, sample_datasets, mock_series):
        """Test alternating pattern boundary targeting."""

        def mock_choice(x):
            if "alternating" in x:
                return "alternating"
            if all(isinstance(i, int) for i in x):
                return 2  # Every 2nd slice
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_boundary_slice_targeting(
                sample_datasets, mock_series, mutation_count=1
            )

        # Should have multiple records for alternating pattern
        assert len(records) >= 1
        assert all(r.details["boundary_type"] == "alternating" for r in records)


# --- Gradient Mutation Strategy Tests ---


class TestGradientMutation:
    """Test _mutate_gradient_mutation method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that gradient mutation produces mutation records."""
        random.seed(42)
        result, records = mutator._mutate_gradient_mutation(
            sample_datasets, mock_series, mutation_count=1
        )

        assert result is not None
        assert isinstance(records, list)
        # May have 0 records if random chance doesn't trigger any

    def test_linear_gradient(self, mutator, sample_datasets, mock_series):
        """Test linear gradient type."""

        def mock_choice(x):
            if "linear" in x:
                return "linear"
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            # Force random to always pass intensity check
            m.setattr(random, "random", lambda: 0.0)
            result, records = mutator._mutate_gradient_mutation(
                sample_datasets, mock_series, mutation_count=1
            )

        if records:
            assert all(r.details["gradient_type"] == "linear" for r in records)

    def test_exponential_gradient(self, mutator, sample_datasets, mock_series):
        """Test exponential gradient type."""

        def mock_choice(x):
            if "exponential" in x:
                return "exponential"
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            m.setattr(random, "random", lambda: 0.0)
            result, records = mutator._mutate_gradient_mutation(
                sample_datasets, mock_series, mutation_count=1
            )

        if records:
            assert all(r.details["gradient_type"] == "exponential" for r in records)

    def test_sinusoidal_gradient(self, mutator, sample_datasets, mock_series):
        """Test sinusoidal gradient type."""

        def mock_choice(x):
            if "sinusoidal" in x:
                return "sinusoidal"
            return x[0]

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            m.setattr(random, "random", lambda: 0.0)
            result, records = mutator._mutate_gradient_mutation(
                sample_datasets, mock_series, mutation_count=1
            )

        if records:
            assert all(r.details["gradient_type"] == "sinusoidal" for r in records)

    def test_intensity_in_records(self, mutator, sample_datasets, mock_series):
        """Test that intensity values are recorded."""
        random.seed(42)

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "random", lambda: 0.0)  # Always pass intensity check
            result, records = mutator._mutate_gradient_mutation(
                sample_datasets, mock_series, mutation_count=1
            )

        if records:
            assert all("intensity" in r.details for r in records)
            assert all("corruption_amount" in r.details for r in records)


# --- Inconsistency Injection Strategy Tests ---


class TestInconsistencyInjection:
    """Test _mutate_inconsistency_injection method."""

    def test_produces_records(self, mutator, sample_datasets, mock_series):
        """Test that inconsistency injection produces mutation records."""
        result, records = mutator._mutate_inconsistency_injection(
            sample_datasets, mock_series, mutation_count=5
        )

        assert result is not None
        assert len(records) >= 1
        assert all(r.strategy == "inconsistency_injection" for r in records)

    def test_mixed_modality_attack(self, mutator, sample_datasets, mock_series):
        """Test mixed modality inconsistency."""

        def mock_choice(x):
            if "mixed_modality" in x:
                return "mixed_modality"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_inconsistency_injection(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].tag == "Modality"
        assert records[0].details["inconsistency_type"] == "mixed_modality"

    def test_conflicting_orientation_attack(
        self, mutator, sample_datasets, mock_series
    ):
        """Test conflicting orientation inconsistency."""

        def mock_choice(x):
            if "conflicting_orientation" in x:
                return "conflicting_orientation"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_inconsistency_injection(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].tag == "ImageOrientationPatient"
        assert records[0].details["inconsistency_type"] == "conflicting_orientation"

    def test_varying_pixel_spacing_attack(self, mutator, sample_datasets, mock_series):
        """Test varying pixel spacing inconsistency."""

        def mock_choice(x):
            if "varying_pixel_spacing" in x:
                return "varying_pixel_spacing"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_inconsistency_injection(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].tag == "PixelSpacing"
        assert records[0].details["inconsistency_type"] == "varying_pixel_spacing"

    def test_mismatched_dimensions_attack(self, mutator, sample_datasets, mock_series):
        """Test mismatched dimensions inconsistency."""

        def mock_choice(x):
            if "mismatched_dimensions" in x:
                return "mismatched_dimensions"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_inconsistency_injection(
                sample_datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].tag == "Rows/Columns"
        assert records[0].details["inconsistency_type"] == "mismatched_dimensions"


# --- Edge Cases and Severity Tests ---


class TestSeverityLevels:
    """Test that severity levels are correctly propagated."""

    def test_low_severity(self, sample_datasets, mock_series):
        """Test low severity level."""
        mutator = MockSeriesMutator(severity="low")
        result, records = mutator._mutate_metadata_corruption(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "low"

    def test_high_severity(self, sample_datasets, mock_series):
        """Test high severity level."""
        mutator = MockSeriesMutator(severity="high")
        result, records = mutator._mutate_metadata_corruption(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "high"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_datasets_list(self, mutator, mock_series):
        """Test handling of empty datasets list."""
        datasets = []

        result, records = mutator._mutate_metadata_corruption(
            datasets, mock_series, mutation_count=1
        )

        assert len(records) == 0

    def test_single_dataset(self, mutator, mock_series):
        """Test handling of single dataset."""
        ds = Dataset()
        ds.SeriesInstanceUID = generate_uid()
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        datasets = [ds]

        result, records = mutator._mutate_slice_position_attack(
            datasets, mock_series, mutation_count=1
        )

        assert result is not None

    def test_zero_mutation_count(self, mutator, sample_datasets, mock_series):
        """Test with zero mutation count."""
        result, records = mutator._mutate_metadata_corruption(
            sample_datasets, mock_series, mutation_count=0
        )

        assert len(records) == 0

    def test_large_mutation_count(self, mutator, sample_datasets, mock_series):
        """Test with large mutation count exceeding slice count."""
        result, records = mutator._mutate_metadata_corruption(
            sample_datasets, mock_series, mutation_count=100
        )

        # Should handle gracefully, limited by available slices for some operations
        assert result is not None
        assert isinstance(records, list)
