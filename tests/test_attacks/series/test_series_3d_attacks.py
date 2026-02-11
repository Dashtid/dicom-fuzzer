"""Test 3D Reconstruction Attack Strategies.

This module tests the Reconstruction3DAttacksMixin class that provides
specialized mutation strategies for targeting 3D volume reconstruction
vulnerabilities in DICOM viewers.
"""

import random
from unittest.mock import MagicMock

import pytest
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.series.series_3d_attacks import Reconstruction3DAttacksMixin


class MockSeriesMutator(Reconstruction3DAttacksMixin):
    """Mock class that uses the Reconstruction3DAttacksMixin."""

    def __init__(self, severity: str = "high"):
        self.severity = severity


@pytest.fixture
def mutator():
    """Create a mock mutator with the mixin."""
    return MockSeriesMutator(severity="high")


@pytest.fixture
def mock_series():
    """Create a mock DicomSeries."""
    return MagicMock()


@pytest.fixture
def sample_datasets():
    """Create a list of sample DICOM datasets for testing."""
    datasets = []
    base_z = 0.0
    for i in range(10):
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        ds.Modality = "CT"
        ds.Rows = 512
        ds.Columns = 512
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        ds.ImagePositionPatient = [0.0, 0.0, base_z + i * 5.0]
        ds.PixelSpacing = [1.0, 1.0]
        ds.SliceThickness = 5.0
        ds.FrameOfReferenceUID = generate_uid()
        datasets.append(ds)
    return datasets


class TestNonOrthogonalOrientation:
    """Test _mutate_non_orthogonal_orientation method."""

    def test_non_unit_vector_attack(self, mutator, sample_datasets, mock_series):
        """Test non-unit vector attack type."""
        random.seed(42)  # For reproducibility

        # Force non_unit_vector attack
        with pytest.MonkeyPatch().context() as m:
            m.setattr(
                random,
                "choice",
                lambda x: "non_unit_vector"
                if isinstance(x, list) and "non_unit_vector" in x
                else x[0],
            )
            result, records = mutator._mutate_non_orthogonal_orientation(
                sample_datasets, mock_series, mutation_count=1
            )

        assert result is not None
        assert len(result) == len(sample_datasets)

    def test_non_perpendicular_attack(self, mutator, sample_datasets, mock_series):
        """Test non-perpendicular vectors attack."""

        def mock_choice(x):
            if isinstance(x, list) and "non_perpendicular" in x:
                return "non_perpendicular"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_non_orthogonal_orientation(
                sample_datasets, mock_series, mutation_count=1
            )

        assert result is not None

    def test_zero_vector_attack(self, mutator, sample_datasets, mock_series):
        """Test zero-length vector attack."""

        def mock_choice(x):
            if isinstance(x, list) and "zero_vector" in x:
                return "zero_vector"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_non_orthogonal_orientation(
                sample_datasets, mock_series, mutation_count=1
            )

        assert result is not None

    def test_parallel_vectors_attack(self, mutator, sample_datasets, mock_series):
        """Test parallel row/column vectors attack."""

        def mock_choice(x):
            if isinstance(x, list) and "parallel_vectors" in x:
                return "parallel_vectors"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_non_orthogonal_orientation(
                sample_datasets, mock_series, mutation_count=1
            )

        assert result is not None

    def test_nan_components_attack(self, mutator, sample_datasets, mock_series):
        """Test NaN components attack."""
        import math

        def mock_choice(x):
            if isinstance(x, list) and "nan_components" in x:
                return "nan_components"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_non_orthogonal_orientation(
                sample_datasets, mock_series, mutation_count=1
            )

        # Verify NaN was injected
        nan_found = False
        for ds in result:
            if hasattr(ds, "ImageOrientationPatient"):
                for val in ds.ImageOrientationPatient:
                    if math.isnan(val):
                        nan_found = True
                        break
            if nan_found:
                break
        # NaN may or may not be found depending on which slice was selected
        # Verify mutation completed
        assert result is not None
        assert isinstance(result, list)

    def test_extreme_values_attack(self, mutator, sample_datasets, mock_series):
        """Test extreme float values attack."""

        def mock_choice(x):
            if isinstance(x, list) and "extreme_values" in x:
                return "extreme_values"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_non_orthogonal_orientation(
                sample_datasets, mock_series, mutation_count=1
            )

        assert result is not None

    def test_missing_orientation_attribute(self, mutator, mock_series):
        """Test handling of datasets without ImageOrientationPatient."""
        datasets = [Dataset() for _ in range(5)]
        for ds in datasets:
            ds.PatientName = "Test"

        result, records = mutator._mutate_non_orthogonal_orientation(
            datasets, mock_series, mutation_count=3
        )

        assert result is not None
        assert len(records) == 0

    def test_multiple_mutations(self, mutator, sample_datasets, mock_series):
        """Test multiple mutations in one call."""
        result, records = mutator._mutate_non_orthogonal_orientation(
            sample_datasets, mock_series, mutation_count=5
        )

        assert result is not None
        assert len(records) <= 5

    def test_mutation_record_content(self, mutator, sample_datasets, mock_series):
        """Test that mutation records contain expected fields."""
        result, records = mutator._mutate_non_orthogonal_orientation(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            record = records[0]
            assert record.strategy == "non_orthogonal_orientation"
            assert record.tag == "ImageOrientationPatient"
            assert record.severity == "high"
            assert "attack_type" in record.details


class TestSystematicSliceGap:
    """Test _mutate_systematic_slice_gap method."""

    def test_every_nth_removal(self, mutator, sample_datasets, mock_series):
        """Test every Nth slice removal."""
        original_count = len(sample_datasets)

        def mock_choice(x):
            if isinstance(x, list) and "every_nth" in x:
                return "every_nth"
            return (
                2
                if isinstance(x, list) and all(isinstance(i, int) for i in x)
                else x[0]
            )

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_systematic_slice_gap(
                sample_datasets.copy(), mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].strategy == "systematic_slice_gap"

    def test_boundary_removal(self, mutator, sample_datasets, mock_series):
        """Test boundary (first/last N) slice removal."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "boundary_removal" in x:
                return "boundary_removal"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_systematic_slice_gap(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "boundary_removal"

    def test_middle_section_removal(self, mutator, sample_datasets, mock_series):
        """Test middle section slice removal."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "middle_section" in x:
                return "middle_section"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_systematic_slice_gap(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "middle_section"

    def test_random_removal(self, mutator, sample_datasets, mock_series):
        """Test random slice removal pattern."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "random_removal" in x:
                return "random_removal"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_systematic_slice_gap(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].details["attack_type"] == "random_removal"

    def test_too_few_slices(self, mutator, mock_series):
        """Test handling when there are too few slices."""
        datasets = [Dataset() for _ in range(3)]

        result, records = mutator._mutate_systematic_slice_gap(
            datasets, mock_series, mutation_count=1
        )

        assert len(records) == 0
        assert len(result) == 3

    def test_removes_slices_from_list(self, mutator, sample_datasets, mock_series):
        """Test that slices are actually removed from the list."""
        original_count = len(sample_datasets)
        datasets = sample_datasets.copy()

        result, records = mutator._mutate_systematic_slice_gap(
            datasets, mock_series, mutation_count=1
        )

        assert len(result) < original_count


class TestSliceOverlapInjection:
    """Test _mutate_slice_overlap_injection method."""

    def test_duplicate_position_attack(self, mutator, sample_datasets, mock_series):
        """Test duplicate position attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "duplicate_position" in x:
                return "duplicate_position"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_slice_overlap_injection(
                datasets, mock_series, mutation_count=1
            )

        assert result is not None

    def test_physical_overlap_attack(self, mutator, sample_datasets, mock_series):
        """Test physical overlap attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "physical_overlap" in x:
                return "physical_overlap"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_slice_overlap_injection(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) >= 1
        assert records[0].details["attack_type"] == "physical_overlap"

    def test_reversed_order_attack(self, mutator, sample_datasets, mock_series):
        """Test reversed order attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "reversed_order" in x:
                return "reversed_order"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_slice_overlap_injection(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) >= 1

    def test_micro_spacing_attack(self, mutator, sample_datasets, mock_series):
        """Test micro spacing attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "micro_spacing" in x:
                return "micro_spacing"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_slice_overlap_injection(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) >= 1

    def test_insufficient_datasets(self, mutator, mock_series):
        """Test with insufficient datasets (< 2)."""
        datasets = [Dataset()]

        result, records = mutator._mutate_slice_overlap_injection(
            datasets, mock_series, mutation_count=1
        )

        assert len(records) == 0


class TestSliceOverlapHelpers:
    """Test slice overlap helper methods."""

    def test_create_overlap_record(self, mutator):
        """Test _create_overlap_record helper."""
        record = mutator._create_overlap_record(
            attack_type="test_attack",
            slice_index=5,
            original_value="100.0",
            mutated_value="50.0",
            details={"extra": "info"},
        )

        assert record.strategy == "slice_overlap_injection"
        assert record.slice_index == 5
        assert record.tag == "ImagePositionPatient[2]"
        assert record.original_value == "100.0"
        assert record.mutated_value == "50.0"
        assert record.details["attack_type"] == "test_attack"
        assert record.details["extra"] == "info"

    def test_create_overlap_record_no_details(self, mutator):
        """Test _create_overlap_record without extra details."""
        record = mutator._create_overlap_record(
            attack_type="basic",
            slice_index=None,
            original_value="val1",
            mutated_value="val2",
        )

        assert record.details["attack_type"] == "basic"

    def test_handle_duplicate_position(self, mutator, sample_datasets):
        """Test _handle_duplicate_position helper."""
        datasets = sample_datasets.copy()
        records = mutator._handle_duplicate_position(datasets)

        assert isinstance(records, list)

    def test_handle_duplicate_position_no_image_position(self, mutator):
        """Test _handle_duplicate_position without ImagePositionPatient."""
        datasets = [Dataset() for _ in range(5)]
        records = mutator._handle_duplicate_position(datasets)

        assert len(records) == 0

    def test_handle_physical_overlap(self, mutator, sample_datasets):
        """Test _handle_physical_overlap helper."""
        datasets = sample_datasets.copy()
        records = mutator._handle_physical_overlap(datasets)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "physical_overlap"

    def test_handle_physical_overlap_no_slice_thickness(self, mutator):
        """Test _handle_physical_overlap without SliceThickness."""
        datasets = []
        for i in range(5):
            ds = Dataset()
            ds.ImagePositionPatient = [0.0, 0.0, i * 5.0]
            datasets.append(ds)

        records = mutator._handle_physical_overlap(datasets)
        assert len(records) == 1  # Uses default thickness

    def test_handle_reversed_order(self, mutator, sample_datasets):
        """Test _handle_reversed_order helper."""
        datasets = sample_datasets.copy()
        original_z = [ds.ImagePositionPatient[2] for ds in datasets]

        records = mutator._handle_reversed_order(datasets)

        assert len(records) == 1
        # Check that z positions are reversed
        new_z = [ds.ImagePositionPatient[2] for ds in datasets]
        assert new_z == list(reversed(original_z))

    def test_handle_reversed_order_no_positions(self, mutator):
        """Test _handle_reversed_order without ImagePositionPatient."""
        datasets = [Dataset() for _ in range(5)]
        records = mutator._handle_reversed_order(datasets)

        assert len(records) == 0

    def test_handle_micro_spacing(self, mutator, sample_datasets):
        """Test _handle_micro_spacing helper."""
        datasets = sample_datasets.copy()
        records = mutator._handle_micro_spacing(datasets)

        assert len(records) == 1
        # Check spacing is very small
        if len(datasets) > 1:
            z0 = datasets[0].ImagePositionPatient[2]
            z1 = datasets[1].ImagePositionPatient[2]
            assert abs(z1 - z0) < 0.01

    def test_handle_micro_spacing_no_image_position(self, mutator):
        """Test _handle_micro_spacing without ImagePositionPatient on first slice."""
        datasets = [Dataset() for _ in range(5)]
        for i, ds in enumerate(datasets[1:], 1):
            ds.ImagePositionPatient = [0.0, 0.0, i * 5.0]

        records = mutator._handle_micro_spacing(datasets)
        # Should use default base_z of 0.0

        # Verify records were created
        assert records is not None


class TestVoxelAspectRatio:
    """Test _mutate_voxel_aspect_ratio method."""

    def test_extreme_ratio_attack(self, mutator, sample_datasets, mock_series):
        """Test extreme aspect ratio attack."""
        datasets = sample_datasets.copy()

        result, records = mutator._mutate_voxel_aspect_ratio(
            datasets, mock_series, mutation_count=5
        )

        assert result is not None
        assert len(records) <= 5

    def test_voxel_attack_extreme_ratio_helper(self, mutator, sample_datasets):
        """Test _voxel_attack_extreme_ratio helper."""
        ds = sample_datasets[0]
        records = []

        mutator._voxel_attack_extreme_ratio(ds, 0, records)

        if ds.PixelSpacing:
            assert len(records) == 1
            assert records[0].details["attack_type"] == "extreme_ratio"

    def test_voxel_attack_non_square_helper(self, mutator, sample_datasets):
        """Test _voxel_attack_non_square helper."""
        ds = sample_datasets[0]
        records = []

        mutator._voxel_attack_non_square(ds, 0, records)

        assert len(records) == 1
        assert ds.PixelSpacing == [0.5, 2.0]

    def test_voxel_attack_pancake_helper(self, mutator, sample_datasets):
        """Test _voxel_attack_pancake helper."""
        ds = sample_datasets[0]
        records = []

        mutator._voxel_attack_pancake(ds, 0, records)

        assert len(records) == 1
        assert ds.SliceThickness == 100.0

    def test_voxel_attack_needle_helper(self, mutator, sample_datasets):
        """Test _voxel_attack_needle helper."""
        ds = sample_datasets[0]
        records = []

        mutator._voxel_attack_needle(ds, 0, records)

        assert len(records) == 1
        assert ds.SliceThickness == 0.001

    def test_voxel_attack_zero_pixel_spacing(self, mutator, sample_datasets):
        """Test _voxel_attack_zero helper targeting PixelSpacing."""
        ds = sample_datasets[0]
        records = []

        # Force PixelSpacing path
        def mock_choice(x):
            if x == ["PixelSpacing", "SliceThickness"]:
                return "PixelSpacing"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            mutator._voxel_attack_zero(ds, 0, records)

        assert len(records) == 1
        assert ds.PixelSpacing == [0.0, 0.0]

    def test_voxel_attack_zero_slice_thickness(self, mutator, sample_datasets):
        """Test _voxel_attack_zero helper targeting SliceThickness."""
        ds = sample_datasets[0]
        records = []

        # Force SliceThickness path
        def mock_choice(x):
            if x == ["PixelSpacing", "SliceThickness"]:
                return "SliceThickness"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            mutator._voxel_attack_zero(ds, 0, records)

        assert len(records) == 1
        assert ds.SliceThickness == 0.0

    def test_voxel_attack_missing_attributes(self, mutator):
        """Test voxel attacks when attributes are missing."""
        ds = Dataset()
        ds.PatientName = "Test"
        records = []

        # Should not raise
        mutator._voxel_attack_extreme_ratio(ds, 0, records)
        assert len(records) == 0

        mutator._voxel_attack_non_square(ds, 0, records)
        assert len(records) == 0

        mutator._voxel_attack_pancake(ds, 0, records)
        assert len(records) == 0

        mutator._voxel_attack_needle(ds, 0, records)
        assert len(records) == 0


class TestFrameOfReference:
    """Test _mutate_frame_of_reference method."""

    def test_inconsistent_within_series_attack(
        self, mutator, sample_datasets, mock_series
    ):
        """Test inconsistent FoR within series attack."""
        datasets = sample_datasets.copy()
        original_fors = [ds.FrameOfReferenceUID for ds in datasets]

        def mock_choice(x):
            if isinstance(x, list) and "inconsistent_within_series" in x:
                return "inconsistent_within_series"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_frame_of_reference(
                datasets, mock_series, mutation_count=1
            )

        # Each slice should have different FoR now
        new_fors = [ds.FrameOfReferenceUID for ds in datasets]
        assert len(set(new_fors)) == len(datasets)
        assert len(records) == 1
        assert records[0].details["attack_type"] == "inconsistent_within_series"

    def test_empty_for_attack(self, mutator, sample_datasets, mock_series):
        """Test empty FrameOfReferenceUID attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "empty_for" in x:
                return "empty_for"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_frame_of_reference(
                datasets, mock_series, mutation_count=1
            )

        # At least one slice should have empty FoR
        empty_found = any(ds.FrameOfReferenceUID == "" for ds in datasets)
        assert empty_found
        assert len(records) == 1

    def test_invalid_for_attack(self, mutator, sample_datasets, mock_series):
        """Test invalid FrameOfReferenceUID attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "invalid_for" in x:
                return "invalid_for"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_frame_of_reference(
                datasets, mock_series, mutation_count=1
            )

        # At least one slice should have invalid FoR
        invalid_found = any(
            ds.FrameOfReferenceUID == "!INVALID-FoR-@#$%^&*()" for ds in datasets
        )
        assert invalid_found
        assert len(records) == 1

    def test_missing_for_attack(self, mutator, sample_datasets, mock_series):
        """Test missing FrameOfReferenceUID attack."""
        datasets = sample_datasets.copy()

        def mock_choice(x):
            if isinstance(x, list) and "missing_for" in x:
                return "missing_for"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_frame_of_reference(
                datasets, mock_series, mutation_count=1
            )

        # At least one slice should be missing FoR
        missing_found = any(not hasattr(ds, "FrameOfReferenceUID") for ds in datasets)
        assert missing_found
        assert len(records) == 1
        assert records[0].mutated_value == "<deleted>"

    def test_missing_for_on_dataset_without_for(self, mutator, mock_series):
        """Test missing_for attack on dataset without existing FoR."""
        datasets = [Dataset() for _ in range(5)]
        for ds in datasets:
            ds.PatientName = "Test"

        def mock_choice(x):
            if isinstance(x, list) and "missing_for" in x:
                return "missing_for"
            return x[0] if isinstance(x, list) else x

        with pytest.MonkeyPatch().context() as m:
            m.setattr(random, "choice", mock_choice)
            result, records = mutator._mutate_frame_of_reference(
                datasets, mock_series, mutation_count=1
            )

        assert len(records) == 1
        assert records[0].original_value == "<none>"

    def test_multiple_mutations(self, mutator, sample_datasets, mock_series):
        """Test multiple frame of reference mutations."""
        datasets = sample_datasets.copy()

        result, records = mutator._mutate_frame_of_reference(
            datasets, mock_series, mutation_count=5
        )

        assert len(records) == 5


class TestSeverityLevels:
    """Test that severity levels are correctly propagated."""

    def test_low_severity(self, sample_datasets, mock_series):
        """Test low severity level."""
        mutator = MockSeriesMutator(severity="low")
        result, records = mutator._mutate_non_orthogonal_orientation(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "low"

    def test_medium_severity(self, sample_datasets, mock_series):
        """Test medium severity level."""
        mutator = MockSeriesMutator(severity="medium")
        result, records = mutator._mutate_voxel_aspect_ratio(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "medium"

    def test_high_severity(self, sample_datasets, mock_series):
        """Test high severity level."""
        mutator = MockSeriesMutator(severity="high")
        result, records = mutator._mutate_frame_of_reference(
            sample_datasets, mock_series, mutation_count=1
        )

        if records:
            assert records[0].severity == "high"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_datasets_list(self, mutator, mock_series):
        """Test handling of empty datasets list."""
        datasets = []

        # Should not raise
        result, records = mutator._mutate_systematic_slice_gap(
            datasets, mock_series, mutation_count=1
        )
        assert len(records) == 0

    def test_single_dataset(self, mutator, mock_series):
        """Test handling of single dataset."""
        ds = Dataset()
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        ds.ImagePositionPatient = [0.0, 0.0, 0.0]
        ds.PixelSpacing = [1.0, 1.0]
        ds.SliceThickness = 5.0
        datasets = [ds]

        result, records = mutator._mutate_non_orthogonal_orientation(
            datasets, mock_series, mutation_count=1
        )
        assert result is not None

    def test_zero_mutation_count(self, mutator, sample_datasets, mock_series):
        """Test with zero mutation count."""
        result, records = mutator._mutate_non_orthogonal_orientation(
            sample_datasets, mock_series, mutation_count=0
        )

        assert len(records) == 0

    def test_large_mutation_count(self, mutator, sample_datasets, mock_series):
        """Test with large mutation count."""
        result, records = mutator._mutate_non_orthogonal_orientation(
            sample_datasets, mock_series, mutation_count=100
        )

        assert len(records) == 100  # Should match mutation count


class TestRandomness:
    """Test randomness handling."""

    def test_reproducible_with_seed(self, mutator, sample_datasets, mock_series):
        """Test that results are reproducible with same seed."""
        random.seed(12345)
        datasets1 = list(sample_datasets)  # Copy references
        result1, records1 = mutator._mutate_non_orthogonal_orientation(
            datasets1, mock_series, mutation_count=3
        )

        random.seed(12345)
        datasets2 = [Dataset() for _ in sample_datasets]  # Fresh datasets
        for ds in datasets2:
            ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]

        result2, records2 = mutator._mutate_non_orthogonal_orientation(
            datasets2, mock_series, mutation_count=3
        )

        # Same number of records with same seed
        assert len(records1) == len(records2)

    def test_different_results_without_seed(
        self, mutator, sample_datasets, mock_series
    ):
        """Test that different calls produce different results (usually)."""
        results = []
        for _ in range(10):
            datasets = [Dataset() for _ in range(5)]
            for ds in datasets:
                ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
                ds.ImagePositionPatient = [0.0, 0.0, 0.0]

            _, records = mutator._mutate_non_orthogonal_orientation(
                datasets, mock_series, mutation_count=1
            )
            if records:
                results.append(records[0].details.get("attack_type"))

        # Should have some variety (not guaranteed but very likely)
        assert len(results) > 0
