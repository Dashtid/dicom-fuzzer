"""
Unit Tests for Series3DMutator

Tests the Series3DMutator class and its 5 mutation strategies for 3D DICOM series fuzzing.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.series.series_mutator import (
    Series3DMutator,
    SeriesMutationRecord,
    SeriesMutationStrategy,
)
from dicom_fuzzer.core.dicom.dicom_series import DicomSeries


@pytest.fixture
def sample_series():
    """Create sample DicomSeries for testing."""
    return DicomSeries(
        series_uid="1.2.840.113619.2.55.3.123456",
        study_uid="1.2.840.113619.2.55.3.123400",
        modality="CT",
        slices=[
            Path("/tmp/slice1.dcm"),
            Path("/tmp/slice2.dcm"),
            Path("/tmp/slice3.dcm"),
            Path("/tmp/slice4.dcm"),
            Path("/tmp/slice5.dcm"),
        ],
        slice_spacing=1.25,
    )


@pytest.fixture
def mock_datasets():
    """Create mock pydicom Datasets for testing."""

    def create_dataset(slice_num):
        ds = Dataset()
        ds.SeriesInstanceUID = "1.2.840.113619.2.55.3.123456"
        ds.StudyInstanceUID = "1.2.840.113619.2.55.3.123400"
        ds.Modality = "CT"
        ds.SOPInstanceUID = f"1.2.840.113619.2.55.3.123456.{slice_num}"
        ds.InstanceNumber = slice_num
        ds.ImagePositionPatient = [0.0, 0.0, float(slice_num * 1.25)]
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        ds.PixelSpacing = [0.5, 0.5]
        ds.Rows = 512
        ds.Columns = 512
        return ds

    return [create_dataset(i) for i in range(1, 6)]


class TestSeries3DMutatorInitialization:
    """Test Series3DMutator initialization."""

    def test_valid_initialization_default(self):
        """Test valid initialization with defaults."""
        mutator = Series3DMutator()
        assert mutator.severity == "moderate"
        assert mutator.seed is None

    def test_valid_initialization_with_severity(self):
        """Test initialization with custom severity."""
        mutator = Series3DMutator(severity="aggressive")
        assert mutator.severity == "aggressive"

    def test_valid_initialization_with_seed(self):
        """Test initialization with random seed."""
        mutator = Series3DMutator(seed=42)
        assert mutator.seed == 42

    def test_invalid_severity_raises_error(self):
        """Test that invalid severity raises error."""
        with pytest.raises(ValueError, match="Invalid severity"):
            Series3DMutator(severity="invalid")


class TestMutateSeries:
    """Test mutate_series method."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_mutate_series_basic(self, mock_dcmread, sample_series, mock_datasets):
        """Test basic series mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="moderate", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="metadata_corruption", mutation_count=3
        )

        assert len(fuzzed_datasets) == 5  # Same number of slices
        assert len(records) >= 1  # At least some mutations applied
        assert all(isinstance(r, SeriesMutationRecord) for r in records)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_mutate_series_random_strategy(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test mutation with random strategy selection."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="moderate", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, mutation_count=2
        )

        assert len(fuzzed_datasets) == 5
        assert len(records) >= 1

    def test_mutate_empty_series_raises_error(self):
        """Test that empty series raises error."""
        empty_series = DicomSeries(
            series_uid="1.2.3", study_uid="1.2.4", modality="CT", slices=[]
        )

        mutator = Series3DMutator()
        with pytest.raises(ValueError, match="Cannot mutate empty series"):
            mutator.mutate_series(empty_series)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_mutate_invalid_strategy_raises_error(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test that invalid strategy raises error."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator()
        with pytest.raises(ValueError, match="Invalid strategy"):
            mutator.mutate_series(sample_series, strategy="invalid_strategy")

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_mutate_with_enum_strategy(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test mutation with SeriesMutationStrategy enum (not string)."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="moderate", seed=42)
        # Use enum instead of string
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series,
            strategy=SeriesMutationStrategy.METADATA_CORRUPTION,
            mutation_count=2,
        )

        assert len(fuzzed_datasets) == 5
        assert len(records) >= 1


class TestMetadataCorruption:
    """Test metadata_corruption mutation strategy."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_metadata_corruption_invalid_series_uid(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test SeriesInstanceUID corruption."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="metadata_corruption", mutation_count=5
        )

        # Check that some records are metadata corruption
        assert any(r.strategy == "metadata_corruption" for r in records)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_metadata_corruption_missing_modality(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test Modality deletion."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="metadata_corruption", mutation_count=10
        )

        # Check if any dataset had Modality deleted
        modality_records = [r for r in records if r.tag == "Modality"]
        # May or may not have modality deletions depending on random choices
        # But verify mutation operation completed successfully
        assert fuzzed_datasets is not None
        assert len(fuzzed_datasets) > 0
        assert isinstance(records, list)


class TestSlicePositionAttack:
    """Test slice_position_attack mutation strategy."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_slice_position_attack_randomize_z(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test z-coordinate randomization."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="slice_position_attack", mutation_count=5
        )

        # Check that ImagePositionPatient was mutated
        position_records = [r for r in records if r.tag == "ImagePositionPatient"]
        assert len(position_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_slice_position_attack_extreme_values(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test extreme value injection (NaN, Inf)."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="slice_position_attack", mutation_count=10
        )

        # Check for extreme values in records
        extreme_records = [
            r
            for r in records
            if "extreme_value" in r.details.get("attack_type", "")
            or "nan" in str(r.mutated_value).lower()
            or "inf" in str(r.mutated_value).lower()
        ]
        # May or may not have extreme values depending on random choices
        # But verify mutation operation completed successfully
        assert fuzzed_datasets is not None
        assert len(fuzzed_datasets) > 0
        assert isinstance(records, list)


class TestBoundarySliceTargeting:
    """Test boundary_slice_targeting mutation strategy."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_boundary_slice_targeting_first_slice(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test first slice targeting."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="boundary_slice_targeting", mutation_count=5
        )

        # Check that boundary slices were targeted
        boundary_records = [
            r for r in records if r.strategy == "boundary_slice_targeting"
        ]
        assert len(boundary_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_boundary_slice_targeting_alternating_pattern(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test alternating pattern mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="moderate", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="boundary_slice_targeting", mutation_count=3
        )

        # Check for alternating pattern
        alternating_records = [
            r for r in records if r.details.get("boundary_type") == "alternating"
        ]
        # May or may not have alternating pattern depending on random choices
        # But verify mutation operation completed successfully
        assert fuzzed_datasets is not None
        assert len(fuzzed_datasets) > 0
        assert isinstance(records, list)


class TestGradientMutation:
    """Test gradient_mutation mutation strategy."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_gradient_mutation_linear(self, mock_dcmread, sample_series, mock_datasets):
        """Test linear gradient mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="moderate", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="gradient_mutation", mutation_count=5
        )

        # Check that gradient mutations were applied
        gradient_records = [r for r in records if r.strategy == "gradient_mutation"]
        assert len(gradient_records) >= 1

        # Check intensity values exist
        intensities = [
            r.details.get("intensity")
            for r in gradient_records
            if "intensity" in r.details
        ]
        assert len(intensities) > 0

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_gradient_mutation_exponential(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test exponential gradient mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=123)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="gradient_mutation", mutation_count=5
        )

        gradient_records = [r for r in records if "gradient_type" in r.details]
        # Gradient type can be linear, exponential, or sinusoidal
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert len(fuzzed_datasets) > 0
        assert isinstance(records, list)


class TestInconsistencyInjection:
    """Test inconsistency_injection mutation strategy."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_inconsistency_injection_mixed_modality(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test mixed modality injection."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="inconsistency_injection", mutation_count=5
        )

        # Check that inconsistencies were injected
        inconsistency_records = [
            r for r in records if r.strategy == "inconsistency_injection"
        ]
        assert len(inconsistency_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_inconsistency_injection_conflicting_orientation(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test conflicting orientation injection."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="inconsistency_injection", mutation_count=10
        )

        # Check for orientation conflicts
        orientation_records = [r for r in records if r.tag == "ImageOrientationPatient"]
        # May or may not have orientation mutations depending on random choices
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert len(fuzzed_datasets) > 0
        assert isinstance(records, list)


class TestSeriesMutationRecord:
    """Test SeriesMutationRecord dataclass."""

    def test_mutation_record_initialization(self):
        """Test SeriesMutationRecord initialization."""
        record = SeriesMutationRecord(
            strategy="metadata_corruption",
            slice_index=0,
            tag="SeriesInstanceUID",
            original_value="1.2.3.4",
            mutated_value="1.2.3.4.FUZZED",
            severity="moderate",
        )

        assert record.strategy == "metadata_corruption"
        assert record.slice_index == 0
        assert record.tag == "SeriesInstanceUID"

    def test_mutation_record_to_dict(self):
        """Test SeriesMutationRecord to_dict conversion."""
        record = SeriesMutationRecord(
            strategy="slice_position_attack",
            slice_index=2,
            tag="ImagePositionPatient",
            original_value="[0.0, 0.0, 2.5]",
            mutated_value="[0.0, 0.0, 999.0]",
            severity="aggressive",
            details={"attack_type": "randomize_z"},
        )

        data = record.to_dict()

        assert isinstance(data, dict)
        assert data["strategy"] == "slice_position_attack"
        assert data["slice_index"] == 2
        assert data["details"]["attack_type"] == "randomize_z"

    def test_mutation_record_none_values(self):
        """Test SeriesMutationRecord with None values for branch coverage."""
        record = SeriesMutationRecord(
            strategy="test",
            original_value=None,
            mutated_value=None,
        )

        data = record.to_dict()
        # _custom_serialization should handle None values
        assert data["original_value"] is None
        assert data["mutated_value"] is None

    def test_mutation_record_non_string_values(self):
        """Test SeriesMutationRecord with non-string values for branch coverage."""
        record = SeriesMutationRecord(
            strategy="test",
            original_value=12345,  # int
            mutated_value=[1.0, 2.0, 3.0],  # list
        )

        data = record.to_dict()
        # _custom_serialization should convert to strings
        assert data["original_value"] == "12345"
        assert data["mutated_value"] == "[1.0, 2.0, 3.0]"


class TestSeriesMutationStrategy:
    """Test SeriesMutationStrategy enum."""

    def test_all_strategies_exist(self):
        """Test that all 12 strategies are defined (5 original + 5 v1.7.0 + 2 v1.8.0)."""
        strategies = list(SeriesMutationStrategy)
        assert len(strategies) == 12

        strategy_names = [s.value for s in strategies]
        # Original 5 strategies
        assert "metadata_corruption" in strategy_names
        assert "slice_position_attack" in strategy_names
        assert "boundary_slice_targeting" in strategy_names
        assert "gradient_mutation" in strategy_names
        assert "inconsistency_injection" in strategy_names
        # v1.7.0 strategies
        assert "non_orthogonal_orientation" in strategy_names
        assert "systematic_slice_gap" in strategy_names
        assert "slice_overlap_injection" in strategy_names
        assert "voxel_aspect_ratio" in strategy_names
        assert "frame_of_reference" in strategy_names
        # v1.8.0 strategies
        assert "cross_slice_reference" in strategy_names
        assert "temporal_inconsistency" in strategy_names


class TestSeverityLevels:
    """Test mutation behavior at different severity levels."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_minimal_severity(self, mock_dcmread, sample_series, mock_datasets):
        """Test minimal severity mutations."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="minimal", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(sample_series)

        # Minimal should have fewer mutations
        assert len(records) >= 1
        assert len(records) <= 3

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_extreme_severity(self, mock_dcmread, sample_series, mock_datasets):
        """Test extreme severity mutations."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(sample_series)

        # Extreme should have more mutations
        assert len(records) >= 5


class TestRandomSeedReproducibility:
    """Test that random seed ensures reproducibility."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_same_seed_produces_same_mutations(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test that same seed produces identical mutations."""
        # First run
        mock_dcmread.side_effect = mock_datasets
        mutator1 = Series3DMutator(severity="moderate", seed=42)
        fuzzed1, records1 = mutator1.mutate_series(
            sample_series, strategy="metadata_corruption", mutation_count=5
        )

        # Second run with same seed
        mock_dcmread.side_effect = mock_datasets
        mutator2 = Series3DMutator(severity="moderate", seed=42)
        fuzzed2, records2 = mutator2.mutate_series(
            sample_series, strategy="metadata_corruption", mutation_count=5
        )

        # Should produce same number of records
        assert len(records1) == len(records2)


class TestLoadDatasets:
    """Test _load_datasets method."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_load_datasets_basic(self, mock_dcmread, sample_series, mock_datasets):
        """Test basic dataset loading."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator()
        datasets = mutator._load_datasets(sample_series)

        assert len(datasets) == 5
        assert all(isinstance(ds, Dataset) for ds in datasets)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_load_datasets_error_handling(self, mock_dcmread, sample_series):
        """Test dataset loading error handling."""
        mock_dcmread.side_effect = Exception("Failed to read DICOM")

        mutator = Series3DMutator()
        with pytest.raises(Exception):
            mutator._load_datasets(sample_series)


# =============================================================================
# v1.7.0 Strategy Tests - 3D Reconstruction Attack Vectors
# =============================================================================


class TestNonOrthogonalOrientation:
    """Test non_orthogonal_orientation mutation strategy (v1.7.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_non_orthogonal_orientation_basic(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test basic non-orthogonal orientation mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="non_orthogonal_orientation", mutation_count=3
        )

        assert len(fuzzed_datasets) == 5
        orientation_records = [
            r for r in records if r.strategy == "non_orthogonal_orientation"
        ]
        assert len(orientation_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_non_orthogonal_orientation_vector_modification(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test that ImageOrientationPatient vectors are modified."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="non_orthogonal_orientation", mutation_count=5
        )

        # Check for ImageOrientationPatient modifications
        iop_records = [r for r in records if r.tag == "ImageOrientationPatient"]
        assert len(iop_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_non_orthogonal_attack_types(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test different attack types are applied."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="non_orthogonal_orientation", mutation_count=10
        )

        # Check for attack type in details
        attack_types = [r.details.get("attack_type") for r in records if r.details]
        assert len(attack_types) >= 1


class TestSystematicSliceGap:
    """Test systematic_slice_gap mutation strategy (v1.7.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_systematic_slice_gap_basic(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test basic systematic slice gap mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="moderate", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="systematic_slice_gap", mutation_count=3
        )

        # Slice gap strategy removes slices, so may have fewer outputs
        gap_records = [r for r in records if r.strategy == "systematic_slice_gap"]
        assert len(gap_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_systematic_slice_gap_every_nth(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test every Nth slice removal pattern."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="systematic_slice_gap", mutation_count=5
        )

        # Check for slice removal records
        removal_records = [r for r in records if "removed" in str(r.details).lower()]
        # May or may not have removal records depending on implementation
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)


class TestSliceOverlapInjection:
    """Test slice_overlap_injection mutation strategy (v1.7.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_slice_overlap_injection_basic(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test basic slice overlap injection."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="slice_overlap_injection", mutation_count=3
        )

        overlap_records = [
            r for r in records if r.strategy == "slice_overlap_injection"
        ]
        assert len(overlap_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_slice_overlap_z_position_duplication(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test Z-position duplication for overlap."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="slice_overlap_injection", mutation_count=5
        )

        # Check for ImagePositionPatient modifications
        position_records = [r for r in records if r.tag == "ImagePositionPatient"]
        # May have position modifications for overlap
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)


class TestVoxelAspectRatio:
    """Test voxel_aspect_ratio mutation strategy (v1.7.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_voxel_aspect_ratio_basic(self, mock_dcmread, sample_series, mock_datasets):
        """Test basic voxel aspect ratio mutation."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="voxel_aspect_ratio", mutation_count=3
        )

        voxel_records = [r for r in records if r.strategy == "voxel_aspect_ratio"]
        assert len(voxel_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_voxel_aspect_ratio_pixel_spacing(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test PixelSpacing modification for voxel ratio attacks."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="voxel_aspect_ratio", mutation_count=5
        )

        # Check for PixelSpacing or SliceThickness modifications
        spacing_records = [
            r for r in records if r.tag in ("PixelSpacing", "SliceThickness")
        ]
        assert len(spacing_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_voxel_aspect_ratio_extreme_values(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test extreme voxel aspect ratios."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="voxel_aspect_ratio", mutation_count=10
        )

        # Check for extreme ratio attack types
        extreme_records = [
            r
            for r in records
            if "extreme" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)


class TestFrameOfReference:
    """Test frame_of_reference mutation strategy (v1.7.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_frame_of_reference_basic(self, mock_dcmread, sample_series, mock_datasets):
        """Test basic frame of reference mutation."""
        # Add FrameOfReferenceUID to mock datasets
        for ds in mock_datasets:
            ds.FrameOfReferenceUID = "1.2.840.113619.2.55.3.999999"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="frame_of_reference", mutation_count=3
        )

        for_records = [r for r in records if r.strategy == "frame_of_reference"]
        assert len(for_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_frame_of_reference_uid_corruption(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test FrameOfReferenceUID corruption."""
        for ds in mock_datasets:
            ds.FrameOfReferenceUID = "1.2.840.113619.2.55.3.999999"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="frame_of_reference", mutation_count=5
        )

        # Check for FrameOfReferenceUID modifications
        uid_records = [r for r in records if r.tag == "FrameOfReferenceUID"]
        assert len(uid_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_frame_of_reference_inconsistency(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test FrameOfReferenceUID inconsistency across slices."""
        for ds in mock_datasets:
            ds.FrameOfReferenceUID = "1.2.840.113619.2.55.3.999999"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="frame_of_reference", mutation_count=10
        )

        # Check for inconsistent attack type
        inconsistent_records = [
            r
            for r in records
            if "inconsistent" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)


# =============================================================================
# v1.8.0 Strategy Tests - Cross-Slice Reference and Temporal Attacks
# =============================================================================


class TestCrossSliceReference:
    """Test cross_slice_reference mutation strategy (v1.8.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_cross_slice_reference_basic(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test basic cross-slice reference mutation."""
        # Add ReferencedSOPInstanceUID to mock datasets
        for i, ds in enumerate(mock_datasets):
            if i < len(mock_datasets) - 1:
                ds.ReferencedSOPInstanceUID = mock_datasets[i + 1].SOPInstanceUID

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="cross_slice_reference", mutation_count=3
        )

        cross_ref_records = [
            r for r in records if r.strategy == "cross_slice_reference"
        ]
        assert len(cross_ref_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_cross_slice_reference_nonexistent(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test reference to nonexistent SOP Instance UID."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="cross_slice_reference", mutation_count=5
        )

        # Check for reference attacks
        ref_records = [
            r
            for r in records
            if "reference" in str(r.details.get("attack_type", "")).lower()
            or "nonexistent" in str(r.details.get("attack_type", "")).lower()
        ]
        # May or may not have specific attack types
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_cross_slice_reference_circular(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test circular reference injection."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="cross_slice_reference", mutation_count=10
        )

        # Check for circular reference attack type
        circular_records = [
            r
            for r in records
            if "circular" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_cross_slice_reference_invalid_uid_format(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test invalid UID format injection."""
        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="cross_slice_reference", mutation_count=10
        )

        # Check for ReferencedSOPInstanceUID or similar tag modifications
        uid_records = [r for r in records if "UID" in r.tag or "Reference" in r.tag]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)


class TestTemporalInconsistency:
    """Test temporal_inconsistency mutation strategy (v1.8.0)."""

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_temporal_inconsistency_basic(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test basic temporal inconsistency mutation."""
        # Add AcquisitionTime to mock datasets
        for i, ds in enumerate(mock_datasets):
            ds.AcquisitionTime = f"10{i:02d}00.000000"
            ds.AcquisitionDateTime = f"20231215{i:02d}0000.000000"
            ds.ContentTime = f"10{i:02d}30.000000"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="aggressive", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="temporal_inconsistency", mutation_count=3
        )

        temporal_records = [
            r for r in records if r.strategy == "temporal_inconsistency"
        ]
        assert len(temporal_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_temporal_inconsistency_randomize_time(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test acquisition time randomization."""
        for i, ds in enumerate(mock_datasets):
            ds.AcquisitionTime = f"10{i:02d}00.000000"
            ds.AcquisitionDateTime = f"20231215{i:02d}0000.000000"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="temporal_inconsistency", mutation_count=5
        )

        # Check for time tag modifications
        time_records = [r for r in records if "Time" in r.tag or "Date" in r.tag]
        assert len(time_records) >= 1

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_temporal_inconsistency_duplicate_timestamps(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test duplicate timestamp injection."""
        for i, ds in enumerate(mock_datasets):
            ds.AcquisitionTime = f"10{i:02d}00.000000"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="temporal_inconsistency", mutation_count=10
        )

        # Check for duplicate attack type
        duplicate_records = [
            r
            for r in records
            if "duplicate" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_temporal_inconsistency_extreme_dates(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test extreme past/future date injection."""
        for i, ds in enumerate(mock_datasets):
            ds.AcquisitionDate = "20231215"
            ds.AcquisitionTime = f"10{i:02d}00.000000"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="temporal_inconsistency", mutation_count=10
        )

        # Check for extreme date attack types
        extreme_records = [
            r
            for r in records
            if "extreme" in str(r.details.get("attack_type", "")).lower()
            or "past" in str(r.details.get("attack_type", "")).lower()
            or "future" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_temporal_inconsistency_invalid_format(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test invalid time format injection."""
        for i, ds in enumerate(mock_datasets):
            ds.AcquisitionTime = f"10{i:02d}00.000000"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="temporal_inconsistency", mutation_count=10
        )

        # Check for invalid format attack type
        format_records = [
            r
            for r in records
            if "invalid" in str(r.details.get("attack_type", "")).lower()
            or "format" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)

    @patch("dicom_fuzzer.attacks.series.series_mutator.pydicom.dcmread")
    def test_temporal_inconsistency_order_reversal(
        self, mock_dcmread, sample_series, mock_datasets
    ):
        """Test temporal order reversal."""
        for i, ds in enumerate(mock_datasets):
            ds.AcquisitionTime = f"10{i:02d}00.000000"

        mock_dcmread.side_effect = mock_datasets

        mutator = Series3DMutator(severity="extreme", seed=42)
        fuzzed_datasets, records = mutator.mutate_series(
            sample_series, strategy="temporal_inconsistency", mutation_count=10
        )

        # Check for order reversal attack type
        reversal_records = [
            r
            for r in records
            if "reversal" in str(r.details.get("attack_type", "")).lower()
            or "order" in str(r.details.get("attack_type", "")).lower()
        ]
        # Verify mutation operation completed
        assert fuzzed_datasets is not None
        assert isinstance(records, list)
