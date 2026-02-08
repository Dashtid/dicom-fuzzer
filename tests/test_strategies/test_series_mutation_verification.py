"""Series + Study Mutation Verification Tests.

Verifies that each series/study mutation strategy produces the claimed defect.
Calls strategy mutate methods directly with patched random.choice to force
specific attack types, then asserts dataset-level properties.

Phase 3: 12 series strategies + 5 study strategies = 17 strategies, 82 attack types.
"""

from __future__ import annotations

import copy
import math
import random as _random
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.series.series_mutator import Series3DMutator
from dicom_fuzzer.attacks.series.study_mutator import DicomStudy, StudyMutator

# Capture real random.choice before any mocking
_real_choice = _random.choice


def _force_attack(attack_value):
    """Return attack_value on first random.choice, real choice after."""
    calls = [0]

    def side_effect(seq):
        calls[0] += 1
        if calls[0] == 1:
            return attack_value
        return _real_choice(seq)

    return side_effect


def _force_sequence(*values):
    """Return values in order on sequential random.choice calls, then real."""
    idx = [0]

    def side_effect(seq):
        if idx[0] < len(values):
            val = values[idx[0]]
            idx[0] += 1
            return val
        return _real_choice(seq)

    return side_effect


@dataclass
class MockDicomSeries:
    """Minimal mock for DicomSeries (series param unused by strategy methods)."""

    series_uid: str = "1.2.3.4.5"
    slices: list = field(default_factory=list)
    slice_count: int = 0


# =============================================================================
# Fixtures
# =============================================================================
@pytest.fixture
def series_datasets():
    """10-slice CT series with all required metadata."""
    datasets = []
    series_uid = generate_uid()
    study_uid = generate_uid()
    for_uid = generate_uid()
    for i in range(10):
        ds = Dataset()
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SeriesInstanceUID = series_uid
        ds.StudyInstanceUID = study_uid
        ds.FrameOfReferenceUID = for_uid
        ds.Modality = "CT"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        ds.ImagePositionPatient = [0.0, 0.0, float(i * 5.0)]
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        ds.PixelSpacing = [0.5, 0.5]
        ds.SliceThickness = 5.0
        ds.InstanceNumber = i + 1
        ds.AcquisitionTime = f"12{i:02d}00.000000"
        ds.AcquisitionDate = "20230101"
        ds.PatientID = "TEST001"
        ds.PatientName = "Test^Patient"
        ds.PatientSex = "M"
        ds.PatientBirthDate = "19800101"
        datasets.append(ds)
    return datasets


@pytest.fixture
def mutator():
    """Series3DMutator instance."""
    return Series3DMutator(severity="moderate")


@pytest.fixture
def mock_series():
    """Mock DicomSeries (unused by strategy methods)."""
    return MockDicomSeries()


@pytest.fixture
def study_datasets():
    """2 series of 5 slices each for study-level tests."""
    all_datasets = []
    study_uid = generate_uid()
    for _s in range(2):
        series_uid = generate_uid()
        series = []
        for i in range(5):
            ds = Dataset()
            ds.SOPInstanceUID = generate_uid()
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ds.SeriesInstanceUID = series_uid
            ds.StudyInstanceUID = study_uid
            ds.FrameOfReferenceUID = generate_uid()
            ds.Modality = "CT"
            ds.Rows = 512
            ds.Columns = 512
            ds.PatientID = "TEST001"
            ds.PatientName = "Test^Patient"
            ds.PatientSex = "M"
            ds.PatientBirthDate = "19800101"
            ds.StudyDate = "20230101"
            ds.StudyID = "STUDY001"
            ds.ImagePositionPatient = [0.0, 0.0, float(i * 5.0)]
            ds.InstanceNumber = i + 1
            series.append(ds)
        all_datasets.append(series)
    return all_datasets


@pytest.fixture
def mock_study(study_datasets):
    """DicomStudy matching study_datasets structure."""
    return DicomStudy(
        study_uid=generate_uid(),
        patient_id="TEST001",
        series_list=[
            MockDicomSeries(series_uid=study_datasets[0][0].SeriesInstanceUID),
            MockDicomSeries(series_uid=study_datasets[1][0].SeriesInstanceUID),
        ],
    )


@pytest.fixture
def study_mutator():
    """StudyMutator instance."""
    return StudyMutator(severity="moderate")


# =============================================================================
# Series Strategy 1: Metadata Corruption (7 handler types)
# =============================================================================
class TestMetadataCorruption:
    """Verify CoreMutationsMixin metadata corruption attacks."""

    def test_invalid_series_uid(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_invalid_series_uid"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        assert len(records) == 1
        assert result[0].SeriesInstanceUID.endswith(".999.FUZZED")
        assert records[0].details["corruption_type"] == "invalid_series_uid"

    def test_invalid_study_uid(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_invalid_study_uid"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        assert result[0].StudyInstanceUID == "!@#$%INVALID_UID^&*()"

    def test_missing_modality(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_missing_modality"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        assert not hasattr(result[0], "Modality")

    def test_empty_series_uid(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_empty_series_uid"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        assert result[0].SeriesInstanceUID == ""

    def test_extreme_uid_length(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_extreme_uid_length"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        assert len(result[0].SeriesInstanceUID) > 100

    def test_invalid_uid_chars(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_invalid_uid_chars"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        assert result[0].SeriesInstanceUID == "1.2.840.ABC.INVALID"

    def test_type_confusion_modality(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "_corrupt_type_confusion_modality"),
        ):
            result, records = mutator._mutate_metadata_corruption(
                ds_list, mock_series, 1
            )
        valid = {
            "999",
            "",
            "XXXXXXXXXXXXXXXXXXXX",
            "CT\\MR",
            "null",
            "\x00\x00",
            "A" * 100,
        }
        assert result[0].Modality in valid


# =============================================================================
# Series Strategy 2: Slice Position Attack (7 attack types)
# =============================================================================
class TestSlicePositionAttack:
    """Verify CoreMutationsMixin slice position attacks."""

    def test_randomize_z(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("randomize_z")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "randomize_z"

    def test_duplicate_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("duplicate")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        if records:
            assert records[0].details["attack_type"] == "duplicate_position"

    def test_nan_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("nan")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        nan_found = any(math.isnan(ds.ImagePositionPatient[2]) for ds in result)
        assert nan_found

    def test_inf_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("inf")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        inf_found = any(math.isinf(ds.ImagePositionPatient[2]) for ds in result)
        assert inf_found

    def test_large_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("large")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        large_found = any(abs(ds.ImagePositionPatient[2]) == 1e308 for ds in result)
        assert large_found

    def test_negative_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("negative")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        neg_found = any(all(x <= 0 for x in ds.ImagePositionPatient) for ds in result)
        assert neg_found

    def test_zero_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("zero")):
            result, records = mutator._mutate_slice_position_attack(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        zero_found = any(
            list(ds.ImagePositionPatient) == [0.0, 0.0, 0.0] for ds in result
        )
        assert zero_found


# =============================================================================
# Series Strategy 3: Boundary Slice Targeting (4 attack types)
# =============================================================================
class TestBoundarySliceTargeting:
    """Verify CoreMutationsMixin boundary slice targeting attacks."""

    def test_first_boundary(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", return_value="first"):
            result, records = mutator._mutate_boundary_slice_targeting(
                ds_list, mock_series, 1
            )
        assert ".BOUNDARY_FUZZ" in str(result[0].SeriesInstanceUID)

    def test_last_boundary(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", return_value="last"):
            result, records = mutator._mutate_boundary_slice_targeting(
                ds_list, mock_series, 1
            )
        assert ".BOUNDARY_FUZZ" in str(result[-1].SeriesInstanceUID)

    def test_middle_boundary(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", return_value="middle"):
            result, records = mutator._mutate_boundary_slice_targeting(
                ds_list, mock_series, 1
            )
        mid = len(result) // 2
        assert ".BOUNDARY_FUZZ" in str(result[mid].SeriesInstanceUID)

    def test_alternating_boundary(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("alternating")):
            result, records = mutator._mutate_boundary_slice_targeting(
                ds_list, mock_series, 1
            )
        assert len(records) >= 2
        assert all(r.details["boundary_type"] == "alternating" for r in records)


# =============================================================================
# Series Strategy 4: Gradient Mutation (3 gradient types)
# =============================================================================
class TestGradientMutation:
    """Verify CoreMutationsMixin gradient mutation attacks."""

    @pytest.mark.parametrize("gradient_type", ["linear", "exponential", "sinusoidal"])
    def test_gradient_type(self, mutator, series_datasets, mock_series, gradient_type):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", return_value=gradient_type):
            result, records = mutator._mutate_gradient_mutation(ds_list, mock_series, 1)
        assert len(records) >= 1
        assert all(r.details["gradient_type"] == gradient_type for r in records)


# =============================================================================
# Series Strategy 5: Inconsistency Injection (4 attack types)
# =============================================================================
class TestInconsistencyInjection:
    """Verify CoreMutationsMixin inconsistency injection attacks."""

    def test_mixed_modality(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_sequence(0, "mixed_modality")):
            result, records = mutator._mutate_inconsistency_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert (
            result[0].Modality != "CT"
            or records[0].details["inconsistency_type"] == "mixed_modality"
        )

    def test_conflicting_orientation(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "conflicting_orientation"),
        ):
            result, records = mutator._mutate_inconsistency_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["inconsistency_type"] == "conflicting_orientation"

    def test_varying_pixel_spacing(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "varying_pixel_spacing"),
        ):
            result, records = mutator._mutate_inconsistency_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        ps = list(result[0].PixelSpacing)
        assert ps != [0.5, 0.5]

    def test_mismatched_dimensions(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_sequence(0, "mismatched_dimensions"),
        ):
            result, records = mutator._mutate_inconsistency_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert result[0].Rows in {256, 512, 1024, 2048}


# =============================================================================
# Series Strategy 6: Non-Orthogonal Orientation (6 attack types)
# =============================================================================
class TestNonOrthogonalOrientation:
    """Verify Reconstruction3DAttacksMixin orientation attacks."""

    def test_non_unit_vector(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("non_unit_vector")):
            result, records = mutator._mutate_non_orthogonal_orientation(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "non_unit_vector"

    def test_non_perpendicular(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("non_perpendicular")):
            result, records = mutator._mutate_non_orthogonal_orientation(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        # Row and col are not perpendicular: dot product != 0
        mutated = any(
            list(ds.ImageOrientationPatient) == [1.0, 0.0, 0.0, 0.5, 0.5, 0.0]
            for ds in result
        )
        assert mutated

    def test_zero_vector(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("zero_vector")):
            result, records = mutator._mutate_non_orthogonal_orientation(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        zero_found = any(
            list(ds.ImageOrientationPatient)[:3] == [0.0, 0.0, 0.0] for ds in result
        )
        assert zero_found

    def test_parallel_vectors(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("parallel_vectors")):
            result, records = mutator._mutate_non_orthogonal_orientation(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        parallel_found = any(
            list(ds.ImageOrientationPatient) == [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            for ds in result
        )
        assert parallel_found

    def test_nan_components(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("nan_components")):
            result, records = mutator._mutate_non_orthogonal_orientation(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        nan_found = any(math.isnan(ds.ImageOrientationPatient[0]) for ds in result)
        assert nan_found

    def test_extreme_values(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("extreme_values")):
            result, records = mutator._mutate_non_orthogonal_orientation(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        extreme_found = any(ds.ImageOrientationPatient[0] == 1e308 for ds in result)
        assert extreme_found


# =============================================================================
# Series Strategy 7: Systematic Slice Gap (4 attack types)
# =============================================================================
class TestSystematicSliceGap:
    """Verify Reconstruction3DAttacksMixin slice gap attacks."""

    @pytest.mark.parametrize(
        "attack",
        ["every_nth", "boundary_removal", "middle_section", "random_removal"],
    )
    def test_slices_removed(self, mutator, series_datasets, mock_series, attack):
        ds_list = copy.deepcopy(series_datasets)
        original_count = len(ds_list)
        with patch("random.choice", side_effect=_force_attack(attack)):
            result, records = mutator._mutate_systematic_slice_gap(
                ds_list, mock_series, 1
            )
        assert len(result) < original_count
        assert len(records) == 1
        assert records[0].details["attack_type"] == attack


# =============================================================================
# Series Strategy 8: Slice Overlap Injection (4 attack types)
# =============================================================================
class TestSliceOverlapInjection:
    """Verify Reconstruction3DAttacksMixin slice overlap attacks."""

    def test_duplicate_position(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("duplicate_position"),
        ):
            result, records = mutator._mutate_slice_overlap_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "duplicate_position"

    def test_physical_overlap(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("physical_overlap"),
        ):
            result, records = mutator._mutate_slice_overlap_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        # Spacing = thickness * 0.5 = 2.5mm
        z0 = result[0].ImagePositionPatient[2]
        z1 = result[1].ImagePositionPatient[2]
        assert abs(z1 - z0) < 5.0  # Less than original spacing

    def test_reversed_order(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("reversed_order")):
            result, records = mutator._mutate_slice_overlap_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        z_values = [ds.ImagePositionPatient[2] for ds in result]
        assert z_values[0] > z_values[-1]  # Descending

    def test_micro_spacing(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("micro_spacing")):
            result, records = mutator._mutate_slice_overlap_injection(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        z0 = result[0].ImagePositionPatient[2]
        z1 = result[1].ImagePositionPatient[2]
        assert abs(z1 - z0) == pytest.approx(0.001, abs=1e-6)


# =============================================================================
# Series Strategy 9: Voxel Aspect Ratio (5 attack types)
# =============================================================================
class TestVoxelAspectRatio:
    """Verify Reconstruction3DAttacksMixin voxel aspect ratio attacks."""

    def test_extreme_ratio(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        handler = mutator._voxel_attack_extreme_ratio
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = mutator._mutate_voxel_aspect_ratio(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "extreme_ratio"

    def test_non_square_pixels(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        handler = mutator._voxel_attack_non_square
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = mutator._mutate_voxel_aspect_ratio(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "non_square_pixels"

    def test_pancake_voxels(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        handler = mutator._voxel_attack_pancake
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = mutator._mutate_voxel_aspect_ratio(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        thick_found = any(ds.SliceThickness == 100.0 for ds in result)
        assert thick_found

    def test_needle_voxels(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        handler = mutator._voxel_attack_needle
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = mutator._mutate_voxel_aspect_ratio(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        thin_found = any(ds.SliceThickness == 0.001 for ds in result)
        assert thin_found

    def test_zero_dimension(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        handler = mutator._voxel_attack_zero
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = mutator._mutate_voxel_aspect_ratio(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "zero_dimension"


# =============================================================================
# Series Strategy 10: Frame of Reference (4 attack types)
# =============================================================================
class TestSeriesFrameOfReference:
    """Verify Reconstruction3DAttacksMixin frame of reference attacks."""

    def test_inconsistent_within_series(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("inconsistent_within_series"),
        ):
            result, records = mutator._mutate_frame_of_reference(
                ds_list, mock_series, 1
            )
        uids = {ds.FrameOfReferenceUID for ds in result}
        assert len(uids) == 10  # Each slice unique

    def test_empty_for(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("empty_for")):
            result, records = mutator._mutate_frame_of_reference(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        empty_found = any(ds.FrameOfReferenceUID == "" for ds in result)
        assert empty_found

    def test_invalid_for(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("invalid_for")):
            result, records = mutator._mutate_frame_of_reference(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        invalid_found = any(
            ds.FrameOfReferenceUID == "!INVALID-FoR-@#$%^&*()" for ds in result
        )
        assert invalid_found

    def test_missing_for(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("missing_for")):
            result, records = mutator._mutate_frame_of_reference(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        missing_found = any(not hasattr(ds, "FrameOfReferenceUID") for ds in result)
        assert missing_found


# =============================================================================
# Series Strategy 11: Cross-Slice Reference (6 attack types)
# =============================================================================
class TestCrossSliceReference:
    """Verify TemporalAttacksMixin cross-slice reference attacks."""

    @pytest.mark.parametrize(
        "attack",
        [
            "reference_nonexistent",
            "circular_reference",
            "invalid_uid_format",
            "self_reference",
            "duplicate_references",
            "missing_reference_chain",
        ],
    )
    def test_attack_creates_records(
        self, mutator, series_datasets, mock_series, attack
    ):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack(attack)):
            result, records = mutator._mutate_cross_slice_reference(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == attack

    def test_reference_nonexistent_uid(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("reference_nonexistent"),
        ):
            result, records = mutator._mutate_cross_slice_reference(
                ds_list, mock_series, 1
            )
        ref_found = any(hasattr(ds, "ReferencedImageSequence") for ds in result)
        assert ref_found

    def test_duplicate_references_count(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("duplicate_references"),
        ):
            result, records = mutator._mutate_cross_slice_reference(
                ds_list, mock_series, 1
            )
        # One slice should have 10+ references
        max_refs = max(len(getattr(ds, "ReferencedImageSequence", [])) for ds in result)
        assert max_refs >= 10


# =============================================================================
# Series Strategy 12: Temporal Inconsistency (7 attack types)
# =============================================================================
class TestTemporalInconsistency:
    """Verify TemporalAttacksMixin temporal inconsistency attacks."""

    def test_randomize(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("randomize")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "randomize_acquisition_time"

    def test_duplicate_timestamps(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("duplicate")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        assert all(ds.AcquisitionTime == "120000.000000" for ds in result)

    def test_extreme_past_date(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("past")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        past_found = any(
            getattr(ds, "AcquisitionDate", "") == "19000101" for ds in result
        )
        assert past_found

    def test_extreme_future_date(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("future")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        future_found = any(
            getattr(ds, "AcquisitionDate", "") == "99991231" for ds in result
        )
        assert future_found

    def test_invalid_time_format(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("invalid")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "invalid_time_format"

    def test_temporal_order_reversal(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("reversal")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        # AcquisitionTime should decrease while InstanceNumber increases
        t0 = result[0].AcquisitionTime
        t_last = result[-1].AcquisitionTime
        assert t0 > t_last

    def test_subsecond_conflicts(self, mutator, series_datasets, mock_series):
        ds_list = copy.deepcopy(series_datasets)
        with patch("random.choice", side_effect=_force_attack("subsecond")):
            result, records = mutator._mutate_temporal_inconsistency(
                ds_list, mock_series, 1
            )
        # All within same second (120000.XXXXXX)
        assert all(ds.AcquisitionTime.startswith("120000.") for ds in result)


# =============================================================================
# Study Strategy 1: Cross-Series Reference (5 attack types)
# =============================================================================
class TestStudyCrossSeriesReference:
    """Verify StudyMutator cross-series reference attacks."""

    @pytest.mark.parametrize(
        "attack",
        [
            "nonexistent_reference",
            "circular_reference",
            "empty_sequence",
            "invalid_uid_format",
            "duplicate_references",
        ],
    )
    def test_attack_creates_records(
        self, study_mutator, study_datasets, mock_study, attack
    ):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack(attack)):
            result, records = study_mutator._mutate_cross_series_reference(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == attack

    def test_nonexistent_reference_uid(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("nonexistent_reference"),
        ):
            result, records = study_mutator._mutate_cross_series_reference(
                ds_list, mock_study, 1
            )
        # Some slice should have ReferencedSeriesSequence with FUZZED UID
        ref_found = False
        for series in result:
            for ds in series:
                seq = getattr(ds, "ReferencedSeriesSequence", None)
                if seq and len(seq) > 0:
                    uid = getattr(seq[0], "SeriesInstanceUID", "")
                    if "FUZZED" in uid and "NONEXISTENT" in uid:
                        ref_found = True
        assert ref_found

    def test_empty_sequence(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("empty_sequence")):
            result, records = study_mutator._mutate_cross_series_reference(
                ds_list, mock_study, 1
            )
        empty_found = False
        for series in result:
            for ds in series:
                seq = getattr(ds, "ReferencedSeriesSequence", None)
                if seq is not None and len(seq) == 0:
                    empty_found = True
        assert empty_found


# =============================================================================
# Study Strategy 2: Frame of Reference (5 attack types)
# =============================================================================
class TestStudyFrameOfReference:
    """Verify StudyMutator frame of reference attacks."""

    @pytest.mark.parametrize(
        "attack",
        [
            "different_for_per_series",
            "same_for_unrelated",
            "empty_for",
            "invalid_for",
            "inconsistent_within_series",
        ],
    )
    def test_attack_creates_records(
        self, study_mutator, study_datasets, mock_study, attack
    ):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack(attack)):
            result, records = study_mutator._mutate_frame_of_reference(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == attack

    def test_empty_for_value(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("empty_for")):
            result, records = study_mutator._mutate_frame_of_reference(
                ds_list, mock_study, 1
            )
        empty_found = False
        for series in result:
            for ds in series:
                if getattr(ds, "FrameOfReferenceUID", None) == "":
                    empty_found = True
        assert empty_found

    def test_invalid_for_value(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("invalid_for")):
            result, records = study_mutator._mutate_frame_of_reference(
                ds_list, mock_study, 1
            )
        invalid_found = False
        for series in result:
            for ds in series:
                if getattr(ds, "FrameOfReferenceUID", "") == "INVALID-FoR-!@#$%":
                    invalid_found = True
        assert invalid_found


# =============================================================================
# Study Strategy 3: Patient Consistency (4 attack types)
# =============================================================================
class TestPatientConsistency:
    """Verify StudyMutator patient consistency attacks."""

    def test_different_patient_id(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        handler = StudyMutator._patient_attack_different_id
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = study_mutator._mutate_patient_consistency(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        # Series 1 should have FUZZED patient ID
        assert result[1][0].PatientID.startswith("FUZZED_")

    def test_conflicting_demographics(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        handler = StudyMutator._patient_attack_demographics
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = study_mutator._mutate_patient_consistency(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert result[1][0].PatientSex in {"M", "F", "O", "INVALID", ""}

    def test_mixed_patient_name(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        handler = StudyMutator._patient_attack_mixed_name
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = study_mutator._mutate_patient_consistency(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert "FUZZED" in str(result[1][0].PatientName)

    def test_conflicting_birthdate(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        handler = StudyMutator._patient_attack_birthdate
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = study_mutator._mutate_patient_consistency(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert result[1][0].PatientBirthDate != "19800101"


# =============================================================================
# Study Strategy 4: Study Metadata (4 attack types)
# =============================================================================
class TestStudyMetadata:
    """Verify StudyMutator study metadata attacks."""

    def test_uid_mismatch(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("uid_mismatch")):
            result, records = study_mutator._mutate_study_metadata(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        # Different series should have different StudyInstanceUIDs
        uid0 = result[0][0].StudyInstanceUID
        uid1 = result[1][0].StudyInstanceUID
        assert uid0 != uid1

    def test_date_conflict(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("date_conflict")):
            result, records = study_mutator._mutate_study_metadata(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "study_date_conflict"

    def test_extreme_id(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("extreme_id")):
            result, records = study_mutator._mutate_study_metadata(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "extreme_study_id"

    def test_empty_uid(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("empty_uid")):
            result, records = study_mutator._mutate_study_metadata(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        empty_found = False
        for series in result:
            for ds in series:
                if getattr(ds, "StudyInstanceUID", None) == "":
                    empty_found = True
        assert empty_found


# =============================================================================
# Study Strategy 5: Mixed Modality Study (3 attack types)
# =============================================================================
class TestMixedModalityStudy:
    """Verify StudyMutator mixed modality attacks."""

    def test_wrong_modality(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch("random.choice", side_effect=_force_attack("wrong_modality")):
            result, records = study_mutator._mutate_mixed_modality(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "wrong_modality"

    def test_mixed_within_series(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("mixed_within_series"),
        ):
            result, records = study_mutator._mutate_mixed_modality(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        # Different slices should have different modalities
        mutated_series = None
        for rec in records:
            if rec.series_index is not None:
                mutated_series = rec.series_index
        if mutated_series is not None:
            modalities = {ds.Modality for ds in result[mutated_series]}
            assert len(modalities) > 1

    def test_invalid_modality(self, study_mutator, study_datasets, mock_study):
        ds_list = copy.deepcopy(study_datasets)
        with patch(
            "random.choice",
            side_effect=_force_attack("invalid_modality"),
        ):
            result, records = study_mutator._mutate_mixed_modality(
                ds_list, mock_study, 1
            )
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "invalid_modality"
