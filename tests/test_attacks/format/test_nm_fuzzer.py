"""Tests for NuclearMedicineFuzzer."""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.nm_fuzzer import (
    _NM_SOP_CLASS_UID,
    NuclearMedicineFuzzer,
)


@pytest.fixture
def fuzzer() -> NuclearMedicineFuzzer:
    return NuclearMedicineFuzzer()


@pytest.fixture
def nm_dataset() -> Dataset:
    """Dataset mimicking a Nuclear Medicine Image Storage instance."""
    ds = Dataset()
    ds.SOPClassUID = _NM_SOP_CLASS_UID
    ds.Modality = "NM"
    ds.NumberOfFrames = 60
    ds.NumberOfSlices = 60
    ds.NumberOfTimeSlices = 1

    # EnergyWindowInformationSequence -- 2 windows
    ew1 = Dataset()
    ew1.EnergyWindowLowerLimit = "126.0"
    ew1.EnergyWindowUpperLimit = "154.0"
    ew1.EnergyWindowName = "Tc-99m"
    ew2 = Dataset()
    ew2.EnergyWindowLowerLimit = "60.0"
    ew2.EnergyWindowUpperLimit = "80.0"
    ew2.EnergyWindowName = "Scatter"
    ds.EnergyWindowInformationSequence = Sequence([ew1, ew2])
    ds.NumberOfEnergyWindows = 2

    # DetectorInformationSequence -- 1 detector
    det = Dataset()
    det.DetectorVector = 1
    det.DetectorType = "SCINTILLATION"
    det.DetectorElementSize = [4.0, 4.0]
    ds.DetectorInformationSequence = Sequence([det])
    ds.NumberOfDetectors = 1

    # RotationInformationSequence
    rot = Dataset()
    rot.StartAngle = "0.0"
    rot.AngularStep = "6.0"
    rot.TypeOfDetectorMotion = "STEP"
    rot.NumberOfFramesInRotation = 60
    ds.RotationInformationSequence = Sequence([rot])

    # RadiopharmaceuticalInformationSequence
    rp = Dataset()
    rp.Radiopharmaceutical = "Tc-99m MIBI"
    rp.RadiopharmaceuticalRoute = "IV"
    rp.RadiopharmaceuticalVolume = "5.0"
    rp.RadiopharmaceuticalSpecificActivity = "740.0"
    rp.RadiopharmaceuticalStartTime = "100000.000"
    rp.RadiopharmaceuticalStopTime = "100030.000"
    nuclide = Dataset()
    nuclide.CodeValue = "C-163A8"
    nuclide.CodingSchemeDesignator = "SRT"
    nuclide.CodeMeaning = "Tc-99m"
    rp.RadionuclideCodeSequence = Sequence([nuclide])
    ds.RadiopharmaceuticalInformationSequence = Sequence([rp])

    return ds


# ---------------------------------------------------------------------------
# can_mutate
# ---------------------------------------------------------------------------


class TestCanMutate:
    def test_accepts_nm_sop_class(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        assert fuzzer.can_mutate(ds) is True

    def test_rejects_ct_sop_class(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_rejects_missing_sop_class(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False


# ---------------------------------------------------------------------------
# _energy_window_corruption
# ---------------------------------------------------------------------------


class TestEnergyWindowCorruption:
    def test_inverted_range(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._energy_window_corruption(ds)
            seq = getattr(result, "EnergyWindowInformationSequence", None)
            if seq and len(seq) > 0:
                lower = getattr(seq[0], "EnergyWindowLowerLimit", None)
                upper = getattr(seq[0], "EnergyWindowUpperLimit", None)
                if lower and upper and float(lower) > float(upper):
                    return
        pytest.fail("inverted_range attack never triggered")

    def test_zero_width(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._energy_window_corruption(ds)
            seq = getattr(result, "EnergyWindowInformationSequence", None)
            if seq and len(seq) > 0:
                lower = getattr(seq[0], "EnergyWindowLowerLimit", None)
                upper = getattr(seq[0], "EnergyWindowUpperLimit", None)
                if lower and upper and float(lower) == float(upper):
                    return
        pytest.fail("zero_width attack never triggered")

    def test_negative_kev(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._energy_window_corruption(ds)
            seq = getattr(result, "EnergyWindowInformationSequence", None)
            if seq and len(seq) > 0:
                lower = getattr(seq[0], "EnergyWindowLowerLimit", None)
                if lower and float(lower) < 0:
                    return
        pytest.fail("negative_kev attack never triggered")

    def test_count_mismatch(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._energy_window_corruption(ds)
            seq = getattr(result, "EnergyWindowInformationSequence", None)
            count = getattr(result, "NumberOfEnergyWindows", None)
            if seq is not None and count is not None and count != len(seq):
                return
        pytest.fail("count_mismatch attack never triggered")

    def test_empty_sequence(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._energy_window_corruption(ds)
            seq = getattr(result, "EnergyWindowInformationSequence", None)
            if seq is not None and len(seq) == 0:
                return
        pytest.fail("empty_sequence attack never triggered")

    def test_handles_missing_sequence(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._energy_window_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _detector_geometry_mismatch
# ---------------------------------------------------------------------------


class TestDetectorGeometryMismatch:
    def test_count_mismatch(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._detector_geometry_mismatch(ds)
            seq = getattr(result, "DetectorInformationSequence", None)
            count = getattr(result, "NumberOfDetectors", None)
            if seq is not None and count is not None and count != len(seq):
                return
        pytest.fail("count_mismatch attack never triggered")

    def test_duplicate_vectors(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._detector_geometry_mismatch(ds)
            seq = getattr(result, "DetectorInformationSequence", None)
            if seq and len(seq) >= 2:
                vectors = [getattr(item, "DetectorVector", None) for item in seq]
                if len(vectors) != len(set(vectors)):
                    return
        pytest.fail("duplicate_vectors attack never triggered")

    def test_invalid_type(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        valid_types = {"SCINTILLATION", "SOLID STATE"}
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._detector_geometry_mismatch(ds)
            seq = getattr(result, "DetectorInformationSequence", None)
            if seq and len(seq) > 0:
                det_type = getattr(seq[0], "DetectorType", None)
                if det_type is not None and det_type not in valid_types:
                    return
        pytest.fail("invalid_type attack never triggered")

    def test_zero_size(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._detector_geometry_mismatch(ds)
            seq = getattr(result, "DetectorInformationSequence", None)
            if seq and len(seq) > 0:
                size = getattr(seq[0], "DetectorElementSize", None)
                if size is not None and all(v == 0.0 for v in size):
                    return
        pytest.fail("zero_size attack never triggered")

    def test_remove_sequence(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._detector_geometry_mismatch(ds)
            if "DetectorInformationSequence" not in result:
                return
        pytest.fail("remove_sequence attack never triggered")

    def test_handles_missing_sequence(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._detector_geometry_mismatch(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _rotation_parameter_attack
# ---------------------------------------------------------------------------


class TestRotationParameterAttack:
    def test_impossible_angle(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._rotation_parameter_attack(ds)
            seq = getattr(result, "RotationInformationSequence", None)
            if seq and len(seq) > 0:
                angle = getattr(seq[0], "StartAngle", None)
                if angle and float(angle) > 360:
                    return
        pytest.fail("impossible_angle attack never triggered")

    def test_zero_step(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._rotation_parameter_attack(ds)
            seq = getattr(result, "RotationInformationSequence", None)
            if seq and len(seq) > 0:
                step = getattr(seq[0], "AngularStep", None)
                if step is not None and float(step) == 0.0:
                    return
        pytest.fail("zero_step attack never triggered")

    def test_frame_count_mismatch(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._rotation_parameter_attack(ds)
            seq = getattr(result, "RotationInformationSequence", None)
            frames = getattr(result, "NumberOfFrames", None)
            if seq and len(seq) > 0:
                rot_frames = getattr(seq[0], "NumberOfFramesInRotation", None)
                if rot_frames and frames and rot_frames != int(frames):
                    return
        pytest.fail("frame_count_mismatch attack never triggered")

    def test_invalid_motion(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        valid_motions = {"STEP", "CONTINUOUS"}
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._rotation_parameter_attack(ds)
            seq = getattr(result, "RotationInformationSequence", None)
            if seq and len(seq) > 0:
                motion = getattr(seq[0], "TypeOfDetectorMotion", None)
                if motion is not None and motion not in valid_motions:
                    return
        pytest.fail("invalid_motion attack never triggered")

    def test_remove_sequence(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._rotation_parameter_attack(ds)
            if "RotationInformationSequence" not in result:
                return
        pytest.fail("remove_sequence attack never triggered")

    def test_handles_missing_sequence(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._rotation_parameter_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _radiopharmaceutical_corruption
# ---------------------------------------------------------------------------


class TestRadiopharmaceuticalCorruption:
    def test_empty_isotope(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._radiopharmaceutical_corruption(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                name = getattr(seq[0], "Radiopharmaceutical", None)
                if name == "":
                    return
        pytest.fail("empty_isotope attack never triggered")

    def test_negative_dose(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._radiopharmaceutical_corruption(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                vol = getattr(seq[0], "RadiopharmaceuticalVolume", None)
                if vol and float(vol) < 0:
                    return
        pytest.fail("negative_dose attack never triggered")

    def test_time_reversal(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._radiopharmaceutical_corruption(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                start = getattr(seq[0], "RadiopharmaceuticalStartTime", None)
                stop = getattr(seq[0], "RadiopharmaceuticalStopTime", None)
                if start and stop and str(stop) < str(start):
                    return
        pytest.fail("time_reversal attack never triggered")

    def test_invalid_route(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        valid_routes = {"IV", "ORAL", "INHALATION"}
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._radiopharmaceutical_corruption(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                route = getattr(seq[0], "RadiopharmaceuticalRoute", None)
                if route is not None and route not in valid_routes:
                    return
        pytest.fail("invalid_route attack never triggered")

    def test_remove_nuclide(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._radiopharmaceutical_corruption(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                if not hasattr(seq[0], "RadionuclideCodeSequence"):
                    return
        pytest.fail("remove_nuclide attack never triggered")

    def test_handles_missing_sequence(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._radiopharmaceutical_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _slice_count_mismatch
# ---------------------------------------------------------------------------


class TestSliceCountMismatch:
    def test_slice_frame_mismatch(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._slice_count_mismatch(ds)
            slices = getattr(result, "NumberOfSlices", None)
            frames = getattr(result, "NumberOfFrames", None)
            if slices and frames and slices != int(frames):
                return
        pytest.fail("slice_frame_mismatch attack never triggered")

    def test_time_slice_mismatch(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._slice_count_mismatch(ds)
            time_slices = getattr(result, "NumberOfTimeSlices", None)
            frames = getattr(result, "NumberOfFrames", None)
            if time_slices and frames and time_slices == 999:
                return
        pytest.fail("time_slice_mismatch attack never triggered")

    def test_zero_slices(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._slice_count_mismatch(ds)
            slices = getattr(result, "NumberOfSlices", None)
            time_slices = getattr(result, "NumberOfTimeSlices", None)
            frames = getattr(result, "NumberOfFrames", None)
            if slices == 0 and time_slices == 0 and frames and int(frames) > 0:
                return
        pytest.fail("zero_slices attack never triggered")

    def test_impossible_ratio(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._slice_count_mismatch(ds)
            slices = getattr(result, "NumberOfSlices", None)
            time_slices = getattr(result, "NumberOfTimeSlices", None)
            if slices == 100 and time_slices == 100:
                return
        pytest.fail("impossible_ratio attack never triggered")

    def test_remove_counts(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            result = fuzzer._slice_count_mismatch(ds)
            has_slices = "NumberOfSlices" in result
            has_time = "NumberOfTimeSlices" in result
            has_frames = "NumberOfFrames" in result
            if not has_slices and not has_time and not has_frames:
                return
        pytest.fail("remove_counts attack never triggered")

    def test_handles_missing_counts(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._slice_count_mismatch(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# mutate() integration
# ---------------------------------------------------------------------------


class TestMutateIntegration:
    def test_returns_dataset(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        result = fuzzer.mutate(copy.deepcopy(nm_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        for i in range(20):
            random.seed(i)
            fuzzer.mutate(copy.deepcopy(nm_dataset))

    def test_modifies_dataset(
        self, fuzzer: NuclearMedicineFuzzer, nm_dataset: Dataset
    ) -> None:
        modified = False
        for i in range(30):
            random.seed(i)
            ds = copy.deepcopy(nm_dataset)
            original = copy.deepcopy(ds)
            result = fuzzer.mutate(ds)
            if result != original:
                modified = True
                break
        assert modified, "mutate() never modified the dataset"

    def test_handles_empty_dataset(self, fuzzer: NuclearMedicineFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _NM_SOP_CLASS_UID
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
