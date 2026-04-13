"""Tests for XRayAngiographyFuzzer.

Verifies all 12 XA/XRF attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.xa_fuzzer import XRayAngiographyFuzzer

_XA_SOP = "1.2.840.10008.5.1.4.1.1.12.1"
_XRF_SOP = "1.2.840.10008.5.1.4.1.1.12.2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _xa_dataset() -> Dataset:
    """Return a minimal well-formed XA CINE dataset."""
    from dicom_fuzzer.attacks.format.xa_fuzzer import _MINIMAL_PIXEL_DATA

    ds = Dataset()
    ds.SOPClassUID = _XA_SOP
    ds.Modality = "XA"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = 10
    ds.CineRate = 15
    ds.FrameTime = "66.7"
    ds.FrameIncrementPointer = 0x00181063
    ds.KVP = "80"
    ds.ExposureTime = 10
    ds.DistanceSourceToDetector = 1000.0
    ds.DistanceSourceToPatient = 700.0
    ds.ImagerPixelSpacing = [0.2, 0.2]
    ds.PositionerPrimaryAngle = 0.0
    ds.PositionerSecondaryAngle = 0.0
    ds.PixelIntensityRelationship = "LOG"
    ds.PixelData = _MINIMAL_PIXEL_DATA * 10
    return ds


def _bare_dataset() -> Dataset:
    ds = Dataset()
    ds.PatientName = "FUZZER^TEST"
    return ds


# ---------------------------------------------------------------------------
# can_mutate()
# ---------------------------------------------------------------------------


class TestCanMutate:
    @pytest.fixture
    def fuzzer(self) -> XRayAngiographyFuzzer:
        return XRayAngiographyFuzzer()

    def test_true_for_xa_sop_class(self, fuzzer: XRayAngiographyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _XA_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_xrf_sop_class(self, fuzzer: XRayAngiographyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _XRF_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_modality_xa(self, fuzzer: XRayAngiographyFuzzer) -> None:
        ds = Dataset()
        ds.Modality = "XA"
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_modality_rf(self, fuzzer: XRayAngiographyFuzzer) -> None:
        ds = Dataset()
        ds.Modality = "RF"
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_xa_geometry_tags(
        self, fuzzer: XRayAngiographyFuzzer
    ) -> None:
        ds = Dataset()
        ds.DistanceSourceToDetector = 1000.0
        ds.CineRate = 15
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset(self, fuzzer: XRayAngiographyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: XRayAngiographyFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert XRayAngiographyFuzzer().strategy_name == "xray_angiography"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> XRayAngiographyFuzzer:
        return XRayAngiographyFuzzer()

    def test_returns_dataset(self, fuzzer: XRayAngiographyFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_xa_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: XRayAngiographyFuzzer) -> None:
        fuzzer.mutate(_xa_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: XRayAngiographyFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: XRayAngiographyFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_xa_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestCineFrameCountOverflow:
    def test_number_of_frames_large(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._cine_frame_count_overflow(ds)
        assert ds.NumberOfFrames == 0xFFFF

    def test_pixel_data_shorter_than_declared(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._cine_frame_count_overflow(ds)
        declared = 2 * 2 * ds.NumberOfFrames
        assert len(ds.PixelData) < declared


class TestCineRateZero:
    def test_cine_rate_zero(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._cine_rate_zero(ds)
        assert ds.CineRate == 0
        assert ds.FrameTime == "0"


class TestPositionerAngleOverflow:
    def test_primary_angle_out_of_range(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._positioner_angle_overflow(ds)
        assert abs(ds.PositionerPrimaryAngle) > 180
        assert abs(ds.PositionerSecondaryAngle) > 180


class TestSourceDetectorDistanceZero:
    def test_distance_source_to_detector_zero(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._source_detector_distance_zero(ds)
        assert ds.DistanceSourceToDetector == 0.0


class TestSourcePatientDistanceNegative:
    def test_distance_source_to_patient_negative(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._source_patient_distance_negative(ds)
        assert ds.DistanceSourceToPatient < 0


class TestKvpOverflow:
    def test_kvp_very_large(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._kvp_overflow(ds)
        assert ds.KVP == "999999"


class TestExposureTimeOverflow:
    def test_exposure_time_int32_max(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._exposure_time_overflow(ds)
        assert ds.ExposureTime == 2147483647


class TestMaskSubtractionBadFrame:
    def test_mask_references_out_of_range_frame(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._mask_subtraction_bad_frame(ds)
        seq = ds.MaskSubtractionSequence
        assert len(seq) == 1
        # pydicom may store a 1-element US list as a scalar int
        frames = seq[0].MaskFrameNumbers
        frame_val = frames[0] if hasattr(frames, "__iter__") else frames
        assert frame_val == 9999

    def test_total_frames_only_ten(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._mask_subtraction_bad_frame(ds)
        assert ds.NumberOfFrames == 10  # frame 9999 is far OOB


class TestNoPixelData:
    def test_pixel_data_removed(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._no_pixel_data(ds)
        assert not hasattr(ds, "PixelData")

    def test_sop_class_is_xa(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert str(ds.SOPClassUID) == _XA_SOP

    def test_cine_parameters_set(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert ds.NumberOfFrames == 50
        assert ds.CineRate == 15


class TestImagerPixelSpacingZero:
    def test_imager_pixel_spacing_zero(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._imager_pixel_spacing_zero(ds)
        assert ds.ImagerPixelSpacing[0] == 0.0
        assert ds.ImagerPixelSpacing[1] == 0.0


class TestPixelIntensityLogLinearMismatch:
    def test_log_with_linear_window(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._pixel_intensity_log_linear_mismatch(ds)
        assert ds.PixelIntensityRelationship == "LOG"
        assert hasattr(ds, "WindowCenter")
        assert hasattr(ds, "WindowWidth")


class TestFrameIncrementPtrMismatch:
    def test_pointer_to_absent_tag(self) -> None:
        fuzzer = XRayAngiographyFuzzer()
        ds = _xa_dataset()
        fuzzer._frame_increment_ptr_mismatch(ds)
        # 0x00089007 = FrameReferenceDateTime -- not in minimal XA dataset
        assert ds.FrameIncrementPointer == 0x00089007


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_xa_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "xray_angiography" in names

    def test_strategy_count_includes_xa(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 38
