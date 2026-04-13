"""Tests for MammographyFuzzer.

Verifies all 12 MG/DBT attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import math

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.mammography_fuzzer import MammographyFuzzer

_MG_SOP = "1.2.840.10008.5.1.4.1.1.1.2"
_DBT_SOP = "1.2.840.10008.5.1.4.1.1.13.1.3"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mg_dataset() -> Dataset:
    """Return a minimal well-formed MG dataset."""
    from dicom_fuzzer.attacks.format.mammography_fuzzer import _MINIMAL_PIXEL_DATA_16

    ds = Dataset()
    ds.SOPClassUID = _MG_SOP
    ds.Modality = "MG"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME1"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.BodyPartThickness = 50.0
    ds.CompressionForce = 120.0
    ds.KVP = "28"
    ds.ImagerPixelSpacing = [0.1, 0.1]
    ds.PixelSpacing = [0.1, 0.1]
    ds.WindowCenter = 2048
    ds.WindowWidth = 1024
    ds.PixelData = _MINIMAL_PIXEL_DATA_16

    view = Dataset()
    view.CodeValue = "R-10228"
    view.CodingSchemeDesignator = "SNM3"
    view.CodeMeaning = "cranio-caudal"
    ds.ViewCodeSequence = Sequence([view])
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
    def fuzzer(self) -> MammographyFuzzer:
        return MammographyFuzzer()

    def test_true_for_mg_sop_class(self, fuzzer: MammographyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _MG_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dbt_sop_class(self, fuzzer: MammographyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _DBT_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_modality_mg(self, fuzzer: MammographyFuzzer) -> None:
        ds = Dataset()
        ds.Modality = "MG"
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_mg_geometry_tags(
        self, fuzzer: MammographyFuzzer
    ) -> None:
        ds = Dataset()
        ds.BodyPartThickness = 50.0
        ds.CompressionForce = 100.0
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset(self, fuzzer: MammographyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: MammographyFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert MammographyFuzzer().strategy_name == "mammography"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> MammographyFuzzer:
        return MammographyFuzzer()

    def test_returns_dataset(self, fuzzer: MammographyFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_mg_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: MammographyFuzzer) -> None:
        fuzzer.mutate(_mg_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: MammographyFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: MammographyFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_mg_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestBreastThicknessZero:
    def test_body_part_thickness_zero(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._breast_thickness_zero(ds)
        assert ds.BodyPartThickness == 0


class TestBreastThicknessNegative:
    def test_body_part_thickness_negative(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._breast_thickness_negative(ds)
        assert ds.BodyPartThickness < 0


class TestPhotometricMonochrome1Rgb:
    def test_monochrome1_with_three_samples(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._photometric_monochrome1_rgb(ds)
        assert ds.PhotometricInterpretation == "MONOCHROME1"
        assert ds.SamplesPerPixel == 3


class TestImagerPixelSpacingMismatch:
    def test_imager_and_pixel_spacing_differ(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._imager_pixel_spacing_mismatch(ds)
        assert ds.ImagerPixelSpacing != ds.PixelSpacing


class TestImagerPixelSpacingNan:
    def test_imager_pixel_spacing_nan(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._imager_pixel_spacing_nan(ds)
        assert math.isnan(ds.ImagerPixelSpacing[0])
        assert math.isnan(ds.ImagerPixelSpacing[1])


class TestDbtFrameCountOverflow:
    def test_number_of_frames_large(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._dbt_frame_count_overflow(ds)
        assert ds.NumberOfFrames == 0xFFFF

    def test_sop_class_is_dbt(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._dbt_frame_count_overflow(ds)
        assert str(ds.SOPClassUID) == _DBT_SOP

    def test_pixel_data_far_shorter_than_declared(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._dbt_frame_count_overflow(ds)
        # 2x2 at 16-bit * 65535 frames >> 8 bytes of PixelData
        declared = 2 * 2 * 2 * ds.NumberOfFrames
        assert len(ds.PixelData) < declared


class TestViewCodeEmpty:
    def test_view_code_sequence_is_empty(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._view_code_empty(ds)
        assert hasattr(ds, "ViewCodeSequence")
        assert len(ds.ViewCodeSequence) == 0


class TestNoPixelData:
    def test_pixel_data_removed(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._no_pixel_data(ds)
        assert not hasattr(ds, "PixelData")

    def test_sop_class_is_mg(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert str(ds.SOPClassUID) == _MG_SOP

    def test_clinical_dimensions_set(self) -> None:
        """MG images use large clinical dimensions (3328x2560 typical FFDM)."""
        fuzzer = MammographyFuzzer()
        ds = _bare_dataset()
        fuzzer._no_pixel_data(ds)
        assert ds.Rows == 3328
        assert ds.Columns == 2560


class TestCompressionForceNegative:
    def test_compression_force_negative(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._compression_force_negative(ds)
        assert ds.CompressionForce < 0


class TestKvpOverflow:
    def test_kvp_very_large(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._kvp_overflow(ds)
        assert ds.KVP == "999999"


class TestWindowWidthZero:
    def test_window_width_zero(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._window_width_zero(ds)
        assert ds.WindowWidth == 0


class TestPartialViewNoDescription:
    def test_partial_view_yes_with_no_description(self) -> None:
        fuzzer = MammographyFuzzer()
        ds = _mg_dataset()
        fuzzer._partial_view_no_description(ds)
        assert ds.PartialView == "YES"
        assert not hasattr(ds, "PartialViewDescription")


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_mammography_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "mammography" in names

    def test_strategy_count_includes_mammography(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 37
