"""Tests for PresentationStateFuzzer.

Verifies all 12 PS attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.presentation_state_fuzzer import (
    PresentationStateFuzzer,
    _build_minimal_gsps_dataset,
)

_GSPS_SOP = "1.2.840.10008.5.1.4.1.1.11.1"
_CSPS_SOP = "1.2.840.10008.5.1.4.1.1.11.2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ps_dataset() -> Dataset:
    """Return a minimal well-formed GSPS dataset."""
    return _build_minimal_gsps_dataset()


def _bare_dataset() -> Dataset:
    ds = Dataset()
    ds.PatientName = "FUZZER^TEST"
    return ds


# ---------------------------------------------------------------------------
# can_mutate()
# ---------------------------------------------------------------------------


class TestCanMutate:
    @pytest.fixture
    def fuzzer(self) -> PresentationStateFuzzer:
        return PresentationStateFuzzer()

    def test_true_for_gsps_sop_class(self, fuzzer: PresentationStateFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _GSPS_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_csps_sop_class(self, fuzzer: PresentationStateFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _CSPS_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_pr_modality(self, fuzzer: PresentationStateFuzzer) -> None:
        ds = Dataset()
        ds.Modality = "PR"
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_softcopy_voi_lut_sequence(
        self, fuzzer: PresentationStateFuzzer
    ) -> None:
        ds = Dataset()
        ds.SoftcopyVOILUTSequence = Sequence([])
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_graphic_annotation_sequence(
        self, fuzzer: PresentationStateFuzzer
    ) -> None:
        ds = Dataset()
        ds.GraphicAnnotationSequence = Sequence([])
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset(self, fuzzer: PresentationStateFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: PresentationStateFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert PresentationStateFuzzer().strategy_name == "presentation_state"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> PresentationStateFuzzer:
        return PresentationStateFuzzer()

    def test_returns_dataset(self, fuzzer: PresentationStateFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_ps_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: PresentationStateFuzzer) -> None:
        fuzzer.mutate(_ps_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: PresentationStateFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: PresentationStateFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_ps_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestVoiLutWindowWidthZero:
    def test_window_width_zero(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._voi_lut_window_width_zero(ds)
        item = ds.SoftcopyVOILUTSequence[0]
        assert item.WindowWidth == "0"

    def test_window_center_preserved(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._voi_lut_window_width_zero(ds)
        item = ds.SoftcopyVOILUTSequence[0]
        assert item.WindowCenter == "512"


class TestVoiLutWindowNan:
    def test_window_center_nan(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._voi_lut_window_nan(ds)
        item = ds.SoftcopyVOILUTSequence[0]
        assert item.WindowCenter == "NaN"

    def test_window_width_nan(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._voi_lut_window_nan(ds)
        item = ds.SoftcopyVOILUTSequence[0]
        assert item.WindowWidth == "NaN"


class TestGraphicAnnotationNoPoints:
    def test_polyline_with_zero_points(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._graphic_annotation_no_points(ds)
        annot = ds.GraphicAnnotationSequence[0]
        graphic = annot.GraphicObjectSequence[0]
        assert graphic.GraphicType == "POLYLINE"
        assert graphic.NumberOfGraphicPoints == 0

    def test_graphic_data_empty(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._graphic_annotation_no_points(ds)
        annot = ds.GraphicAnnotationSequence[0]
        graphic = annot.GraphicObjectSequence[0]
        assert len(graphic.GraphicData) == 0


class TestReferencedSeriesEmpty:
    def test_sequence_is_empty(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._referenced_series_empty(ds)
        assert len(ds.ReferencedSeriesSequence) == 0


class TestReferencedSopEmpty:
    def test_series_present_but_no_sop_items(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._referenced_sop_empty(ds)
        assert len(ds.ReferencedSeriesSequence) == 1
        assert len(ds.ReferencedSeriesSequence[0].ReferencedSOPSequence) == 0


class TestPresentationLutZero:
    def test_lut_descriptor_first_entry_zero(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._presentation_lut_zero(ds)
        lut_item = ds.PresentationLUTSequence[0]
        assert lut_item.LUTDescriptor[0] == 0

    def test_lut_data_truncated(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._presentation_lut_zero(ds)
        lut_item = ds.PresentationLUTSequence[0]
        assert len(lut_item.LUTData) == 2


class TestNoReferencedSeries:
    def test_sop_class_is_gsps(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _bare_dataset()
        fuzzer._no_referenced_series(ds)
        assert str(ds.SOPClassUID) == _GSPS_SOP

    def test_referenced_series_removed(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._no_referenced_series(ds)
        assert not hasattr(ds, "ReferencedSeriesSequence")

    def test_presentation_label_orphan(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _bare_dataset()
        fuzzer._no_referenced_series(ds)
        assert ds.PresentationLabel == "ORPHAN"


class TestOverlayWrongBitDepth:
    def test_overlay_bit_position_15(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._overlay_wrong_bit_depth(ds)
        # OverlayBitPosition (6000,0102) -- repeating group, access via tag tuple
        assert ds[0x6000, 0x0102].value == 15

    def test_overlay_dimensions(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._overlay_wrong_bit_depth(ds)
        assert ds[0x6000, 0x0010].value == 512  # OverlayRows
        assert ds[0x6000, 0x0011].value == 512  # OverlayColumns

    def test_overlay_data_present(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._overlay_wrong_bit_depth(ds)
        assert len(ds[0x6000, 0x3000].value) == 512 * 512 // 8  # OverlayData


class TestAnnotationLayerNoLabel:
    def test_graphic_layer_label_absent(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._annotation_layer_no_label(ds)
        layer = ds.GraphicLayerSequence[0]
        assert not hasattr(layer, "GraphicLayerLabel")

    def test_graphic_layer_order_present(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._annotation_layer_no_label(ds)
        layer = ds.GraphicLayerSequence[0]
        assert layer.GraphicLayerOrder == 1


class TestCircularSopReference:
    def test_referenced_uid_equals_own_uid(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        own_uid = str(ds.SOPInstanceUID)
        fuzzer._circular_sop_reference(ds)
        ref = ds.ReferencedSeriesSequence[0].ReferencedSOPSequence[0]
        assert ref.ReferencedSOPInstanceUID == own_uid

    def test_referenced_sop_class_is_gsps(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._circular_sop_reference(ds)
        ref = ds.ReferencedSeriesSequence[0].ReferencedSOPSequence[0]
        assert str(ref.ReferencedSOPClassUID) == _GSPS_SOP


class TestSoftcopyVoiNoSequence:
    def test_sequence_present_but_empty(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._softcopy_voi_no_sequence(ds)
        assert hasattr(ds, "SoftcopyVOILUTSequence")
        assert len(ds.SoftcopyVOILUTSequence) == 0


class TestModalityLutDescrMismatch:
    def test_lut_descriptor_start_near_max(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._modality_lut_descr_mismatch(ds)
        lut_item = ds.ModalityLUTSequence[0]
        # first_stored_value = LUTDescriptor[1] = 4095
        assert lut_item.LUTDescriptor[1] == 4095

    def test_lut_data_far_shorter_than_declared(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._modality_lut_descr_mismatch(ds)
        lut_item = ds.ModalityLUTSequence[0]
        # Declared 4096 entries * 2 bytes each = 8192 bytes; actual = 2
        assert len(lut_item.LUTData) == 2

    def test_modality_lut_type_hu(self) -> None:
        fuzzer = PresentationStateFuzzer()
        ds = _ps_dataset()
        fuzzer._modality_lut_descr_mismatch(ds)
        lut_item = ds.ModalityLUTSequence[0]
        assert lut_item.ModalityLUTType == "HU"


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_ps_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "presentation_state" in names

    def test_strategy_count_includes_ps(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 42
