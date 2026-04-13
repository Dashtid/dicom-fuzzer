"""Presentation State Fuzzer - DICOM Softcopy Presentation State Mutations.

Category: structural

Targets Grayscale and Color Softcopy Presentation State (GSPS/CSPS) DICOM
objects by corrupting VOI LUT parameters, graphic annotation geometry,
referenced series chains, and overlay data.

Attack surface rationale:
  Presentation State parsers apply VOI LUT transformations and overlay
  annotations when displaying referenced images. When the ReferencedSOPSequence
  is empty, WindowWidth is zero, GraphicAnnotationSequence has no vertices,
  or the LUT data is inconsistent, parsers that trust these fields without
  validation are vulnerable to divide-by-zero, NULL deref on LUT lookup,
  and integer overflow in overlay/annotation rendering.

Dataset-level attacks:
- voi_lut_window_width_zero: SoftcopyVOILUTSequence item with WindowWidth=0
- voi_lut_window_nan: WindowCenter=NaN / WindowWidth=NaN (NaN in LUT transform)
- graphic_annotation_no_points: GraphicAnnotation item with empty PointCoordinatesData
- referenced_series_empty: ReferencedSeriesSequence present but empty
- referenced_sop_empty: ReferencedSOPSequence in series item has zero instances
- presentation_lut_zero: PresentationLUTSequence with LUTDescriptor[0]=0
- no_referenced_series: GSPS with SOPClassUID but no ReferencedSeriesSequence
- overlay_wrong_bit_depth: OverlayBitPosition set to 15 (steals pixel bit)
- annotation_layer_no_label: GraphicLayer item without required GraphicLayerLabel
- circular_sop_reference: GSPS ReferencedSOPInstanceUID == own SOPInstanceUID
- softcopy_voi_no_sequence: VOI LUT reference sequence present but empty
- modality_lut_descr_mismatch: ModalityLUTSequence with inconsistent first/last
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Presentation State SOP Class UIDs
_PS_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.11.1",  # Grayscale Softcopy PS
        "1.2.840.10008.5.1.4.1.1.11.2",  # Color Softcopy PS
        "1.2.840.10008.5.1.4.1.1.11.3",  # Pseudo-color Softcopy PS
        "1.2.840.10008.5.1.4.1.1.11.4",  # Blending Softcopy PS
    }
)

_GSPS_SOP = "1.2.840.10008.5.1.4.1.1.11.1"

# A well-known CT SOP instance UID (used as reference target)
_REF_SOP_CLASS = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
_REF_INSTANCE_UID = "1.2.3.4.5.6.7.8.9.0.1.2"
_OWN_INSTANCE_UID = "9.8.7.6.5.4.3.2.1.0"


def _build_voi_lut_item(center: float = 512.0, width: float = 1024.0) -> Dataset:
    """Return a minimal SoftcopyVOILUT item."""
    item = Dataset()
    item.WindowCenter = str(center)
    item.WindowWidth = str(width)
    ref = Dataset()
    ref.ReferencedSOPClassUID = _REF_SOP_CLASS
    ref.ReferencedSOPInstanceUID = _REF_INSTANCE_UID
    item.ReferencedSOPSequence = Sequence([ref])
    return item


def _build_minimal_gsps_dataset() -> Dataset:
    """Return a minimal well-formed GSPS dataset."""
    ds = Dataset()
    ds.SOPClassUID = _GSPS_SOP
    ds.SOPInstanceUID = _OWN_INSTANCE_UID
    ds.Modality = "PR"
    ds.PresentationLabel = "DEFAULT"

    # ReferencedSeriesSequence
    ref_instance = Dataset()
    ref_instance.ReferencedSOPClassUID = _REF_SOP_CLASS
    ref_instance.ReferencedSOPInstanceUID = _REF_INSTANCE_UID

    ref_series = Dataset()
    ref_series.SeriesInstanceUID = "1.2.3.4.5.6.7"
    ref_series.ReferencedSOPSequence = Sequence([ref_instance])
    ds.ReferencedSeriesSequence = Sequence([ref_series])

    # SoftcopyVOILUTSequence
    ds.SoftcopyVOILUTSequence = Sequence([_build_voi_lut_item()])

    # GraphicAnnotationSequence (minimal)
    layer = Dataset()
    layer.GraphicLayerLabel = "LAYER1"
    layer.GraphicLayerOrder = 1
    ds.GraphicLayerSequence = Sequence([layer])

    annot = Dataset()
    annot.GraphicLayer = "LAYER1"
    annot.TextObjectSequence = Sequence([])
    annot.GraphicObjectSequence = Sequence([])
    ds.GraphicAnnotationSequence = Sequence([annot])
    return ds


class PresentationStateFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Softcopy Presentation State objects.

    Targets GSPS/CSPS parsers through VOI LUT parameter violations,
    graphic annotation corruption, and referenced series chain attacks.
    """

    def __init__(self) -> None:
        """Initialize PS fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "presentation_state"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for GSPS/CSPS datasets."""
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        if sop_class in _PS_SOP_CLASSES:
            return True
        if str(getattr(dataset, "Modality", "")) == "PR":
            return True
        return hasattr(dataset, "SoftcopyVOILUTSequence") or hasattr(
            dataset, "GraphicAnnotationSequence"
        )

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply Presentation State mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._voi_lut_window_width_zero,
            self._voi_lut_window_nan,
            self._graphic_annotation_no_points,
            self._referenced_series_empty,
            self._referenced_sop_empty,
            self._presentation_lut_zero,
            self._no_referenced_series,
            self._overlay_wrong_bit_depth,
            self._annotation_layer_no_label,
            self._circular_sop_reference,
            self._softcopy_voi_no_sequence,
            self._modality_lut_descr_mismatch,
        ]

        attack = random.choice(attacks)
        try:
            attack(dataset)
            self.last_variant = attack.__name__.lstrip("_")
        except Exception:
            self.last_variant = "fallback"
            self._no_referenced_series(dataset)

        return dataset

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_ps_root(self, dataset: Dataset) -> None:
        """Ensure dataset has GSPS SOPClassUID and minimal attributes."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = _GSPS_SOP
        if not hasattr(dataset, "SOPInstanceUID"):
            dataset.SOPInstanceUID = _OWN_INSTANCE_UID
        if not hasattr(dataset, "SoftcopyVOILUTSequence"):
            dataset.SoftcopyVOILUTSequence = Sequence([_build_voi_lut_item()])

    def _ensure_voi_lut_item(self, dataset: Dataset) -> Dataset:
        """Return the first VOI LUT item, creating it if needed."""
        self._ensure_ps_root(dataset)
        if len(dataset.SoftcopyVOILUTSequence) == 0:
            dataset.SoftcopyVOILUTSequence = Sequence([_build_voi_lut_item()])
        return dataset.SoftcopyVOILUTSequence[0]

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _voi_lut_window_width_zero(self, dataset: Dataset) -> None:
        """SoftcopyVOILUT item with WindowWidth=0 (divide-by-zero in normalization)."""
        item = self._ensure_voi_lut_item(dataset)
        item.WindowCenter = "512"
        item.WindowWidth = "0"

    def _voi_lut_window_nan(self, dataset: Dataset) -> None:
        """WindowCenter/Width = NaN (NaN propagation in VOI LUT pipeline)."""
        item = self._ensure_voi_lut_item(dataset)
        item.WindowCenter = "NaN"
        item.WindowWidth = "NaN"

    def _graphic_annotation_no_points(self, dataset: Dataset) -> None:
        """GraphicAnnotation POLYLINE with empty PointCoordinatesData (zero-point polygon)."""
        self._ensure_ps_root(dataset)
        graphic = Dataset()
        graphic.GraphicAnnotationUnits = "PIXEL"
        graphic.GraphicType = "POLYLINE"
        graphic.NumberOfGraphicPoints = 0
        graphic.GraphicData = []  # Empty -- no vertices
        graphic.GraphicFilled = "N"
        annot = Dataset()
        annot.GraphicLayer = "LAYER1"
        annot.GraphicObjectSequence = Sequence([graphic])
        dataset.GraphicAnnotationSequence = Sequence([annot])

    def _referenced_series_empty(self, dataset: Dataset) -> None:
        """ReferencedSeriesSequence present but empty (NULL deref on first series)."""
        self._ensure_ps_root(dataset)
        dataset.ReferencedSeriesSequence = Sequence([])

    def _referenced_sop_empty(self, dataset: Dataset) -> None:
        """ReferencedSOPSequence in series has zero instances (empty image list)."""
        self._ensure_ps_root(dataset)
        ref_series = Dataset()
        ref_series.SeriesInstanceUID = "1.2.3.4.5.6.7"
        ref_series.ReferencedSOPSequence = Sequence([])  # Zero instances
        dataset.ReferencedSeriesSequence = Sequence([ref_series])

    def _presentation_lut_zero(self, dataset: Dataset) -> None:
        """PresentationLUTSequence with LUTDescriptor[0]=0 (zero-entry LUT)."""
        self._ensure_ps_root(dataset)
        lut_item = Dataset()
        lut_item.LUTDescriptor = [0, 0, 16]  # 0 entries in LUT (should be 256 or 65536)
        lut_item.LUTData = bytes(2)  # only 2 bytes of LUT data
        dataset.PresentationLUTSequence = Sequence([lut_item])

    def _no_referenced_series(self, dataset: Dataset) -> None:
        """GSPS SOPClassUID but no ReferencedSeriesSequence (orphaned presentation state)."""
        dataset.SOPClassUID = _GSPS_SOP
        dataset.Modality = "PR"
        dataset.PresentationLabel = "ORPHAN"
        if hasattr(dataset, "ReferencedSeriesSequence"):
            del dataset.ReferencedSeriesSequence

    def _overlay_wrong_bit_depth(self, dataset: Dataset) -> None:
        """OverlayBitPosition=15 (steals highest pixel bit for overlay encoding)."""
        self._ensure_ps_root(dataset)
        # Overlay tags are repeating-group (60xx,xxxx) -- must use add_new()
        dataset.add_new((0x6000, 0x0010), "US", 512)  # OverlayRows
        dataset.add_new((0x6000, 0x0011), "US", 512)  # OverlayColumns
        dataset.add_new((0x6000, 0x0040), "CS", "G")  # OverlayType
        dataset.add_new((0x6000, 0x0102), "US", 15)  # OverlayBitPosition (should be 0)
        # Deliberately provide pixel data that doesn't reserve bit 15
        dataset.add_new((0x6000, 0x3000), "OB", bytes(512 * 512 // 8))  # OverlayData

    def _annotation_layer_no_label(self, dataset: Dataset) -> None:
        """GraphicLayer item without required GraphicLayerLabel (NULL deref on layer lookup)."""
        self._ensure_ps_root(dataset)
        bad_layer = Dataset()
        bad_layer.GraphicLayerOrder = 1
        # Deliberately omit GraphicLayerLabel
        dataset.GraphicLayerSequence = Sequence([bad_layer])

    def _circular_sop_reference(self, dataset: Dataset) -> None:
        """GSPS ReferencedSOPInstanceUID == own SOPInstanceUID (self-reference)."""
        self._ensure_ps_root(dataset)
        own_uid = str(getattr(dataset, "SOPInstanceUID", _OWN_INSTANCE_UID))
        ref_instance = Dataset()
        ref_instance.ReferencedSOPClassUID = _GSPS_SOP  # References another GSPS
        ref_instance.ReferencedSOPInstanceUID = own_uid  # ...which is itself
        ref_series = Dataset()
        ref_series.SeriesInstanceUID = "1.2.3.4.5.6.7"
        ref_series.ReferencedSOPSequence = Sequence([ref_instance])
        dataset.ReferencedSeriesSequence = Sequence([ref_series])

    def _softcopy_voi_no_sequence(self, dataset: Dataset) -> None:
        """SoftcopyVOILUTSequence present but empty (first item deref without guard)."""
        self._ensure_ps_root(dataset)
        dataset.SoftcopyVOILUTSequence = Sequence([])

    def _modality_lut_descr_mismatch(self, dataset: Dataset) -> None:
        """ModalityLUTSequence with first > last value in LUTDescriptor (inverted range)."""
        self._ensure_ps_root(dataset)
        lut_item = Dataset()
        # LUTDescriptor: [number_of_entries, first_stored_value, bits_for_entry]
        # Setting first_stored_value > 0 with too-small LUT
        lut_item.LUTDescriptor = [
            4096,
            4095,
            16,
        ]  # start at 4095, step through 4096 values
        lut_item.LUTData = bytes(2)  # only 2 bytes -- far less than declared
        lut_item.ModalityLUTType = "HU"
        dataset.ModalityLUTSequence = Sequence([lut_item])
