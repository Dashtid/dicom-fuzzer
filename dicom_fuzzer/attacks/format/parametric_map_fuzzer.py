"""Parametric Map Fuzzer - DICOM Quantitative MRI Map Mutations.

Category: structural

Targets Parametric Map (PM) DICOM objects by corrupting the real-world
value mapping parameters, pixel-to-physical unit conversion, and
multi-frame per-frame metadata.

Attack surface rationale:
  Parametric Map parsers apply a linear transform (Slope * pixel + Intercept)
  to convert stored integer values to physical units (T1 ms, ADC mm2/s, etc.).
  When RealWorldValueSlope is zero or NaN, or when the value mapping sequence
  is absent or empty, parsers that trust these fields without validation are
  vulnerable to divide-by-zero, NaN propagation, and NULL deref on LUT lookup.

Dataset-level attacks:
- rwv_slope_zero: RealWorldValueSlope = 0 (divide-by-zero in physical unit conversion)
- rwv_slope_nan: RealWorldValueSlope = NaN (NaN propagation through measurement display)
- rwv_intercept_inf: RealWorldValueIntercept = Inf (Inf in display pipeline)
- frame_count_overflow: NumberOfFrames >> PixelData (OOB in per-frame iterator)
- no_pixel_data: PM SOPClassUID + frame geometry but no PixelData
- rwv_mapping_empty: RealWorldValueMappingSequence present but empty (NULL deref)
- bits_alloc_mismatch: BitsAllocated=32 / BitsStored=16 / HighBit=11 (inconsistent)
- measurement_units_missing: RWV mapping item without MeasurementUnitsCodeSequence
- first_value_gt_last: RealWorldValueFirstValueMapped > RealWorldValueLastValueMapped
- pixel_spacing_zero: PixelSpacing = [0, 0] (divide-by-zero in physical distance calc)
- slice_thickness_negative: SliceThickness = -1.0 (sign error in volume reconstruction)
- per_frame_functional_empty: PerFrameFunctionalGroupsSequence present but empty
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Parametric Map SOP Class UID
_PM_SOP_CLASS = "1.2.840.10008.5.1.4.1.1.30"

_PM_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.30",  # Parametric Map Storage
    }
)

# Minimal 16-bit greyscale pixel data (2x2 pixels, LE unsigned)
_MINIMAL_PIXEL_DATA_16 = bytes([0x00, 0x00, 0x80, 0x00, 0x00, 0x40, 0x00, 0xC0])


def _build_rwv_item(slope: float = 0.001, intercept: float = 0.0) -> Dataset:
    """Return a minimal RealWorldValueMappingSequence item."""
    item = Dataset()
    item.RealWorldValueFirstValueMapped = 0
    item.RealWorldValueLastValueMapped = 4095
    item.RealWorldValueSlope = slope
    item.RealWorldValueIntercept = intercept
    item.LUTExplanation = "T1 map (ms)"
    item.LUTLabel = "T1"

    units = Dataset()
    units.CodeValue = "ms"
    units.CodingSchemeDesignator = "UCUM"
    units.CodeMeaning = "millisecond"
    item.MeasurementUnitsCodeSequence = Sequence([units])
    return item


def _build_minimal_pm_dataset(n_frames: int = 4) -> Dataset:
    """Return a minimal well-formed Parametric Map dataset."""
    ds = Dataset()
    ds.SOPClassUID = _PM_SOP_CLASS
    ds.Modality = "MR"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = n_frames
    ds.PixelSpacing = [1.0, 1.0]
    ds.SliceThickness = 5.0
    ds.PixelData = _MINIMAL_PIXEL_DATA_16 * n_frames
    ds.RealWorldValueMappingSequence = Sequence([_build_rwv_item()])

    # Minimal PerFrameFunctionalGroupsSequence (one item per frame)
    per_frame_items = []
    for _ in range(n_frames):
        fg = Dataset()
        rwv_fg = Dataset()
        rwv_fg.RealWorldValueMappingSequence = Sequence([_build_rwv_item()])
        fg.RealWorldValueMappingSequence = Sequence([rwv_fg])
        per_frame_items.append(fg)
    ds.PerFrameFunctionalGroupsSequence = Sequence(per_frame_items)
    return ds


class ParametricMapFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Parametric Map (quantitative MRI) objects.

    Targets PM parsers through real-world value mapping corruption,
    pixel-to-physical unit conversion failures, and per-frame metadata
    violations.
    """

    def __init__(self) -> None:
        """Initialize PM fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "parametric_map"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for Parametric Map datasets."""
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        if sop_class in _PM_SOP_CLASSES:
            return True
        return hasattr(dataset, "RealWorldValueMappingSequence")

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply Parametric Map mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._rwv_slope_zero,
            self._rwv_slope_nan,
            self._rwv_intercept_inf,
            self._frame_count_overflow,
            self._no_pixel_data,
            self._rwv_mapping_empty,
            self._bits_alloc_mismatch,
            self._measurement_units_missing,
            self._first_value_gt_last,
            self._pixel_spacing_zero,
            self._slice_thickness_negative,
            self._per_frame_functional_empty,
        ]

        attack = random.choice(attacks)
        try:
            attack(dataset)
            self.last_variant = attack.__name__.lstrip("_")
        except Exception:
            self.last_variant = "fallback"
            self._no_pixel_data(dataset)

        return dataset

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_pm_root(self, dataset: Dataset) -> None:
        """Ensure dataset has PM SOPClassUID and minimal attributes."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = _PM_SOP_CLASS
        if not hasattr(dataset, "Rows"):
            dataset.Rows = 2
            dataset.Columns = 2
        if not hasattr(dataset, "BitsAllocated"):
            dataset.BitsAllocated = 16
            dataset.BitsStored = 12
            dataset.HighBit = 11
        if not hasattr(dataset, "PixelData"):
            dataset.PixelData = _MINIMAL_PIXEL_DATA_16
        if not hasattr(dataset, "NumberOfFrames"):
            dataset.NumberOfFrames = 4
        if not hasattr(dataset, "RealWorldValueMappingSequence"):
            dataset.RealWorldValueMappingSequence = Sequence([_build_rwv_item()])

    def _ensure_rwv_item(self, dataset: Dataset) -> Dataset:
        """Return the first RWV mapping item, creating it if absent."""
        self._ensure_pm_root(dataset)
        if len(dataset.RealWorldValueMappingSequence) == 0:
            dataset.RealWorldValueMappingSequence = Sequence([_build_rwv_item()])
        return dataset.RealWorldValueMappingSequence[0]

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _rwv_slope_zero(self, dataset: Dataset) -> None:
        """RealWorldValueSlope = 0 (divide-by-zero in pixel-to-physical conversion)."""
        item = self._ensure_rwv_item(dataset)
        item.RealWorldValueSlope = 0.0

    def _rwv_slope_nan(self, dataset: Dataset) -> None:
        """RealWorldValueSlope = NaN (NaN propagation through measurement display)."""
        item = self._ensure_rwv_item(dataset)
        item.RealWorldValueSlope = float("nan")

    def _rwv_intercept_inf(self, dataset: Dataset) -> None:
        """RealWorldValueIntercept = Inf (Inf in physical value display pipeline)."""
        item = self._ensure_rwv_item(dataset)
        item.RealWorldValueIntercept = float("inf")

    def _frame_count_overflow(self, dataset: Dataset) -> None:
        """NumberOfFrames >> PixelData length (OOB read in per-frame iterator)."""
        self._ensure_pm_root(dataset)
        dataset.NumberOfFrames = 0xFFFF  # 65535 declared slices
        dataset.PixelData = _MINIMAL_PIXEL_DATA_16  # only 8 bytes

    def _no_pixel_data(self, dataset: Dataset) -> None:
        """PM SOPClassUID + clinical geometry but no PixelData (NULL deref in render)."""
        dataset.SOPClassUID = _PM_SOP_CLASS
        dataset.Modality = "MR"
        dataset.Rows = 256
        dataset.Columns = 256
        dataset.NumberOfFrames = 30
        dataset.RealWorldValueMappingSequence = Sequence([_build_rwv_item()])
        if hasattr(dataset, "PixelData"):
            del dataset.PixelData

    def _rwv_mapping_empty(self, dataset: Dataset) -> None:
        """RealWorldValueMappingSequence present but empty (NULL deref on LUT lookup)."""
        self._ensure_pm_root(dataset)
        dataset.RealWorldValueMappingSequence = Sequence([])

    def _bits_alloc_mismatch(self, dataset: Dataset) -> None:
        """BitsAllocated=32 / BitsStored=16 / HighBit=11 (inconsistent bit geometry)."""
        self._ensure_pm_root(dataset)
        dataset.BitsAllocated = 32
        dataset.BitsStored = 16
        dataset.HighBit = 11  # Should be BitsStored-1=15

    def _measurement_units_missing(self, dataset: Dataset) -> None:
        """RWV mapping item without MeasurementUnitsCodeSequence (missing required attr)."""
        self._ensure_pm_root(dataset)
        bad_item = Dataset()
        bad_item.RealWorldValueFirstValueMapped = 0
        bad_item.RealWorldValueLastValueMapped = 4095
        bad_item.RealWorldValueSlope = 0.001
        bad_item.RealWorldValueIntercept = 0.0
        bad_item.LUTExplanation = "Missing units"
        # Deliberately omit MeasurementUnitsCodeSequence
        dataset.RealWorldValueMappingSequence = Sequence([bad_item])

    def _first_value_gt_last(self, dataset: Dataset) -> None:
        """RealWorldValueFirstValueMapped > RealWorldValueLastValueMapped (inverted range)."""
        item = self._ensure_rwv_item(dataset)
        item.RealWorldValueFirstValueMapped = 4095
        item.RealWorldValueLastValueMapped = 0  # inverted: first > last

    def _pixel_spacing_zero(self, dataset: Dataset) -> None:
        """PixelSpacing = [0, 0] (divide-by-zero in physical distance measurement)."""
        self._ensure_pm_root(dataset)
        dataset.PixelSpacing = [0.0, 0.0]

    def _slice_thickness_negative(self, dataset: Dataset) -> None:
        """SliceThickness = -1.0 (sign error in volume reconstruction calculations)."""
        self._ensure_pm_root(dataset)
        dataset.SliceThickness = -1.0

    def _per_frame_functional_empty(self, dataset: Dataset) -> None:
        """PerFrameFunctionalGroupsSequence present but empty (first-frame NULL deref)."""
        self._ensure_pm_root(dataset)
        dataset.PerFrameFunctionalGroupsSequence = Sequence([])
