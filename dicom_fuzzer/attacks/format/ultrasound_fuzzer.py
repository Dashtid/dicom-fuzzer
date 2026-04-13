"""Ultrasound Fuzzer - DICOM US Image and Multi-frame Mutations.

Category: structural

Targets Ultrasound (US) DICOM objects by corrupting the pixel geometry,
Doppler region metadata, SequenceOfUltrasoundRegions, and multi-frame
frame-count declarations.

Attack surface rationale:
  US parsers map pixel data into display using per-region coordinate
  transformations (PhysicalDeltaX/Y) and frame count metadata.
  When region coordinates overlap, frame counts differ from pixel data
  length, or Doppler scaling values are NaN/Inf, parsers that trust
  these fields without validation are vulnerable to out-of-bounds reads,
  divide-by-zero, and floating-point propagation bugs.

Dataset-level attacks:
- frame_count_overflow: NumberOfFrames >> actual PixelData byte length
- frame_count_zero: NumberOfFrames = 0 (deref first frame without guard)
- region_overlap: two US regions with identical bounding box (Z-order crash)
- region_missing_coords: SequenceOfUltrasoundRegions item with no coordinates
- doppler_nan: PhysicalDeltaX / PhysicalDeltaY = NaN
- doppler_negative: PhysicalDeltaX = -1.0 (negative pixel spacing)
- frame_increment_ptr_bad: FrameIncrementPointer -> nonexistent tag
- no_pixel_data: US SOP class with SOPClassUID but no PixelData
- bits_alloc_mismatch: BitsAllocated=16 / BitsStored=12 / HighBit=7 (inconsistent)
- photometric_mismatch: PhotometricInterpretation=RGB with SamplesPerPixel=1
- cine_rate_zero: RecommendedDisplayFrameRate = 0 (divide-by-zero in FPS calc)
- empty_region_sequence: SequenceOfUltrasoundRegions exists with zero items
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Ultrasound SOP Class UIDs (for can_mutate check)
_US_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.6.1",  # Ultrasound Image Storage
        "1.2.840.10008.5.1.4.1.1.3.1",  # Ultrasound Multi-frame Image Storage
        "1.2.840.10008.5.1.4.1.1.6.2",  # Enhanced US Volume Storage
    }
)

# Minimal single-frame greyscale pixel data (2x2 pixels, 8-bit)
_MINIMAL_PIXEL_DATA = bytes([0x00, 0x80, 0x40, 0xC0])


def _build_us_region(
    x0: int = 0,
    y0: int = 0,
    x1: int = 100,
    y1: int = 100,
    spatial_fmt: int = 1,  # 1 = 2D
    data_type: int = 1,  # 1 = Tissue
) -> Dataset:
    """Return a minimal SequenceOfUltrasoundRegions item."""
    r = Dataset()
    r.RegionSpatialFormat = spatial_fmt
    r.RegionDataType = data_type
    r.RegionFlags = 0
    r.RegionLocationMinX0 = x0
    r.RegionLocationMinY0 = y0
    r.RegionLocationMaxX1 = x1
    r.RegionLocationMaxY1 = y1
    r.PhysicalUnitsXDirection = 3  # cm
    r.PhysicalUnitsYDirection = 3  # cm
    r.PhysicalDeltaX = 0.1
    r.PhysicalDeltaY = 0.1
    r.ReferencePixelX0 = x0
    r.ReferencePixelY0 = y0
    return r


def _build_minimal_us_dataset(n_frames: int = 1) -> Dataset:
    """Return a minimal well-formed US multi-frame dataset."""
    ds = Dataset()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.3.1"
    ds.Modality = "US"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = n_frames
    # Frame time list (one value per frame, microseconds)
    ds.FrameTimeVector = [33] * n_frames
    ds.FrameIncrementPointer = 0x00181065  # FrameTimeVector tag
    ds.PixelData = _MINIMAL_PIXEL_DATA * n_frames
    ds.SequenceOfUltrasoundRegions = Sequence([_build_us_region()])
    return ds


class UltrasoundFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Ultrasound image objects.

    Targets US parsers through frame-count mismatches, Doppler region
    metadata corruption, and pixel geometry violations.
    """

    def __init__(self) -> None:
        """Initialize US fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "ultrasound"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for US datasets or datasets with US region tags."""
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        if sop_class in _US_SOP_CLASSES:
            return True
        if hasattr(dataset, "SequenceOfUltrasoundRegions"):
            return True
        # Also accept Modality = US even without SOPClassUID
        return str(getattr(dataset, "Modality", "")) == "US"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply US mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._frame_count_overflow,
            self._frame_count_zero,
            self._region_overlap,
            self._region_missing_coords,
            self._doppler_nan,
            self._doppler_negative,
            self._frame_increment_ptr_bad,
            self._no_pixel_data,
            self._bits_alloc_mismatch,
            self._photometric_mismatch,
            self._cine_rate_zero,
            self._empty_region_sequence,
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

    def _ensure_us_root(self, dataset: Dataset) -> None:
        """Ensure dataset has US SOPClassUID and minimal pixel geometry."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.3.1"
        if not hasattr(dataset, "Rows"):
            dataset.Rows = 2
            dataset.Columns = 2
        if not hasattr(dataset, "BitsAllocated"):
            dataset.BitsAllocated = 8
            dataset.BitsStored = 8
            dataset.HighBit = 7
        if not hasattr(dataset, "PixelData"):
            dataset.PixelData = _MINIMAL_PIXEL_DATA
        if not hasattr(dataset, "NumberOfFrames"):
            dataset.NumberOfFrames = 1

    def _ensure_region_seq(self, dataset: Dataset) -> None:
        """Ensure dataset has a SequenceOfUltrasoundRegions."""
        self._ensure_us_root(dataset)
        if not hasattr(dataset, "SequenceOfUltrasoundRegions"):
            dataset.SequenceOfUltrasoundRegions = Sequence([_build_us_region()])

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _frame_count_overflow(self, dataset: Dataset) -> None:
        """NumberOfFrames >> actual PixelData size (OOB read in frame iterator)."""
        self._ensure_us_root(dataset)
        # Declare 2^24 frames; keep actual PixelData tiny (4 bytes)
        dataset.NumberOfFrames = 0xFFFFFF
        dataset.PixelData = _MINIMAL_PIXEL_DATA  # far less than declared

    def _frame_count_zero(self, dataset: Dataset) -> None:
        """NumberOfFrames = 0 (NULL deref if first frame is assumed to exist)."""
        self._ensure_us_root(dataset)
        dataset.NumberOfFrames = 0
        # PixelData is non-empty; parsers that read frame 0 without a guard crash
        dataset.PixelData = _MINIMAL_PIXEL_DATA

    def _region_overlap(self, dataset: Dataset) -> None:
        """Two US regions with identical bounding box (Z-order / dedupe crash)."""
        self._ensure_us_root(dataset)
        region_a = _build_us_region(x0=0, y0=0, x1=100, y1=100)
        region_b = _build_us_region(x0=0, y0=0, x1=100, y1=100)  # identical
        region_b.RegionDataType = 2  # different type -- same coords
        dataset.SequenceOfUltrasoundRegions = Sequence([region_a, region_b])

    def _region_missing_coords(self, dataset: Dataset) -> None:
        """US region item with no bounding box coordinates (NULL deref on region render)."""
        self._ensure_us_root(dataset)
        bad_region = Dataset()
        bad_region.RegionSpatialFormat = 1
        bad_region.RegionDataType = 1
        bad_region.RegionFlags = 0
        # Deliberately omit RegionLocationMinX0, Y0, MaxX1, Y1
        bad_region.PhysicalDeltaX = 0.1
        bad_region.PhysicalDeltaY = 0.1
        dataset.SequenceOfUltrasoundRegions = Sequence([bad_region])

    def _doppler_nan(self, dataset: Dataset) -> None:
        """PhysicalDeltaX/Y = NaN (NaN propagation in pixel-to-physical transform)."""
        self._ensure_region_seq(dataset)
        region = dataset.SequenceOfUltrasoundRegions[0]
        region.PhysicalDeltaX = float("nan")
        region.PhysicalDeltaY = float("nan")

    def _doppler_negative(self, dataset: Dataset) -> None:
        """PhysicalDeltaX = -1.0 (negative pixel spacing -- sign error in transform)."""
        self._ensure_region_seq(dataset)
        region = dataset.SequenceOfUltrasoundRegions[0]
        region.PhysicalDeltaX = -1.0
        region.PhysicalDeltaY = -1.0

    def _frame_increment_ptr_bad(self, dataset: Dataset) -> None:
        """FrameIncrementPointer pointing to a nonexistent tag (tag lookup crash)."""
        self._ensure_us_root(dataset)
        # Use a private/non-existent tag group as the pointer value
        # 0x99990001 -- clearly not a standard DICOM attribute
        dataset.FrameIncrementPointer = 0x99990001

    def _no_pixel_data(self, dataset: Dataset) -> None:
        """US SOPClassUID present but no PixelData (NULL deref in render pipeline)."""
        dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.3.1"
        dataset.Modality = "US"
        dataset.Rows = 512
        dataset.Columns = 512
        dataset.NumberOfFrames = 10
        if hasattr(dataset, "PixelData"):
            del dataset.PixelData

    def _bits_alloc_mismatch(self, dataset: Dataset) -> None:
        """BitsAllocated=16 / BitsStored=12 / HighBit=7 -- inconsistent bit geometry."""
        self._ensure_us_root(dataset)
        dataset.BitsAllocated = 16
        dataset.BitsStored = 12
        dataset.HighBit = 7  # HighBit should be BitsStored-1=11, not 7
        # Pixel data is still 8-bit length (too short for 16-bit)
        dataset.PixelData = _MINIMAL_PIXEL_DATA

    def _photometric_mismatch(self, dataset: Dataset) -> None:
        """PhotometricInterpretation=RGB with SamplesPerPixel=1 (channel count mismatch)."""
        self._ensure_us_root(dataset)
        dataset.PhotometricInterpretation = "RGB"
        dataset.SamplesPerPixel = 1  # RGB requires 3

    def _cine_rate_zero(self, dataset: Dataset) -> None:
        """RecommendedDisplayFrameRate = 0 (divide-by-zero in frame timing calc)."""
        self._ensure_us_root(dataset)
        dataset.NumberOfFrames = 10
        dataset.RecommendedDisplayFrameRate = 0
        dataset.PixelData = _MINIMAL_PIXEL_DATA * 10

    def _empty_region_sequence(self, dataset: Dataset) -> None:
        """SequenceOfUltrasoundRegions exists with zero items (first-element deref)."""
        self._ensure_us_root(dataset)
        dataset.SequenceOfUltrasoundRegions = Sequence([])  # tag present, no items
