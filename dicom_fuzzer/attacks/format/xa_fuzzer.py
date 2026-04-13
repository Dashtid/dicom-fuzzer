"""X-Ray Angiography Fuzzer - DICOM XA/XRF Image Mutations.

Category: structural

Targets X-Ray Angiographic (XA) and Digital Subtraction Angiography (DSA)
DICOM objects by corrupting radiation dose metadata, positioner angles,
source-to-detector geometry, CINE frame declarations, and mask subtraction
references.

Attack surface rationale:
  XA parsers use DistanceSourceToDetector for magnification, KVP for
  dose calculations, CineRate for playback, and PositionerAngle for
  display orientation. Parsers that trust these fields without range
  validation are vulnerable to divide-by-zero (distance=0), overflow
  (KVP=999999), and out-of-bounds frame references (DSA mask frame).

Dataset-level attacks:
- cine_frame_count_overflow: NumberOfFrames >> PixelData (OOB in CINE iterator)
- cine_rate_zero: CineRate = 0 (divide-by-zero in FPS / playback timing)
- positioner_angle_overflow: PositionerPrimaryAngle = 999.9 (out of -180..+180)
- source_detector_distance_zero: DistanceSourceToDetector = 0 (div-zero in magnification)
- source_patient_distance_negative: DistanceSourceToPatient = -1.0 (sign error)
- kvp_overflow: KVP = 999999 (far beyond typical 60-125 kV XA range)
- exposure_time_overflow: ExposureTime = 2147483647 (INT32_MAX microseconds)
- mask_subtraction_bad_frame: MaskSubtractionSequence references nonexistent frame
- no_pixel_data: XA SOPClassUID + CINE geometry but no PixelData
- imager_pixel_spacing_zero: ImagerPixelSpacing = [0, 0] (div-zero in measurements)
- pixel_intensity_log_linear_mismatch: PixelIntensityRelationship=LOG with linear window
- frame_increment_ptr_mismatch: FrameIncrementPointer -> tag absent from dataset
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# X-Ray Angiography SOP Class UIDs
_XA_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.12.1",  # X-Ray Angiographic Image Storage
        "1.2.840.10008.5.1.4.1.1.12.2",  # X-Ray Radiofluoroscopic Image Storage
        "1.2.840.10008.5.1.4.1.1.12.1.1",  # Enhanced XA Image Storage
        "1.2.840.10008.5.1.4.1.1.12.2.1",  # Enhanced XRF Image Storage
    }
)

# Minimal 8-bit greyscale pixel data (2x2 pixels)
_MINIMAL_PIXEL_DATA = bytes([0x10, 0x40, 0x80, 0xC0])


def _build_minimal_xa_dataset(n_frames: int = 10) -> Dataset:
    """Return a minimal well-formed XA CINE dataset."""
    ds = Dataset()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.12.1"
    ds.Modality = "XA"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.NumberOfFrames = n_frames
    ds.CineRate = 15
    ds.FrameTime = "66.7"  # ms per frame (15 fps)
    ds.FrameIncrementPointer = 0x00181063  # FrameTime tag
    ds.KVP = "80"
    ds.ExposureTime = 10  # ms
    ds.XRayTubeCurrent = 200  # mA
    ds.DistanceSourceToDetector = 1000.0  # mm
    ds.DistanceSourceToPatient = 700.0  # mm
    ds.ImagerPixelSpacing = [0.2, 0.2]  # mm/pixel
    ds.PositionerPrimaryAngle = 0.0
    ds.PositionerSecondaryAngle = 0.0
    ds.PixelIntensityRelationship = "LOG"
    ds.PixelData = _MINIMAL_PIXEL_DATA * n_frames
    return ds


class XRayAngiographyFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM X-Ray Angiography and fluoroscopy image objects.

    Targets XA parsers through radiation dose parameter violations,
    positioner angle overflow, geometry zero values, and DSA mask frame
    reference errors.
    """

    def __init__(self) -> None:
        """Initialize XA fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "xray_angiography"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for XA/XRF datasets."""
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        if sop_class in _XA_SOP_CLASSES:
            return True
        modality = str(getattr(dataset, "Modality", ""))
        if modality in ("XA", "RF"):
            return True
        # Accept datasets with XA-specific geometry tags
        return hasattr(dataset, "DistanceSourceToDetector") and hasattr(
            dataset, "CineRate"
        )

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply XA mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._cine_frame_count_overflow,
            self._cine_rate_zero,
            self._positioner_angle_overflow,
            self._source_detector_distance_zero,
            self._source_patient_distance_negative,
            self._kvp_overflow,
            self._exposure_time_overflow,
            self._mask_subtraction_bad_frame,
            self._no_pixel_data,
            self._imager_pixel_spacing_zero,
            self._pixel_intensity_log_linear_mismatch,
            self._frame_increment_ptr_mismatch,
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

    def _ensure_xa_root(self, dataset: Dataset) -> None:
        """Ensure dataset has XA SOPClassUID and minimal attributes."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.12.1"
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
            dataset.NumberOfFrames = 10

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _cine_frame_count_overflow(self, dataset: Dataset) -> None:
        """NumberOfFrames >> PixelData length (OOB read in CINE frame iterator)."""
        self._ensure_xa_root(dataset)
        dataset.NumberOfFrames = 0xFFFF  # 65535 declared frames
        dataset.PixelData = _MINIMAL_PIXEL_DATA  # only 4 bytes

    def _cine_rate_zero(self, dataset: Dataset) -> None:
        """CineRate = 0 (divide-by-zero in frame timing and playback FPS calc)."""
        self._ensure_xa_root(dataset)
        dataset.CineRate = 0
        dataset.FrameTime = "0"  # also zero frame time

    def _positioner_angle_overflow(self, dataset: Dataset) -> None:
        """PositionerPrimaryAngle = 999.9 (out of valid -180..+180 range)."""
        self._ensure_xa_root(dataset)
        dataset.PositionerPrimaryAngle = 999.9
        dataset.PositionerSecondaryAngle = -999.9

    def _source_detector_distance_zero(self, dataset: Dataset) -> None:
        """DistanceSourceToDetector = 0 (divide-by-zero in magnification factor)."""
        self._ensure_xa_root(dataset)
        dataset.DistanceSourceToDetector = 0.0

    def _source_patient_distance_negative(self, dataset: Dataset) -> None:
        """DistanceSourceToPatient = -1.0 (sign error in geometry calculation)."""
        self._ensure_xa_root(dataset)
        dataset.DistanceSourceToPatient = -1.0

    def _kvp_overflow(self, dataset: Dataset) -> None:
        """KVP = 999999 (far beyond 60-125 kV typical XA range)."""
        self._ensure_xa_root(dataset)
        dataset.KVP = "999999"

    def _exposure_time_overflow(self, dataset: Dataset) -> None:
        """ExposureTime = 2^31-1 (INT32_MAX ms -- overflow in dose accumulation)."""
        self._ensure_xa_root(dataset)
        dataset.ExposureTime = 2147483647  # INT32_MAX

    def _mask_subtraction_bad_frame(self, dataset: Dataset) -> None:
        """MaskSubtractionSequence references frame 9999 (nonexistent frame OOB)."""
        self._ensure_xa_root(dataset)
        dataset.NumberOfFrames = 10
        dataset.PixelData = _MINIMAL_PIXEL_DATA * 10
        mask_item = Dataset()
        mask_item.MaskOperation = "AVG_SUB"
        mask_item.ApplicableFrameRange = [1, 10]
        # SubtractionItemID pointing to far-out-of-range frame
        mask_item.MaskFrameNumbers = [9999]  # frame 9999 of 10 total
        dataset.MaskSubtractionSequence = Sequence([mask_item])

    def _no_pixel_data(self, dataset: Dataset) -> None:
        """XA SOPClassUID + CINE geometry but no PixelData (NULL deref in render)."""
        dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.12.1"
        dataset.Modality = "XA"
        dataset.Rows = 512
        dataset.Columns = 512
        dataset.NumberOfFrames = 50
        dataset.CineRate = 15
        if hasattr(dataset, "PixelData"):
            del dataset.PixelData

    def _imager_pixel_spacing_zero(self, dataset: Dataset) -> None:
        """ImagerPixelSpacing = [0, 0] (divide-by-zero in physical measurement calc)."""
        self._ensure_xa_root(dataset)
        dataset.ImagerPixelSpacing = [0.0, 0.0]

    def _pixel_intensity_log_linear_mismatch(self, dataset: Dataset) -> None:
        """PixelIntensityRelationship=LOG with linear WindowCenter/Width (LUT mismatch)."""
        self._ensure_xa_root(dataset)
        dataset.PixelIntensityRelationship = "LOG"
        dataset.PixelIntensityRelationshipSign = 1
        # Linear window applied to LOG-encoded pixels -- decoding will be wrong
        dataset.WindowCenter = 128
        dataset.WindowWidth = 256

    def _frame_increment_ptr_mismatch(self, dataset: Dataset) -> None:
        """FrameIncrementPointer -> tag absent from dataset (tag lookup returns NULL)."""
        self._ensure_xa_root(dataset)
        # Point to FrameReferenceDateTime (0008,9007) -- not present in this dataset
        dataset.FrameIncrementPointer = 0x00089007
