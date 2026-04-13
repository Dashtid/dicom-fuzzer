"""Mammography Fuzzer - DICOM MG/DBT Image Mutations.

Category: structural

Targets Digital Mammography (MG) and Digital Breast Tomosynthesis (DBT)
DICOM objects by corrupting breast geometry metadata, pixel calibration
parameters, and multi-frame frame-count declarations.

Attack surface rationale:
  Mammography parsers use BodyPartThickness for compression calibration,
  ImagerPixelSpacing for physical measurements, and PhotometricInterpretation
  to determine inversion (MONOCHROME1 = white-is-zero, inverted).
  Parsers that trust these fields without range validation are vulnerable
  to divide-by-zero (thickness=0), NaN propagation (pixel spacing),
  and frame-count OOB reads (DBT tomosynthesis volumes).

Dataset-level attacks:
- breast_thickness_zero: BodyPartThickness = 0 (div-by-zero in calibration)
- breast_thickness_negative: BodyPartThickness = -10.0 (sign error in range)
- photometric_monochrome1_rgb: MONOCHROME1 with SamplesPerPixel=3 (channel mismatch)
- imager_pixel_spacing_mismatch: ImagerPixelSpacing != PixelSpacing (calibration confusion)
- imager_pixel_spacing_nan: ImagerPixelSpacing = NaN (NaN propagation)
- dbt_frame_count_overflow: DBT NumberOfFrames >> PixelData (OOB read)
- view_code_empty: ViewCodeSequence present but empty (NULL deref on view lookup)
- no_pixel_data: MG SOPClassUID + geometry but no PixelData
- compression_force_negative: CompressionForce = -1.0 (negative force)
- kvp_overflow: KVP = 999999 (far beyond typical 20-50 kV range)
- window_width_zero: WindowWidth = 0 (div-by-zero in LUT normalization)
- partial_view_no_description: PartialView=YES with no PartialViewDescription
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Mammography and Breast Tomosynthesis SOP Class UIDs
_MG_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.1.2",  # Digital Mammography X-Ray - For Presentation
        "1.2.840.10008.5.1.4.1.1.1.2.1",  # Digital Mammography X-Ray - For Processing
        "1.2.840.10008.5.1.4.1.1.13.1.3",  # Breast Tomosynthesis Image Storage
        "1.2.840.10008.5.1.4.1.1.13.1.4",  # Breast Projection X-Ray - For Presentation
        "1.2.840.10008.5.1.4.1.1.13.1.5",  # Breast Projection X-Ray - For Processing
    }
)

# Minimal greyscale pixel data (2x2 pixels, 16-bit LE)
_MINIMAL_PIXEL_DATA_16 = bytes([0x00, 0x01, 0x80, 0x01, 0x40, 0x01, 0xC0, 0x01])


def _build_minimal_mg_dataset() -> Dataset:
    """Return a minimal well-formed MG dataset."""
    ds = Dataset()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.1.2"
    ds.Modality = "MG"
    ds.Rows = 2
    ds.Columns = 2
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME1"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.BodyPartThickness = 50.0  # mm
    ds.CompressionForce = 120.0  # N
    ds.KVP = "28"
    ds.ImagerPixelSpacing = [0.1, 0.1]  # mm/pixel
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


class MammographyFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Mammography and Breast Tomosynthesis objects.

    Targets MG parsers through breast geometry metadata corruption,
    pixel calibration parameter violations, and DBT frame-count mismatches.
    """

    def __init__(self) -> None:
        """Initialize MG fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "mammography"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for MG/DBT datasets."""
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        if sop_class in _MG_SOP_CLASSES:
            return True
        if str(getattr(dataset, "Modality", "")) == "MG":
            return True
        return hasattr(dataset, "BodyPartThickness") and hasattr(
            dataset, "CompressionForce"
        )

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply MG mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._breast_thickness_zero,
            self._breast_thickness_negative,
            self._photometric_monochrome1_rgb,
            self._imager_pixel_spacing_mismatch,
            self._imager_pixel_spacing_nan,
            self._dbt_frame_count_overflow,
            self._view_code_empty,
            self._no_pixel_data,
            self._compression_force_negative,
            self._kvp_overflow,
            self._window_width_zero,
            self._partial_view_no_description,
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

    def _ensure_mg_root(self, dataset: Dataset) -> None:
        """Ensure dataset has MG SOPClassUID and minimal attributes."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.1.2"
        if not hasattr(dataset, "Rows"):
            dataset.Rows = 2
            dataset.Columns = 2
        if not hasattr(dataset, "BitsAllocated"):
            dataset.BitsAllocated = 16
            dataset.BitsStored = 12
            dataset.HighBit = 11
        if not hasattr(dataset, "PixelData"):
            dataset.PixelData = _MINIMAL_PIXEL_DATA_16
        if not hasattr(dataset, "WindowCenter"):
            dataset.WindowCenter = 2048
            dataset.WindowWidth = 1024

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _breast_thickness_zero(self, dataset: Dataset) -> None:
        """BodyPartThickness = 0 (divide-by-zero in compression calibration)."""
        self._ensure_mg_root(dataset)
        dataset.BodyPartThickness = 0

    def _breast_thickness_negative(self, dataset: Dataset) -> None:
        """BodyPartThickness = -10.0 (sign error in physical range checks)."""
        self._ensure_mg_root(dataset)
        dataset.BodyPartThickness = -10.0

    def _photometric_monochrome1_rgb(self, dataset: Dataset) -> None:
        """PhotometricInterpretation=MONOCHROME1 with SamplesPerPixel=3 (channel mismatch)."""
        self._ensure_mg_root(dataset)
        dataset.PhotometricInterpretation = "MONOCHROME1"
        dataset.SamplesPerPixel = 3  # MONOCHROME1 requires 1

    def _imager_pixel_spacing_mismatch(self, dataset: Dataset) -> None:
        """ImagerPixelSpacing != PixelSpacing (calibration confusion for measurements)."""
        self._ensure_mg_root(dataset)
        dataset.ImagerPixelSpacing = [0.1, 0.1]
        dataset.PixelSpacing = [0.5, 0.5]  # diverges from imager spacing

    def _imager_pixel_spacing_nan(self, dataset: Dataset) -> None:
        """ImagerPixelSpacing = NaN (NaN propagation in pixel-to-mm transform)."""
        self._ensure_mg_root(dataset)
        dataset.ImagerPixelSpacing = [float("nan"), float("nan")]

    def _dbt_frame_count_overflow(self, dataset: Dataset) -> None:
        """DBT NumberOfFrames >> PixelData (OOB read in tomosynthesis frame iterator)."""
        self._ensure_mg_root(dataset)
        dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.13.1.3"  # DBT SOP
        dataset.NumberOfFrames = 0xFFFF  # 65535 slices declared
        dataset.PixelData = _MINIMAL_PIXEL_DATA_16  # only 8 bytes

    def _view_code_empty(self, dataset: Dataset) -> None:
        """ViewCodeSequence present but empty (NULL deref on view label lookup)."""
        self._ensure_mg_root(dataset)
        dataset.ViewCodeSequence = Sequence([])

    def _no_pixel_data(self, dataset: Dataset) -> None:
        """MG SOPClassUID + geometry but no PixelData (NULL deref in render pipeline)."""
        dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.1.2"
        dataset.Modality = "MG"
        dataset.Rows = 3328
        dataset.Columns = 2560
        dataset.BitsAllocated = 16
        if hasattr(dataset, "PixelData"):
            del dataset.PixelData

    def _compression_force_negative(self, dataset: Dataset) -> None:
        """CompressionForce = -1.0 (negative force -- sign error in range check)."""
        self._ensure_mg_root(dataset)
        dataset.CompressionForce = -1.0

    def _kvp_overflow(self, dataset: Dataset) -> None:
        """KVP = 999999 (far beyond typical 20-50 kV range for MG)."""
        self._ensure_mg_root(dataset)
        dataset.KVP = "999999"

    def _window_width_zero(self, dataset: Dataset) -> None:
        """WindowWidth = 0 (divide-by-zero in LUT normalization: pixel / width)."""
        self._ensure_mg_root(dataset)
        dataset.WindowCenter = 2048
        dataset.WindowWidth = 0

    def _partial_view_no_description(self, dataset: Dataset) -> None:
        """PartialView=YES with no PartialViewDescription (missing required attribute)."""
        self._ensure_mg_root(dataset)
        dataset.PartialView = "YES"
        # Deliberately omit PartialViewDescription and PartialViewCodeSequence
        if hasattr(dataset, "PartialViewDescription"):
            del dataset.PartialViewDescription
