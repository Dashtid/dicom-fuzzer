"""Calibration Fuzzer - DICOM Measurement and Calibration Mutations.

Category: generic

Attacks:
- PixelSpacing zero, negative, extreme, NaN, mismatch with ImagerPixelSpacing
- RescaleSlope/Intercept zero, negative, extreme, NaN, infinity, HU overflow
- WindowCenter/Width zero, negative, extreme, NaN, conflicting presets
- SliceThickness zero, negative, extreme, mismatch with SpacingBetweenSlices
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)


class CalibrationFuzzer(FormatFuzzerBase):
    """Fuzzer for DICOM calibration and measurement-related tags.

    Targets calibration parameters that affect measurements, calculations,
    and display rendering in medical imaging applications.
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "calibration"

    def __init__(self) -> None:
        """Initialize CalibrationFuzzer."""
        super().__init__()

    def fuzz_pixel_spacing(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz PixelSpacing and related calibration tags."""
        if attack_type is None:
            attack_type = random.choice(
                [
                    "mismatch",
                    "zero",
                    "negative",
                    "extreme_small",
                    "extreme_large",
                    "nan",
                    "inconsistent",
                    "calibration_type",
                ]
            )

        if attack_type == "mismatch":
            dataset.PixelSpacing = [1.0, 1.0]
            dataset.ImagerPixelSpacing = [0.5, 0.5]

        elif attack_type == "zero":
            dataset.PixelSpacing = [0.0, 0.0]

        elif attack_type == "negative":
            dataset.PixelSpacing = [-1.0, -1.0]

        elif attack_type == "extreme_small":
            dataset.PixelSpacing = [1e-10, 1e-10]

        elif attack_type == "extreme_large":
            dataset.PixelSpacing = [1e10, 1e10]

        elif attack_type == "nan":
            dataset.PixelSpacing = [float("nan"), float("nan")]

        elif attack_type == "inconsistent":
            dataset.PixelSpacing = [0.1, 100.0]

        elif attack_type == "calibration_type":
            invalid_types = ["", "INVALID", "GEOMETRY" * 10, "\x00\x00"]
            dataset.PixelSpacingCalibrationType = random.choice(invalid_types)

        return dataset

    def fuzz_hounsfield_rescale(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz RescaleSlope and RescaleIntercept for CT HU calculations.

        The Hounsfield Unit formula is: HU = pixel_value * RescaleSlope + RescaleIntercept

        Attack types:
        - zero_slope: RescaleSlope = 0 (all pixels become intercept)
        - negative_slope: Inverts the scale
        - extreme_slope: Very large slope (overflow)
        - nan_slope: NaN slope
        - extreme_intercept: Push values out of valid HU range
        - inconsistent: Different rescale per slice

        Args:
            dataset: DICOM dataset to mutate
            attack_type: Specific attack (random if None)

        Returns:
            Mutated dataset

        """
        if attack_type is None:
            attack_type = random.choice(
                [
                    "zero_slope",
                    "negative_slope",
                    "extreme_slope",
                    "nan_slope",
                    "inf_slope",
                    "extreme_intercept",
                    "hu_overflow",
                ]
            )

        if attack_type == "zero_slope":
            # Zero slope - all pixels become intercept value
            dataset.RescaleSlope = 0.0

        elif attack_type == "negative_slope":
            # Negative slope - inverts the scale
            dataset.RescaleSlope = -1.0

        elif attack_type == "extreme_slope":
            # Very large slope - integer overflow when multiplied
            dataset.RescaleSlope = 1e15

        elif attack_type == "nan_slope":
            # NaN slope
            dataset.RescaleSlope = float("nan")

        elif attack_type == "inf_slope":
            # Infinity slope
            dataset.RescaleSlope = float("inf")

        elif attack_type == "extreme_intercept":
            # Extreme intercept - push HU values out of valid range
            # Valid HU range is typically -1024 to +3071
            extreme_values = [-1e10, 1e10, -32768, 32767, -2147483648]
            dataset.RescaleIntercept = random.choice(extreme_values)

        elif attack_type == "hu_overflow":
            # Combination that causes HU overflow
            # With 16-bit pixel data (0-65535) and slope 1e6, HU = 65535 * 1e6 = overflow
            dataset.RescaleSlope = 1e6
            dataset.RescaleIntercept = 1e10

        return dataset

    def fuzz_window_level(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz WindowCenter and WindowWidth for display rendering.

        Window/Level formula: displayed = (pixel - WindowCenter) / WindowWidth

        Attack types:
        - zero_width: WindowWidth = 0 (divide by zero)
        - negative_width: Negative window width
        - extreme_width: Very large/small width
        - extreme_center: Center far outside data range
        - nan_values: NaN center or width
        - multiple_windows: Conflicting multiple window settings

        Args:
            dataset: DICOM dataset to mutate
            attack_type: Specific attack (random if None)

        Returns:
            Mutated dataset

        """
        if attack_type is None:
            attack_type = random.choice(
                [
                    "zero_width",
                    "negative_width",
                    "extreme_width_small",
                    "extreme_width_large",
                    "extreme_center",
                    "nan_values",
                    "multiple_windows_conflict",
                ]
            )

        if attack_type == "zero_width":
            # Zero window width - divide by zero
            dataset.WindowWidth = 0

        elif attack_type == "negative_width":
            # Negative window width
            dataset.WindowWidth = -100

        elif attack_type == "extreme_width_small":
            # Very small window width
            dataset.WindowWidth = 0.0001

        elif attack_type == "extreme_width_large":
            # Very large window width
            dataset.WindowWidth = 1e10

        elif attack_type == "extreme_center":
            # Window center far outside data range
            extreme_centers = [-1e10, 1e10, -2147483648, 2147483647]
            dataset.WindowCenter = random.choice(extreme_centers)

        elif attack_type == "nan_values":
            # NaN window/level
            dataset.WindowCenter = float("nan")
            dataset.WindowWidth = float("nan")

        elif attack_type == "multiple_windows_conflict":
            # Multiple conflicting window presets
            dataset.WindowCenter = [100, -500, 40]  # Different centers
            dataset.WindowWidth = [400, 1500, 80]  # Different widths
            # Add conflicting explanations
            dataset.WindowCenterWidthExplanation = ["BONE", "LUNG", "BRAIN"]

        return dataset

    def fuzz_slice_thickness(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz SliceThickness and SpacingBetweenSlices.

        These affect volume calculations and 3D reconstruction.

        Attack types:
        - zero: Zero thickness (volume = 0)
        - negative: Negative thickness
        - mismatch: SliceThickness != SpacingBetweenSlices
        - extreme: Very large/small values

        Args:
            dataset: DICOM dataset to mutate
            attack_type: Specific attack (random if None)

        Returns:
            Mutated dataset

        """
        if attack_type is None:
            attack_type = random.choice(
                [
                    "zero",
                    "negative",
                    "mismatch",
                    "extreme_small",
                    "extreme_large",
                ]
            )

        if attack_type == "zero":
            dataset.SliceThickness = 0.0

        elif attack_type == "negative":
            dataset.SliceThickness = -5.0

        elif attack_type == "mismatch":
            # SliceThickness and SpacingBetweenSlices should typically match
            dataset.SliceThickness = 5.0
            dataset.SpacingBetweenSlices = 1.0  # 5x mismatch

        elif attack_type == "extreme_small":
            dataset.SliceThickness = 1e-10

        elif attack_type == "extreme_large":
            dataset.SliceThickness = 1e10

        return dataset

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply calibration mutations (FormatFuzzerBase interface).

        Always runs one structural attack (VR-type confusion or oversized DS
        string). Randomly adds one content attack (calibration value corruption)
        at 33% probability.
        """
        structural = [
            self._vr_type_confusion,
            self._oversized_numeric_string,
            self._voi_lut_corruption,
        ]
        content = [
            self.fuzz_pixel_spacing,  # [CONTENT] calibration values — rendering only
            self.fuzz_hounsfield_rescale,  # [CONTENT] HU slope/intercept — rendering only
            self.fuzz_window_level,  # [CONTENT] display window — rendering only
            self.fuzz_slice_thickness,  # [CONTENT] calibration value — rendering only
            self.fuzz_mr_parameters,  # [CONTENT] MR-specific acquisition parameters
            self.fuzz_dx_parameters,  # [CONTENT] DX/CR-specific exposure parameters
        ]

        selected = random.sample(structural, k=1)
        if random.random() < 0.33:
            selected.append(random.choice(content))

        applied: list[str] = []
        for attack in selected:
            try:
                dataset = attack(dataset)
                applied.append(attack.__name__)
            except Exception as e:
                logger.debug("Calibration %s failed: %s", attack.__name__, e)
        self.last_variant = ",".join(applied) if applied else None

        return dataset

    def _vr_type_confusion(self, dataset: Dataset) -> Dataset:
        """Replace a DS-VR calibration field with a Sequence object.

        PixelSpacing is declared DS (Decimal String). Replacing it with a
        pydicom Sequence causes VR-dispatch paths in parsers to attempt reading
        a sequence structure as a decimal string — wrong-type allocation or an
        illegal memory access.
        """
        try:
            item = Dataset()
            item.PixelSpacing = [1.0, 1.0]
            dataset.PixelSpacing = Sequence([item])
        except Exception as e:
            logger.debug("VR type confusion attack failed: %s", e)
        return dataset

    def _oversized_numeric_string(self, dataset: Dataset) -> Dataset:
        """Set a DS-VR field to a string far exceeding the 16-byte DS maximum.

        DS (Decimal String) VR has a declared maximum of 16 bytes per value
        component. VR copy routines that allocate based on the declared maximum
        will overflow when presented with a value thousands of times larger.
        """
        # 100 KB string — 6250x the DS 16-byte maximum
        oversized = "1." + "2" * 102400
        tag = random.choice(["SliceThickness", "SpacingBetweenSlices", "RescaleSlope"])
        try:
            setattr(dataset, tag, oversized)
        except Exception as e:
            logger.debug("Oversized numeric string attack failed: %s", e)
        return dataset

    def _voi_lut_corruption(self, dataset: Dataset) -> Dataset:
        """Add a VOI LUT Sequence with type-confused or mismatched entries.

        DCMTK CVE-2024-28130 (TALOS-2024-1957, CVSS 7.5): incorrect type
        conversion in DVPSSoftcopyVOI_PList::createFromImage(). fo-dicom
        #1062: VOI LUT Sequence without Modality LUT causes
        IndexOutOfRangeException in VOISequenceLUT indexer.

        Attacks:
        - VOI LUT descriptor claiming more entries than data provides
        - VOI LUT data with wrong VR (OW instead of expected US/SS)
        - VOI LUT Sequence present without any Modality LUT
        """
        attack = random.choice(
            [
                "descriptor_mismatch",
                "missing_modality_lut",
                "type_confused_data",
            ]
        )

        try:
            lut_item = Dataset()
            if attack == "descriptor_mismatch":
                # Descriptor says 4096 entries but data has only 16 bytes
                lut_item.add_new(0x00283002, "US", [4096, 0, 16])  # LUTDescriptor
                lut_item.add_new(0x00283006, "OW", b"\x00" * 16)  # LUTData
            elif attack == "missing_modality_lut":
                # Valid-looking VOI LUT but no RescaleSlope/Intercept
                lut_item.add_new(0x00283002, "US", [256, 0, 8])
                lut_item.add_new(0x00283006, "OW", b"\x00" * 512)
                # Explicitly remove modality LUT if present
                for tag_name in ("RescaleSlope", "RescaleIntercept", "RescaleType"):
                    if hasattr(dataset, tag_name):
                        delattr(dataset, tag_name)
            elif attack == "type_confused_data":
                # LUT descriptor declares 16-bit entries but data is 8-bit garbage
                lut_item.add_new(0x00283002, "US", [256, 0, 16])
                lut_item.add_new(
                    0x00283006, "OW", b"\xff" * 128
                )  # half the expected size

            lut_item.LUTExplanation = "FUZZER_VOI"
            dataset.VOILUTSequence = Sequence([lut_item])

        except Exception as e:
            logger.debug("VOI LUT corruption failed: %s", e)
        return dataset

    def fuzz_mr_parameters(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz MR-specific acquisition parameters.

        Targets numeric fields that MR processing pipelines use for
        sequence timing, flip angle calculations, and diffusion
        weighting. Zero/negative/extreme values cause division-by-zero
        in timing calculations and NaN propagation in derived values.
        """
        if attack_type is None:
            attack_type = random.choice(
                [
                    "zero_echo_time",
                    "negative_repetition_time",
                    "extreme_flip_angle",
                    "nan_inversion_time",
                    "zero_magnetic_field",
                    "extreme_diffusion",
                ]
            )

        if attack_type == "zero_echo_time":
            dataset.EchoTime = 0.0
        elif attack_type == "negative_repetition_time":
            dataset.RepetitionTime = -1.0
        elif attack_type == "extreme_flip_angle":
            dataset.FlipAngle = random.choice([0.0, -90.0, 360.0, 99999.0])
        elif attack_type == "nan_inversion_time":
            dataset.InversionTime = float("nan")
        elif attack_type == "zero_magnetic_field":
            dataset.MagneticFieldStrength = 0.0
        elif attack_type == "extreme_diffusion":
            dataset.add_new(0x00189087, "FD", random.choice([0.0, -1.0, 1e15]))

        return dataset

    def fuzz_dx_parameters(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz DX/CR-specific exposure and geometry parameters.

        Targets numeric fields in radiographic acquisition that
        processing pipelines use for dose calculations, geometric
        magnification, and image quality metrics.
        """
        if attack_type is None:
            attack_type = random.choice(
                [
                    "zero_exposure",
                    "negative_kvp",
                    "extreme_distance",
                    "zero_exposure_time",
                    "nan_exposure",
                ]
            )

        if attack_type == "zero_exposure":
            dataset.ExposureInuAs = 0
        elif attack_type == "negative_kvp":
            dataset.KVP = random.choice([-1.0, 0.0, 999.0])
        elif attack_type == "extreme_distance":
            dataset.DistanceSourceToDetector = random.choice([0.0, -100.0, 1e10])
        elif attack_type == "zero_exposure_time":
            dataset.ExposureTime = 0
        elif attack_type == "nan_exposure":
            dataset.ExposureInuAs = random.choice([0, -1, 2147483647])

        return dataset
