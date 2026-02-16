"""Calibration and Measurement Fuzzing Strategies.

Category: generic

This module provides CalibrationFuzzer for targeting measurement and calibration
vulnerabilities in DICOM viewers and analysis applications.

MUTATION CATEGORIES:
1. PixelSpacing Attacks - Corrupt distance measurements
2. Hounsfield Unit Attacks - Corrupt density/intensity calculations
3. Window/Level Attacks - Corrupt display and visibility
4. Calibration Consistency - Cross-slice calibration mismatches

SECURITY RATIONALE:
Medical imaging applications rely on calibration data for:
- Distance and area measurements
- Volume calculations
- Density analysis (CT Hounsfield units)
- SUV calculations (PET)
- Treatment planning doses

Incorrect calibration can lead to:
- Misdiagnosis from wrong measurements
- Treatment planning errors
- Crashes from divide-by-zero or overflow
- Display corruption

USAGE:
    fuzzer = CalibrationFuzzer(severity="aggressive")
    fuzzed_ds = fuzzer.fuzz_pixel_spacing(dataset)
    fuzzed_ds = fuzzer.fuzz_hounsfield_rescale(dataset)
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset

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

    def __init__(self, severity: str = "moderate", seed: int | None = None):
        """Initialize CalibrationFuzzer.

        Args:
            severity: Mutation severity (minimal, moderate, aggressive, extreme)
            seed: Random seed for reproducibility

        """
        super().__init__()
        if severity not in ["minimal", "moderate", "aggressive", "extreme"]:
            raise ValueError(f"Invalid severity: {severity}")

        self.severity = severity
        self.seed = seed
        if seed is not None:
            random.seed(seed)

        logger.info(f"CalibrationFuzzer initialized (severity={severity})")

    # --- PixelSpacing Attack Handlers ---

    def _ps_mismatch(self, dataset: Dataset) -> bool:
        """PixelSpacing different from ImagerPixelSpacing."""
        if not hasattr(dataset, "PixelSpacing"):
            return False
        dataset.PixelSpacing = [1.0, 1.0]
        dataset.ImagerPixelSpacing = [0.5, 0.5]
        return True

    def _ps_simple(self, dataset: Dataset, value: list[float]) -> bool:
        """Apply simple PixelSpacing mutation."""
        if not hasattr(dataset, "PixelSpacing"):
            return False
        dataset.PixelSpacing = value
        return True

    def _ps_calibration_type(self, dataset: Dataset) -> None:
        """Invalid calibration type."""
        invalid_types = ["", "INVALID", "GEOMETRY" * 10, "\x00\x00"]
        dataset.PixelSpacingCalibrationType = random.choice(invalid_types)

    # Attack type specifications: (value, display_string)
    _PS_SIMPLE_ATTACKS: dict[str, tuple[list[float], str]] = {
        "zero": ([0.0, 0.0], "[0.0, 0.0]"),
        "negative": ([-1.0, -1.0], "[-1.0, -1.0]"),
        "extreme_small": ([1e-10, 1e-10], "[1e-10, 1e-10]"),
        "extreme_large": ([1e10, 1e10], "[1e10, 1e10]"),
        "nan": ([float("nan"), float("nan")], "[NaN, NaN]"),
        "inconsistent": ([0.1, 100.0], "[0.1, 100.0] (1000:1 ratio)"),
    }

    _PS_ATTACK_TYPES = [
        "mismatch",
        "zero",
        "negative",
        "extreme_small",
        "extreme_large",
        "nan",
        "inconsistent",
        "calibration_type",
    ]

    def fuzz_pixel_spacing(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> Dataset:
        """Fuzz PixelSpacing and related calibration tags."""
        if attack_type is None:
            attack_type = random.choice(self._PS_ATTACK_TYPES)

        if attack_type == "mismatch":
            self._ps_mismatch(dataset)
        elif attack_type == "calibration_type":
            self._ps_calibration_type(dataset)
        elif attack_type in self._PS_SIMPLE_ATTACKS:
            value, _display = self._PS_SIMPLE_ATTACKS[attack_type]
            self._ps_simple(dataset, value)

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

    def fuzz_all(self, dataset: Dataset) -> Dataset:
        """Apply random calibration fuzzing across all categories.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        # Apply each fuzzer category with some probability
        fuzzers = [
            self.fuzz_pixel_spacing,
            self.fuzz_hounsfield_rescale,
            self.fuzz_window_level,
            self.fuzz_slice_thickness,
        ]

        for fuzzer in fuzzers:
            if random.random() < 0.5:  # 50% chance for each category
                try:
                    dataset = fuzzer(dataset)
                except Exception as e:
                    logger.debug("Calibration %s failed: %s", fuzzer.__name__, e)

        return dataset

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply calibration mutations (FormatFuzzerBase interface).

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        return self.fuzz_all(dataset)
