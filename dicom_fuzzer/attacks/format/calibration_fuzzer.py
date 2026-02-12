"""Calibration and Measurement Fuzzing Strategies

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
from dataclasses import dataclass, field
from typing import Any

from pydicom.dataset import Dataset

from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)


@dataclass
class CalibrationMutationRecord(SerializableMixin):
    """Record of a calibration mutation."""

    category: str
    tag: str
    original_value: str | None = None
    mutated_value: str | None = None
    attack_type: str = ""
    severity: str = "moderate"
    details: dict[str, Any] = field(default_factory=dict)

    def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
        """Ensure values are serializable."""
        if data.get("original_value") is not None:
            data["original_value"] = str(data["original_value"])
        if data.get("mutated_value") is not None:
            data["mutated_value"] = str(data["mutated_value"])
        return data


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
        if severity not in ["minimal", "moderate", "aggressive", "extreme"]:
            raise ValueError(f"Invalid severity: {severity}")

        self.severity = severity
        self.seed = seed
        if seed is not None:
            random.seed(seed)

        logger.info(f"CalibrationFuzzer initialized (severity={severity})")

    # --- PixelSpacing Attack Handlers ---

    def _ps_mismatch(self, dataset: Dataset) -> CalibrationMutationRecord | None:
        """PixelSpacing different from ImagerPixelSpacing."""
        if not hasattr(dataset, "PixelSpacing"):
            return None
        original = list(dataset.PixelSpacing)
        dataset.PixelSpacing = [1.0, 1.0]
        dataset.ImagerPixelSpacing = [0.5, 0.5]
        return CalibrationMutationRecord(
            category="pixel_spacing",
            tag="PixelSpacing/ImagerPixelSpacing",
            original_value=str(original),
            mutated_value="PS=[1.0,1.0] IPS=[0.5,0.5]",
            attack_type="mismatch",
            severity=self.severity,
            details={"ratio": 2.0},
        )

    def _ps_simple(
        self, dataset: Dataset, value: list[float], attack_type: str, display: str
    ) -> CalibrationMutationRecord | None:
        """Apply simple PixelSpacing mutation."""
        if not hasattr(dataset, "PixelSpacing"):
            return None
        original = list(dataset.PixelSpacing)
        dataset.PixelSpacing = value
        return CalibrationMutationRecord(
            category="pixel_spacing",
            tag="PixelSpacing",
            original_value=str(original),
            mutated_value=display,
            attack_type=attack_type,
            severity=self.severity,
        )

    def _ps_calibration_type(self, dataset: Dataset) -> CalibrationMutationRecord:
        """Invalid calibration type."""
        original_cal_type = getattr(dataset, "PixelSpacingCalibrationType", None)
        invalid_types = ["", "INVALID", "GEOMETRY" * 10, "\x00\x00"]
        dataset.PixelSpacingCalibrationType = random.choice(invalid_types)
        return CalibrationMutationRecord(
            category="pixel_spacing",
            tag="PixelSpacingCalibrationType",
            original_value=str(original_cal_type) if original_cal_type else "<none>",
            mutated_value=repr(dataset.PixelSpacingCalibrationType)[:50],
            attack_type="calibration_type",
            severity=self.severity,
        )

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
    ) -> tuple[Dataset, list[CalibrationMutationRecord]]:
        """Fuzz PixelSpacing and related calibration tags."""
        records: list[CalibrationMutationRecord] = []

        if attack_type is None:
            attack_type = random.choice(self._PS_ATTACK_TYPES)

        record: CalibrationMutationRecord | None = None
        if attack_type == "mismatch":
            record = self._ps_mismatch(dataset)
        elif attack_type == "calibration_type":
            record = self._ps_calibration_type(dataset)
        elif attack_type in self._PS_SIMPLE_ATTACKS:
            value, display = self._PS_SIMPLE_ATTACKS[attack_type]
            record = self._ps_simple(dataset, value, attack_type, display)

        if record:
            records.append(record)

        return dataset, records

    def fuzz_hounsfield_rescale(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> tuple[Dataset, list[CalibrationMutationRecord]]:
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
            Tuple of (mutated dataset, mutation records)

        """
        records: list[CalibrationMutationRecord] = []

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
            original = getattr(dataset, "RescaleSlope", None)
            dataset.RescaleSlope = 0.0

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleSlope",
                    original_value=str(original) if original else "<none>",
                    mutated_value="0.0",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"effect": "all_pixels_become_intercept"},
                )
            )

        elif attack_type == "negative_slope":
            # Negative slope - inverts the scale
            original = getattr(dataset, "RescaleSlope", None)
            dataset.RescaleSlope = -1.0

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleSlope",
                    original_value=str(original) if original else "<none>",
                    mutated_value="-1.0",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"effect": "inverted_scale"},
                )
            )

        elif attack_type == "extreme_slope":
            # Very large slope - integer overflow when multiplied
            original = getattr(dataset, "RescaleSlope", None)
            dataset.RescaleSlope = 1e15

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleSlope",
                    original_value=str(original) if original else "<none>",
                    mutated_value="1e15",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"effect": "potential_overflow"},
                )
            )

        elif attack_type == "nan_slope":
            # NaN slope
            original = getattr(dataset, "RescaleSlope", None)
            dataset.RescaleSlope = float("nan")

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleSlope",
                    original_value=str(original) if original else "<none>",
                    mutated_value="NaN",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "inf_slope":
            # Infinity slope
            original = getattr(dataset, "RescaleSlope", None)
            dataset.RescaleSlope = float("inf")

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleSlope",
                    original_value=str(original) if original else "<none>",
                    mutated_value="Infinity",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "extreme_intercept":
            # Extreme intercept - push HU values out of valid range
            # Valid HU range is typically -1024 to +3071
            original = getattr(dataset, "RescaleIntercept", None)
            extreme_values = [-1e10, 1e10, -32768, 32767, -2147483648]
            dataset.RescaleIntercept = random.choice(extreme_values)

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleIntercept",
                    original_value=str(original) if original else "<none>",
                    mutated_value=str(dataset.RescaleIntercept),
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "hu_overflow":
            # Combination that causes HU overflow
            # With 16-bit pixel data (0-65535) and slope 1e6, HU = 65535 * 1e6 = overflow
            original_slope = getattr(dataset, "RescaleSlope", None)
            original_intercept = getattr(dataset, "RescaleIntercept", None)
            dataset.RescaleSlope = 1e6
            dataset.RescaleIntercept = 1e10

            records.append(
                CalibrationMutationRecord(
                    category="hounsfield_rescale",
                    tag="RescaleSlope/RescaleIntercept",
                    original_value=f"slope={original_slope}, intercept={original_intercept}",
                    mutated_value="slope=1e6, intercept=1e10",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"effect": "hu_overflow"},
                )
            )

        return dataset, records

    def fuzz_window_level(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> tuple[Dataset, list[CalibrationMutationRecord]]:
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
            Tuple of (mutated dataset, mutation records)

        """
        records: list[CalibrationMutationRecord] = []

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
            original = getattr(dataset, "WindowWidth", None)
            dataset.WindowWidth = 0

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowWidth",
                    original_value=str(original) if original else "<none>",
                    mutated_value="0",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"effect": "divide_by_zero"},
                )
            )

        elif attack_type == "negative_width":
            # Negative window width
            original = getattr(dataset, "WindowWidth", None)
            dataset.WindowWidth = -100

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowWidth",
                    original_value=str(original) if original else "<none>",
                    mutated_value="-100",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "extreme_width_small":
            # Very small window width
            original = getattr(dataset, "WindowWidth", None)
            dataset.WindowWidth = 0.0001

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowWidth",
                    original_value=str(original) if original else "<none>",
                    mutated_value="0.0001",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "extreme_width_large":
            # Very large window width
            original = getattr(dataset, "WindowWidth", None)
            dataset.WindowWidth = 1e10

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowWidth",
                    original_value=str(original) if original else "<none>",
                    mutated_value="1e10",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "extreme_center":
            # Window center far outside data range
            original = getattr(dataset, "WindowCenter", None)
            extreme_centers = [-1e10, 1e10, -2147483648, 2147483647]
            dataset.WindowCenter = random.choice(extreme_centers)

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowCenter",
                    original_value=str(original) if original else "<none>",
                    mutated_value=str(dataset.WindowCenter),
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "nan_values":
            # NaN window/level
            original_center = getattr(dataset, "WindowCenter", None)
            original_width = getattr(dataset, "WindowWidth", None)
            dataset.WindowCenter = float("nan")
            dataset.WindowWidth = float("nan")

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowCenter/WindowWidth",
                    original_value=f"center={original_center}, width={original_width}",
                    mutated_value="center=NaN, width=NaN",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "multiple_windows_conflict":
            # Multiple conflicting window presets
            dataset.WindowCenter = [100, -500, 40]  # Different centers
            dataset.WindowWidth = [400, 1500, 80]  # Different widths
            # Add conflicting explanations
            dataset.WindowCenterWidthExplanation = ["BONE", "LUNG", "BRAIN"]

            records.append(
                CalibrationMutationRecord(
                    category="window_level",
                    tag="WindowCenter/WindowWidth (multiple)",
                    original_value="<single_or_none>",
                    mutated_value="3 conflicting presets",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"preset_count": 3},
                )
            )

        return dataset, records

    def fuzz_slice_thickness(
        self, dataset: Dataset, attack_type: str | None = None
    ) -> tuple[Dataset, list[CalibrationMutationRecord]]:
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
            Tuple of (mutated dataset, mutation records)

        """
        records: list[CalibrationMutationRecord] = []

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
            original = getattr(dataset, "SliceThickness", None)
            dataset.SliceThickness = 0.0

            records.append(
                CalibrationMutationRecord(
                    category="slice_thickness",
                    tag="SliceThickness",
                    original_value=str(original) if original else "<none>",
                    mutated_value="0.0",
                    attack_type=attack_type,
                    severity=self.severity,
                    details={"effect": "volume_calculation_zero"},
                )
            )

        elif attack_type == "negative":
            original = getattr(dataset, "SliceThickness", None)
            dataset.SliceThickness = -5.0

            records.append(
                CalibrationMutationRecord(
                    category="slice_thickness",
                    tag="SliceThickness",
                    original_value=str(original) if original else "<none>",
                    mutated_value="-5.0",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "mismatch":
            # SliceThickness and SpacingBetweenSlices should typically match
            original_thickness = getattr(dataset, "SliceThickness", None)
            original_spacing = getattr(dataset, "SpacingBetweenSlices", None)
            dataset.SliceThickness = 5.0
            dataset.SpacingBetweenSlices = 1.0  # 5x mismatch

            records.append(
                CalibrationMutationRecord(
                    category="slice_thickness",
                    tag="SliceThickness/SpacingBetweenSlices",
                    original_value=f"thickness={original_thickness}, spacing={original_spacing}",
                    mutated_value="thickness=5.0, spacing=1.0 (5x mismatch)",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "extreme_small":
            original = getattr(dataset, "SliceThickness", None)
            dataset.SliceThickness = 1e-10

            records.append(
                CalibrationMutationRecord(
                    category="slice_thickness",
                    tag="SliceThickness",
                    original_value=str(original) if original else "<none>",
                    mutated_value="1e-10",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        elif attack_type == "extreme_large":
            original = getattr(dataset, "SliceThickness", None)
            dataset.SliceThickness = 1e10

            records.append(
                CalibrationMutationRecord(
                    category="slice_thickness",
                    tag="SliceThickness",
                    original_value=str(original) if original else "<none>",
                    mutated_value="1e10",
                    attack_type=attack_type,
                    severity=self.severity,
                )
            )

        return dataset, records

    def fuzz_all(
        self, dataset: Dataset
    ) -> tuple[Dataset, list[CalibrationMutationRecord]]:
        """Apply random calibration fuzzing across all categories.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Tuple of (mutated dataset, all mutation records)

        """
        all_records: list[CalibrationMutationRecord] = []

        # Apply each fuzzer category with some probability
        fuzzers = [
            self.fuzz_pixel_spacing,
            self.fuzz_hounsfield_rescale,
            self.fuzz_window_level,
            self.fuzz_slice_thickness,
        ]

        for fuzzer in fuzzers:
            if random.random() < 0.5:  # 50% chance for each category
                dataset, records = fuzzer(dataset)
                all_records.extend(records)

        return dataset, all_records

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply calibration mutations (FormatFuzzerBase interface).

        Wraps fuzz_all() and returns just the mutated dataset.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        dataset, _records = self.fuzz_all(dataset)
        return dataset
