"""3D DICOM Series Mutation Strategies

This module provides Series3DMutator with five specialized mutation strategies
for fuzzing complete DICOM series (multi-slice 3D volumes).

MUTATION STRATEGIES:
1. Series Metadata Corruption - Invalid UIDs, missing tags, type confusion
2. Slice Position Attacks - Randomized ImagePositionPatient, duplicates, extreme values
3. Boundary Slice Targeting - First/last/middle slice corruption, alternating patterns
4. Gradient Mutations - Progressive corruption (clean → heavily mutated)
5. Inconsistency Injection - Mixed modalities, conflicting orientations, varying pixel spacing

SECURITY RATIONALE:
Based on 2025 CVE research (CVE-2025-35975, CVE-2025-36521, CVE-2025-5943),
DICOM viewers are vulnerable to:
- Memory corruption from malformed series metadata
- Out-of-bounds access from invalid slice positions
- Infinite loops from circular slice references
- Memory exhaustion from extreme dimensions

These strategies target the series-level parsing and rendering code paths that
individual file fuzzing cannot reach.

USAGE:
    mutator = Series3DMutator(severity="aggressive")
    fuzzed_datasets = mutator.mutate_series(series, strategy="slice_position_attack")
"""

import copy
import math
import random
from dataclasses import dataclass, field
from enum import Enum

import numpy as np
import pydicom
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class SeriesMutationStrategy(Enum):
    """Available series-level mutation strategies."""

    METADATA_CORRUPTION = "metadata_corruption"
    SLICE_POSITION_ATTACK = "slice_position_attack"
    BOUNDARY_SLICE_TARGETING = "boundary_slice_targeting"
    GRADIENT_MUTATION = "gradient_mutation"
    INCONSISTENCY_INJECTION = "inconsistency_injection"


@dataclass
class SeriesMutationRecord:
    """Record of a series-level mutation.

    Extends MutationRecord with series-specific information.
    """

    strategy: str
    slice_index: int | None = None  # Which slice was mutated (None = all slices)
    tag: str | None = None
    original_value: str | None = None
    mutated_value: str | None = None
    severity: str = "moderate"
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "strategy": self.strategy,
            "slice_index": self.slice_index,
            "tag": self.tag,
            "original_value": str(self.original_value) if self.original_value else None,
            "mutated_value": str(self.mutated_value) if self.mutated_value else None,
            "severity": self.severity,
            "details": self.details,
        }


class Series3DMutator:
    """Mutator for 3D DICOM series with specialized attack strategies.

    This class implements series-level fuzzing that targets vulnerabilities
    in multi-slice DICOM loading, parsing, and rendering.
    """

    def __init__(self, severity: str = "moderate", seed: int | None = None):
        """Initialize Series3DMutator.

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
            np.random.seed(seed)

        # Severity-based mutation counts
        self._mutation_counts = {
            "minimal": (1, 2),
            "moderate": (2, 5),
            "aggressive": (5, 10),
            "extreme": (10, 20),
        }

        logger.info(f"Series3DMutator initialized (severity={severity})")

    def mutate_series(
        self,
        series: DicomSeries,
        strategy: str | None = None,
        mutation_count: int | None = None,
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Mutate a complete DICOM series using specified strategy.

        Args:
            series: DicomSeries to mutate
            strategy: Mutation strategy name (random if None)
            mutation_count: Number of mutations (severity-based if None)

        Returns:
            Tuple of (list of mutated pydicom Datasets, list of mutation records)

        Raises:
            ValueError: If series is empty or strategy invalid

        """
        if not series.slices:
            raise ValueError("Cannot mutate empty series")

        # Select strategy
        if strategy is None:
            strategy = random.choice(list(SeriesMutationStrategy)).value
        elif not isinstance(strategy, str):
            strategy = strategy.value

        if strategy not in [s.value for s in SeriesMutationStrategy]:
            raise ValueError(f"Invalid strategy: {strategy}")

        # Determine mutation count
        if mutation_count is None:
            min_count, max_count = self._mutation_counts[self.severity]
            mutation_count = random.randint(min_count, max_count)

        logger.info(
            f"Mutating series with {mutation_count} mutations "
            f"(strategy={strategy}, severity={self.severity})"
        )

        # Load all datasets
        datasets = self._load_datasets(series)

        # Apply strategy
        strategy_method = {
            SeriesMutationStrategy.METADATA_CORRUPTION.value: self._mutate_metadata_corruption,
            SeriesMutationStrategy.SLICE_POSITION_ATTACK.value: self._mutate_slice_position_attack,
            SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value: self._mutate_boundary_slice_targeting,
            SeriesMutationStrategy.GRADIENT_MUTATION.value: self._mutate_gradient_mutation,
            SeriesMutationStrategy.INCONSISTENCY_INJECTION.value: self._mutate_inconsistency_injection,
        }[strategy]

        mutated_datasets, records = strategy_method(datasets, series, mutation_count)

        logger.info(f"Applied {len(records)} mutations to series")
        return mutated_datasets, records

    def _load_datasets(self, series: DicomSeries) -> list[Dataset]:
        """Load all DICOM datasets from series.

        Args:
            series: DicomSeries object

        Returns:
            List of pydicom Dataset objects (deep copies)

        """
        datasets = []
        for slice_path in series.slices:
            try:
                ds = pydicom.dcmread(slice_path)
                # Deep copy to avoid modifying original
                datasets.append(copy.deepcopy(ds))
            except Exception as e:
                logger.error(f"Failed to load slice {slice_path}: {e}")
                raise

        return datasets

    def _mutate_metadata_corruption(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 1: Series Metadata Corruption.

        Corrupts series-level metadata to trigger parsing vulnerabilities:
        - Invalid SeriesInstanceUID format (empty, too long, invalid characters)
        - Missing required tags (SeriesInstanceUID, StudyInstanceUID, Modality)
        - Type confusion (string where integer expected)
        - Mismatched UIDs across slices

        Targets: CVE-2025-5943 (out-of-bounds write in DICOM parser)
        """
        records = []
        available_slices = list(range(len(datasets)))

        for _ in range(mutation_count):
            if not available_slices:
                break

            slice_idx = random.choice(available_slices)
            ds = datasets[slice_idx]

            # Choose corruption type
            corruption_type = random.choice(
                [
                    "invalid_series_uid",
                    "invalid_study_uid",
                    "missing_modality",
                    "empty_series_uid",
                    "extreme_uid_length",
                    "uid_with_invalid_chars",
                    "type_confusion_modality",
                ]
            )

            if corruption_type == "invalid_series_uid":
                original = (
                    ds.SeriesInstanceUID if hasattr(ds, "SeriesInstanceUID") else None
                )
                ds.SeriesInstanceUID = generate_uid() + ".999.FUZZED"  # Invalid suffix
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="SeriesInstanceUID",
                        original_value=original,
                        mutated_value=ds.SeriesInstanceUID,
                        severity=self.severity,
                        details={"corruption_type": corruption_type},
                    )
                )

            elif corruption_type == "invalid_study_uid":
                original = (
                    ds.StudyInstanceUID if hasattr(ds, "StudyInstanceUID") else None
                )
                ds.StudyInstanceUID = "!@#$%INVALID_UID^&*()"
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="StudyInstanceUID",
                        original_value=original,
                        mutated_value=ds.StudyInstanceUID,
                        severity=self.severity,
                        details={"corruption_type": corruption_type},
                    )
                )

            elif corruption_type == "missing_modality":
                original = ds.Modality if hasattr(ds, "Modality") else None
                if hasattr(ds, "Modality"):
                    del ds.Modality
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="Modality",
                        original_value=original,
                        mutated_value="<deleted>",
                        severity=self.severity,
                        details={"corruption_type": corruption_type},
                    )
                )

            elif corruption_type == "empty_series_uid":
                original = (
                    ds.SeriesInstanceUID if hasattr(ds, "SeriesInstanceUID") else None
                )
                ds.SeriesInstanceUID = ""
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="SeriesInstanceUID",
                        original_value=original,
                        mutated_value="",
                        severity=self.severity,
                        details={"corruption_type": corruption_type},
                    )
                )

            elif corruption_type == "extreme_uid_length":
                original = (
                    ds.SeriesInstanceUID if hasattr(ds, "SeriesInstanceUID") else None
                )
                # DICOM UID max is 64 characters, create 128-character UID
                ds.SeriesInstanceUID = "1.2." + ".".join(["999"] * 30)
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="SeriesInstanceUID",
                        original_value=original,
                        mutated_value=ds.SeriesInstanceUID,
                        severity=self.severity,
                        details={
                            "corruption_type": corruption_type,
                            "length": len(ds.SeriesInstanceUID),
                        },
                    )
                )

            elif corruption_type == "uid_with_invalid_chars":
                original = (
                    ds.SeriesInstanceUID if hasattr(ds, "SeriesInstanceUID") else None
                )
                ds.SeriesInstanceUID = "1.2.840.ABC.INVALID"  # Letters not allowed
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="SeriesInstanceUID",
                        original_value=original,
                        mutated_value=ds.SeriesInstanceUID,
                        severity=self.severity,
                        details={"corruption_type": corruption_type},
                    )
                )

            elif corruption_type == "type_confusion_modality":
                original = ds.Modality if hasattr(ds, "Modality") else None
                ds.Modality = 999  # Integer instead of string
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="Modality",
                        original_value=original,
                        mutated_value=ds.Modality,
                        severity=self.severity,
                        details={"corruption_type": corruption_type},
                    )
                )

        return datasets, records

    def _mutate_slice_position_attack(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 2: Slice Position Attacks.

        Corrupts ImagePositionPatient to trigger geometry vulnerabilities:
        - Randomized z-coordinates (out of sequence)
        - Duplicate positions (multiple slices at same location)
        - Extreme values (NaN, Infinity, 1e308)
        - Negative positions (below origin)
        - Overlapping slices (z-positions too close)

        Targets: CVE-2025-35975 (out-of-bounds write), CVE-2025-36521 (out-of-bounds read)
        """
        records = []
        available_slices = list(range(len(datasets)))

        for _ in range(mutation_count):
            if not available_slices:
                break

            slice_idx = random.choice(available_slices)
            ds = datasets[slice_idx]

            if not hasattr(ds, "ImagePositionPatient"):
                continue

            original = tuple(ds.ImagePositionPatient)

            # Choose attack type
            attack_type = random.choice(
                [
                    "randomize_z",
                    "duplicate_position",
                    "extreme_value_nan",
                    "extreme_value_inf",
                    "extreme_value_large",
                    "negative_position",
                    "zero_position",
                ]
            )

            if attack_type == "randomize_z":
                ds.ImagePositionPatient[2] = random.uniform(-1000, 1000)
                records.append(
                    SeriesMutationRecord(
                        strategy="slice_position_attack",
                        slice_index=slice_idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value=str(tuple(ds.ImagePositionPatient)),
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "duplicate_position":
                # Copy position from another slice
                if len(datasets) > 1:
                    other_idx = random.choice(
                        [i for i in range(len(datasets)) if i != slice_idx]
                    )
                    if hasattr(datasets[other_idx], "ImagePositionPatient"):
                        ds.ImagePositionPatient = list(
                            datasets[other_idx].ImagePositionPatient
                        )
                        records.append(
                            SeriesMutationRecord(
                                strategy="slice_position_attack",
                                slice_index=slice_idx,
                                tag="ImagePositionPatient",
                                original_value=str(original),
                                mutated_value=str(tuple(ds.ImagePositionPatient)),
                                severity=self.severity,
                                details={
                                    "attack_type": attack_type,
                                    "duplicated_from": other_idx,
                                },
                            )
                        )

            elif attack_type == "extreme_value_nan":
                ds.ImagePositionPatient[2] = float("nan")
                records.append(
                    SeriesMutationRecord(
                        strategy="slice_position_attack",
                        slice_index=slice_idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value="NaN",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_value_inf":
                ds.ImagePositionPatient[2] = (
                    float("inf") if random.random() > 0.5 else float("-inf")
                )
                records.append(
                    SeriesMutationRecord(
                        strategy="slice_position_attack",
                        slice_index=slice_idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value=str(ds.ImagePositionPatient[2]),
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_value_large":
                ds.ImagePositionPatient[2] = 1e308 if random.random() > 0.5 else -1e308
                records.append(
                    SeriesMutationRecord(
                        strategy="slice_position_attack",
                        slice_index=slice_idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value=f"{ds.ImagePositionPatient[2]:.2e}",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "negative_position":
                ds.ImagePositionPatient = [-abs(x) for x in ds.ImagePositionPatient]
                records.append(
                    SeriesMutationRecord(
                        strategy="slice_position_attack",
                        slice_index=slice_idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value=str(tuple(ds.ImagePositionPatient)),
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "zero_position":
                ds.ImagePositionPatient = [0.0, 0.0, 0.0]
                records.append(
                    SeriesMutationRecord(
                        strategy="slice_position_attack",
                        slice_index=slice_idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value="[0.0, 0.0, 0.0]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return datasets, records

    def _mutate_boundary_slice_targeting(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 3: Boundary Slice Targeting.

        Targets first, last, and middle slices with heavy corruption:
        - First slice corruption (affects series initialization)
        - Last slice corruption (affects finalization)
        - Middle slice corruption (affects interpolation)
        - Alternating pattern (every N-th slice)

        Targets: Edge cases in series loading algorithms
        """
        records = []
        slice_count = len(datasets)

        # Identify boundary slices
        first_idx = 0
        last_idx = slice_count - 1
        middle_idx = slice_count // 2

        boundary_indices = {
            "first": first_idx,
            "last": last_idx,
            "middle": middle_idx,
        }

        for _ in range(mutation_count):
            # Choose boundary type
            boundary_type = random.choice(["first", "last", "middle", "alternating"])

            if boundary_type == "alternating":
                # Mutate every N-th slice
                step = random.choice([2, 3, 5])
                for idx in range(0, slice_count, step):
                    ds = datasets[idx]
                    if hasattr(ds, "ImagePositionPatient"):
                        original = tuple(ds.ImagePositionPatient)
                        ds.ImagePositionPatient[2] = random.uniform(-1000, 1000)
                        records.append(
                            SeriesMutationRecord(
                                strategy="boundary_slice_targeting",
                                slice_index=idx,
                                tag="ImagePositionPatient",
                                original_value=str(original),
                                mutated_value=str(tuple(ds.ImagePositionPatient)),
                                severity=self.severity,
                                details={"boundary_type": boundary_type, "step": step},
                            )
                        )
            else:
                idx = boundary_indices[boundary_type]
                ds = datasets[idx]

                # Apply heavy corruption
                if hasattr(ds, "SeriesInstanceUID"):
                    original = ds.SeriesInstanceUID
                    ds.SeriesInstanceUID = generate_uid() + ".BOUNDARY_FUZZ"
                    records.append(
                        SeriesMutationRecord(
                            strategy="boundary_slice_targeting",
                            slice_index=idx,
                            tag="SeriesInstanceUID",
                            original_value=original,
                            mutated_value=ds.SeriesInstanceUID,
                            severity=self.severity,
                            details={"boundary_type": boundary_type},
                        )
                    )

        return datasets, records

    def _mutate_gradient_mutation(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 4: Gradient Mutations.

        Progressive corruption from clean to heavily mutated:
        - Linear gradient (corruption increases slice by slice)
        - Exponential gradient (rapid increase in corruption)
        - Sinusoidal gradient (wave pattern of corruption)

        Targets: Algorithms that assume consistent corruption levels
        """
        records = []
        slice_count = len(datasets)

        # Choose gradient type
        gradient_type = random.choice(["linear", "exponential", "sinusoidal"])

        # Calculate corruption intensity for each slice
        intensities = []
        for i in range(slice_count):
            progress = i / (slice_count - 1) if slice_count > 1 else 0

            if gradient_type == "linear":
                intensity = progress
            elif gradient_type == "exponential":
                intensity = progress**3
            elif gradient_type == "sinusoidal":
                intensity = (math.sin(progress * math.pi * 2) + 1) / 2

            intensities.append(intensity)

        # Apply mutations based on intensity
        for idx, intensity in enumerate(intensities):
            if random.random() > intensity:
                continue

            ds = datasets[idx]

            # Corrupt ImagePositionPatient based on intensity
            if hasattr(ds, "ImagePositionPatient"):
                original = tuple(ds.ImagePositionPatient)
                corruption_amount = intensity * random.uniform(100, 1000)
                ds.ImagePositionPatient[2] += corruption_amount
                records.append(
                    SeriesMutationRecord(
                        strategy="gradient_mutation",
                        slice_index=idx,
                        tag="ImagePositionPatient",
                        original_value=str(original),
                        mutated_value=str(tuple(ds.ImagePositionPatient)),
                        severity=self.severity,
                        details={
                            "gradient_type": gradient_type,
                            "intensity": intensity,
                            "corruption_amount": corruption_amount,
                        },
                    )
                )

        return datasets, records

    def _mutate_inconsistency_injection(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 5: Inconsistency Injection.

        Creates inconsistencies across slices:
        - Mixed modalities (CT in one slice, MRI in another)
        - Conflicting orientations (different ImageOrientationPatient)
        - Varying pixel spacing (inconsistent PixelSpacing across slices)
        - Mismatched dimensions (different Rows/Columns)

        Targets: Parsers that assume series consistency
        """
        records = []
        available_slices = list(range(len(datasets)))

        for _ in range(mutation_count):
            if not available_slices:
                break

            slice_idx = random.choice(available_slices)
            ds = datasets[slice_idx]

            # Choose inconsistency type
            inconsistency_type = random.choice(
                [
                    "mixed_modality",
                    "conflicting_orientation",
                    "varying_pixel_spacing",
                    "mismatched_dimensions",
                ]
            )

            if inconsistency_type == "mixed_modality":
                original = ds.Modality if hasattr(ds, "Modality") else None
                # Change modality to something unexpected
                new_modality = random.choice(
                    ["CT", "MR", "US", "XA", "PT", "NM", "FUZZ"]
                )
                ds.Modality = new_modality
                records.append(
                    SeriesMutationRecord(
                        strategy="inconsistency_injection",
                        slice_index=slice_idx,
                        tag="Modality",
                        original_value=original,
                        mutated_value=new_modality,
                        severity=self.severity,
                        details={"inconsistency_type": inconsistency_type},
                    )
                )

            elif inconsistency_type == "conflicting_orientation":
                if hasattr(ds, "ImageOrientationPatient"):
                    original = tuple(ds.ImageOrientationPatient)
                    # Flip orientation
                    ds.ImageOrientationPatient = [
                        -x if random.random() > 0.5 else x
                        for x in ds.ImageOrientationPatient
                    ]
                    records.append(
                        SeriesMutationRecord(
                            strategy="inconsistency_injection",
                            slice_index=slice_idx,
                            tag="ImageOrientationPatient",
                            original_value=str(original),
                            mutated_value=str(tuple(ds.ImageOrientationPatient)),
                            severity=self.severity,
                            details={"inconsistency_type": inconsistency_type},
                        )
                    )

            elif inconsistency_type == "varying_pixel_spacing":
                if hasattr(ds, "PixelSpacing"):
                    original = tuple(ds.PixelSpacing)
                    ds.PixelSpacing = [
                        random.uniform(0.1, 10.0),
                        random.uniform(0.1, 10.0),
                    ]
                    records.append(
                        SeriesMutationRecord(
                            strategy="inconsistency_injection",
                            slice_index=slice_idx,
                            tag="PixelSpacing",
                            original_value=str(original),
                            mutated_value=str(tuple(ds.PixelSpacing)),
                            severity=self.severity,
                            details={"inconsistency_type": inconsistency_type},
                        )
                    )

            elif inconsistency_type == "mismatched_dimensions":
                if hasattr(ds, "Rows") and hasattr(ds, "Columns"):
                    original_rows = ds.Rows
                    original_cols = ds.Columns
                    ds.Rows = random.choice([256, 512, 1024, 2048])
                    ds.Columns = random.choice([256, 512, 1024, 2048])
                    records.append(
                        SeriesMutationRecord(
                            strategy="inconsistency_injection",
                            slice_index=slice_idx,
                            tag="Rows/Columns",
                            original_value=f"{original_rows}x{original_cols}",
                            mutated_value=f"{ds.Rows}x{ds.Columns}",
                            severity=self.severity,
                            details={"inconsistency_type": inconsistency_type},
                        )
                    )

        return datasets, records
