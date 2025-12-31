"""3D DICOM Series Mutation Strategies

This module provides Series3DMutator with five specialized mutation strategies
for fuzzing complete DICOM series (multi-slice 3D volumes).

MUTATION STRATEGIES:
1. Series Metadata Corruption - Invalid UIDs, missing tags, type confusion
2. Slice Position Attacks - Randomized ImagePositionPatient, duplicates, extreme values
3. Boundary Slice Targeting - First/last/middle slice corruption, alternating patterns
4. Gradient Mutations - Progressive corruption (clean -> heavily mutated)
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
from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class SeriesMutationStrategy(Enum):
    """Available series-level mutation strategies."""

    METADATA_CORRUPTION = "metadata_corruption"
    SLICE_POSITION_ATTACK = "slice_position_attack"
    BOUNDARY_SLICE_TARGETING = "boundary_slice_targeting"
    GRADIENT_MUTATION = "gradient_mutation"
    INCONSISTENCY_INJECTION = "inconsistency_injection"
    # v1.7.0 - 3D Reconstruction Attack Vectors
    NON_ORTHOGONAL_ORIENTATION = "non_orthogonal_orientation"
    SYSTEMATIC_SLICE_GAP = "systematic_slice_gap"
    SLICE_OVERLAP_INJECTION = "slice_overlap_injection"
    VOXEL_ASPECT_RATIO = "voxel_aspect_ratio"
    FRAME_OF_REFERENCE = "frame_of_reference"
    # v1.8.0 - Cross-Slice Reference and Temporal Attacks
    CROSS_SLICE_REFERENCE = "cross_slice_reference"
    TEMPORAL_INCONSISTENCY = "temporal_inconsistency"


@dataclass
class SeriesMutationRecord(SerializableMixin):
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

    def _custom_serialization(self, data: dict) -> dict:
        """Ensure values are converted to strings for JSON serialization."""
        # Convert values to strings if present (handles non-string types)
        if data.get("original_value") is not None:
            data["original_value"] = str(data["original_value"])
        if data.get("mutated_value") is not None:
            data["mutated_value"] = str(data["mutated_value"])
        return data


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
        strategy: str | SeriesMutationStrategy | None = None,
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
            # v1.7.0 - 3D Reconstruction Attack Vectors
            SeriesMutationStrategy.NON_ORTHOGONAL_ORIENTATION.value: self._mutate_non_orthogonal_orientation,
            SeriesMutationStrategy.SYSTEMATIC_SLICE_GAP.value: self._mutate_systematic_slice_gap,
            SeriesMutationStrategy.SLICE_OVERLAP_INJECTION.value: self._mutate_slice_overlap_injection,
            SeriesMutationStrategy.VOXEL_ASPECT_RATIO.value: self._mutate_voxel_aspect_ratio,
            SeriesMutationStrategy.FRAME_OF_REFERENCE.value: self._mutate_frame_of_reference,
            # v1.8.0 - Cross-Slice Reference and Temporal Attacks
            SeriesMutationStrategy.CROSS_SLICE_REFERENCE.value: self._mutate_cross_slice_reference,
            SeriesMutationStrategy.TEMPORAL_INCONSISTENCY.value: self._mutate_temporal_inconsistency,
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
        datasets: list[Dataset] = []
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
                # Use invalid string values that may confuse parsers
                # (pydicom can't serialize actual integers for CS VR tags)
                invalid_modalities = [
                    "999",  # Numeric string (invalid modality code)
                    "",  # Empty string
                    "XXXXXXXXXXXXXXXXXXXX",  # Overly long (CS max is 16 chars)
                    "CT\\MR",  # Multiple values (invalid for single-valued)
                    "null",  # SQL/JSON injection attempt
                    "\x00\x00",  # Null bytes
                    "A" * 100,  # Very long string
                ]
                ds.Modality = random.choice(invalid_modalities)
                records.append(
                    SeriesMutationRecord(
                        strategy="metadata_corruption",
                        slice_index=slice_idx,
                        tag="Modality",
                        original_value=original,
                        mutated_value=repr(ds.Modality),
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
                    original_uid = str(ds.SeriesInstanceUID)
                    ds.SeriesInstanceUID = generate_uid() + ".BOUNDARY_FUZZ"
                    records.append(
                        SeriesMutationRecord(
                            strategy="boundary_slice_targeting",
                            slice_index=idx,
                            tag="SeriesInstanceUID",
                            original_value=original_uid,
                            mutated_value=str(ds.SeriesInstanceUID),
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

    # =========================================================================
    # v1.7.0 - 3D Reconstruction Attack Vectors
    # =========================================================================

    def _mutate_non_orthogonal_orientation(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 6: Non-Orthogonal Orientation Vectors.

        Creates invalid ImageOrientationPatient vectors:
        - Non-unit vectors (length != 1)
        - Non-perpendicular row/column vectors (dot product != 0)
        - Degenerate vectors (zero length, parallel)
        - NaN/Inf components

        Targets: 3D reconstruction algorithms, MPR viewers, oblique reformatting
        """
        records = []

        for _ in range(mutation_count):
            slice_idx = random.randint(0, len(datasets) - 1)
            ds = datasets[slice_idx]

            if not hasattr(ds, "ImageOrientationPatient"):
                continue

            original = list(ds.ImageOrientationPatient)

            attack_type = random.choice(
                [
                    "non_unit_vector",
                    "non_perpendicular",
                    "zero_vector",
                    "parallel_vectors",
                    "nan_components",
                    "extreme_values",
                ]
            )

            if attack_type == "non_unit_vector":
                # Scale vectors so they're not unit length
                scale = random.choice([0.0, 0.5, 2.0, 10.0, 100.0])
                ds.ImageOrientationPatient = [
                    original[0] * scale,
                    original[1] * scale,
                    original[2] * scale,
                    original[3],
                    original[4],
                    original[5],
                ]

            elif attack_type == "non_perpendicular":
                # Make row and column vectors not perpendicular
                ds.ImageOrientationPatient = [
                    1.0,
                    0.0,
                    0.0,  # Row vector
                    0.5,
                    0.5,
                    0.0,  # Column vector (not perpendicular)
                ]

            elif attack_type == "zero_vector":
                # Zero-length vector
                ds.ImageOrientationPatient = [
                    0.0,
                    0.0,
                    0.0,  # Zero row vector
                    0.0,
                    1.0,
                    0.0,
                ]

            elif attack_type == "parallel_vectors":
                # Row and column vectors are parallel
                ds.ImageOrientationPatient = [
                    1.0,
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                    0.0,  # Same as row vector
                ]

            elif attack_type == "nan_components":
                # NaN in orientation
                ds.ImageOrientationPatient = [
                    float("nan"),
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                ]

            elif attack_type == "extreme_values":
                # Extreme float values
                ds.ImageOrientationPatient = [
                    1e308,
                    0.0,
                    0.0,
                    0.0,
                    1e308,
                    0.0,
                ]

            records.append(
                SeriesMutationRecord(
                    strategy="non_orthogonal_orientation",
                    slice_index=slice_idx,
                    tag="ImageOrientationPatient",
                    original_value=str(original),
                    mutated_value=str(list(ds.ImageOrientationPatient)),
                    severity=self.severity,
                    details={"attack_type": attack_type},
                )
            )

        return datasets, records

    def _mutate_systematic_slice_gap(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 7: Systematic Slice Gap Injection.

        Removes slices to create gaps in the series:
        - Remove every Nth slice
        - Remove boundary slices (first/last N)
        - Remove middle section
        - Random removal pattern

        Targets: Interpolation algorithms, volume rendering, gap detection

        Note: This modifies the datasets list itself (removes elements).
        """
        records: list[SeriesMutationRecord] = []
        original_count = len(datasets)

        if original_count < 5:
            return datasets, records  # Too few slices to create meaningful gaps

        attack_type = random.choice(
            [
                "every_nth",
                "boundary_removal",
                "middle_section",
                "random_removal",
            ]
        )

        removed_indices: list[int] = []

        if attack_type == "every_nth":
            # Remove every Nth slice
            n = random.choice([2, 3, 4, 5])
            removed_indices = list(range(0, original_count, n))

        elif attack_type == "boundary_removal":
            # Remove first and last N slices
            n = min(3, original_count // 4)
            removed_indices = list(range(n)) + list(
                range(original_count - n, original_count)
            )

        elif attack_type == "middle_section":
            # Remove middle 20-50% of slices
            start = original_count // 3
            end = 2 * original_count // 3
            removed_indices = list(range(start, end))

        elif attack_type == "random_removal":
            # Remove random 20-40% of slices
            remove_count = random.randint(original_count // 5, 2 * original_count // 5)
            removed_indices = random.sample(range(original_count), remove_count)

        # Remove in reverse order to maintain indices
        for idx in sorted(removed_indices, reverse=True):
            if idx < len(datasets):
                datasets.pop(idx)

        records.append(
            SeriesMutationRecord(
                strategy="systematic_slice_gap",
                slice_index=None,
                tag="<series_structure>",
                original_value=f"{original_count} slices",
                mutated_value=f"{len(datasets)} slices",
                severity=self.severity,
                details={
                    "attack_type": attack_type,
                    "removed_count": len(removed_indices),
                    "removed_indices": removed_indices[:10],  # Limit for logging
                },
            )
        )

        return datasets, records

    def _mutate_slice_overlap_injection(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 8: Slice Overlap Injection.

        Creates overlapping or duplicated slice positions:
        - Multiple slices at exact same Z position
        - Z-spacing less than SliceThickness (physical overlap)
        - Negative slice spacing (reversed order)
        - Extremely close slices

        Targets: Slice sorting, deduplication, interpolation
        """
        records = []

        for _ in range(mutation_count):
            if len(datasets) < 2:
                break

            attack_type = random.choice(
                [
                    "duplicate_position",
                    "physical_overlap",
                    "reversed_order",
                    "micro_spacing",
                ]
            )

            if attack_type == "duplicate_position":
                # Set multiple slices to same Z position
                target_idx = random.randint(0, len(datasets) - 1)
                if hasattr(datasets[target_idx], "ImagePositionPatient"):
                    target_z = datasets[target_idx].ImagePositionPatient[2]

                    # Set adjacent slices to same position
                    for offset in [-1, 1]:
                        adj_idx = target_idx + offset
                        if 0 <= adj_idx < len(datasets):
                            if hasattr(datasets[adj_idx], "ImagePositionPatient"):
                                original = list(datasets[adj_idx].ImagePositionPatient)
                                datasets[adj_idx].ImagePositionPatient[2] = target_z

                                records.append(
                                    SeriesMutationRecord(
                                        strategy="slice_overlap_injection",
                                        slice_index=adj_idx,
                                        tag="ImagePositionPatient[2]",
                                        original_value=str(original[2]),
                                        mutated_value=str(target_z),
                                        severity=self.severity,
                                        details={
                                            "attack_type": attack_type,
                                            "duplicated_from": target_idx,
                                        },
                                    )
                                )

            elif attack_type == "physical_overlap":
                # Z-spacing less than SliceThickness
                slice_thickness = 5.0  # Default assumption
                if hasattr(datasets[0], "SliceThickness"):
                    slice_thickness = float(datasets[0].SliceThickness)

                # Set spacing to 50% of thickness (overlapping)
                overlap_spacing = slice_thickness * 0.5
                base_z = 0.0
                if hasattr(datasets[0], "ImagePositionPatient"):
                    base_z = datasets[0].ImagePositionPatient[2]

                for i, ds in enumerate(datasets):
                    if hasattr(ds, "ImagePositionPatient"):
                        ds.ImagePositionPatient[2] = base_z + i * overlap_spacing

                records.append(
                    SeriesMutationRecord(
                        strategy="slice_overlap_injection",
                        slice_index=None,
                        tag="ImagePositionPatient[2]",
                        original_value="<original_spacing>",
                        mutated_value=f"spacing={overlap_spacing:.2f}mm (50% of thickness)",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "overlap_spacing": overlap_spacing,
                        },
                    )
                )

            elif attack_type == "reversed_order":
                # Reverse Z positions
                z_positions = []
                for ds in datasets:
                    if hasattr(ds, "ImagePositionPatient"):
                        z_positions.append(ds.ImagePositionPatient[2])

                if z_positions:
                    z_positions.reverse()
                    for i, ds in enumerate(datasets):
                        if hasattr(ds, "ImagePositionPatient") and i < len(z_positions):
                            ds.ImagePositionPatient[2] = z_positions[i]

                    records.append(
                        SeriesMutationRecord(
                            strategy="slice_overlap_injection",
                            slice_index=None,
                            tag="ImagePositionPatient[2]",
                            original_value="<ascending>",
                            mutated_value="<descending>",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "micro_spacing":
                # Extremely small spacing (essentially overlapping)
                micro_spacing = 0.001  # 1 micrometer
                base_z = 0.0
                if hasattr(datasets[0], "ImagePositionPatient"):
                    base_z = datasets[0].ImagePositionPatient[2]

                for i, ds in enumerate(datasets):
                    if hasattr(ds, "ImagePositionPatient"):
                        ds.ImagePositionPatient[2] = base_z + i * micro_spacing

                records.append(
                    SeriesMutationRecord(
                        strategy="slice_overlap_injection",
                        slice_index=None,
                        tag="ImagePositionPatient[2]",
                        original_value="<normal_spacing>",
                        mutated_value=f"spacing={micro_spacing}mm",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return datasets, records

    def _mutate_voxel_aspect_ratio(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 9: Voxel Aspect Ratio Attacks.

        Creates extreme non-isotropic voxel dimensions:
        - Extreme aspect ratios (100:1)
        - Non-square pixels (PixelSpacing[0] != PixelSpacing[1])
        - SliceThickness >> in-plane spacing (pancake voxels)
        - Zero dimensions

        Targets: Volume rendering, measurements, interpolation
        """
        records = []

        for _ in range(mutation_count):
            slice_idx = random.randint(0, len(datasets) - 1)
            ds = datasets[slice_idx]

            attack_type = random.choice(
                [
                    "extreme_ratio",
                    "non_square_pixels",
                    "pancake_voxels",
                    "needle_voxels",
                    "zero_dimension",
                ]
            )

            if attack_type == "extreme_ratio":
                # 100:1 aspect ratio in-plane
                if hasattr(ds, "PixelSpacing"):
                    original = list(ds.PixelSpacing)
                    ds.PixelSpacing = [0.1, 10.0]  # 100:1 ratio

                    records.append(
                        SeriesMutationRecord(
                            strategy="voxel_aspect_ratio",
                            slice_index=slice_idx,
                            tag="PixelSpacing",
                            original_value=str(original),
                            mutated_value="[0.1, 10.0] (100:1 ratio)",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "non_square_pixels":
                # Different row/column spacing
                if hasattr(ds, "PixelSpacing"):
                    original = list(ds.PixelSpacing)
                    ds.PixelSpacing = [0.5, 2.0]  # 4:1 ratio

                    records.append(
                        SeriesMutationRecord(
                            strategy="voxel_aspect_ratio",
                            slice_index=slice_idx,
                            tag="PixelSpacing",
                            original_value=str(original),
                            mutated_value="[0.5, 2.0] (4:1 ratio)",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "pancake_voxels":
                # SliceThickness >> PixelSpacing (very thick slices)
                if hasattr(ds, "SliceThickness"):
                    original = ds.SliceThickness
                    ds.SliceThickness = 100.0  # 100mm thick slices

                    records.append(
                        SeriesMutationRecord(
                            strategy="voxel_aspect_ratio",
                            slice_index=slice_idx,
                            tag="SliceThickness",
                            original_value=str(original),
                            mutated_value="100.0mm (pancake)",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "needle_voxels":
                # SliceThickness << PixelSpacing (very thin slices)
                if hasattr(ds, "SliceThickness"):
                    original = ds.SliceThickness
                    ds.SliceThickness = 0.001  # 1 micrometer

                    records.append(
                        SeriesMutationRecord(
                            strategy="voxel_aspect_ratio",
                            slice_index=slice_idx,
                            tag="SliceThickness",
                            original_value=str(original),
                            mutated_value="0.001mm (needle)",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "zero_dimension":
                # Zero spacing or thickness
                target = random.choice(["PixelSpacing", "SliceThickness"])
                if target == "PixelSpacing" and hasattr(ds, "PixelSpacing"):
                    original = list(ds.PixelSpacing)
                    ds.PixelSpacing = [0.0, 0.0]

                    records.append(
                        SeriesMutationRecord(
                            strategy="voxel_aspect_ratio",
                            slice_index=slice_idx,
                            tag="PixelSpacing",
                            original_value=str(original),
                            mutated_value="[0.0, 0.0]",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )
                elif target == "SliceThickness" and hasattr(ds, "SliceThickness"):
                    original = ds.SliceThickness
                    ds.SliceThickness = 0.0

                    records.append(
                        SeriesMutationRecord(
                            strategy="voxel_aspect_ratio",
                            slice_index=slice_idx,
                            tag="SliceThickness",
                            original_value=str(original),
                            mutated_value="0.0",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

        return datasets, records

    def _mutate_frame_of_reference(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 10: Frame of Reference Attacks (Series-Level).

        Manipulates FrameOfReferenceUID within a series:
        - Different FoR for each slice (should be consistent)
        - Empty FoR
        - Invalid UID format
        - Missing FoR

        Targets: Registration, slice grouping, coordinate systems
        """
        records = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "inconsistent_within_series",
                    "empty_for",
                    "invalid_for",
                    "missing_for",
                ]
            )

            if attack_type == "inconsistent_within_series":
                # Each slice gets different FoR
                for _i, ds in enumerate(datasets):
                    ds.FrameOfReferenceUID = generate_uid()

                records.append(
                    SeriesMutationRecord(
                        strategy="frame_of_reference",
                        slice_index=None,
                        tag="FrameOfReferenceUID",
                        original_value="<consistent>",
                        mutated_value="<different_per_slice>",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "slice_count": len(datasets),
                        },
                    )
                )

            elif attack_type == "empty_for":
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                original = getattr(ds, "FrameOfReferenceUID", None)
                ds.FrameOfReferenceUID = ""

                records.append(
                    SeriesMutationRecord(
                        strategy="frame_of_reference",
                        slice_index=slice_idx,
                        tag="FrameOfReferenceUID",
                        original_value=str(original) if original else "<none>",
                        mutated_value="<empty>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_for":
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                original = getattr(ds, "FrameOfReferenceUID", None)
                ds.FrameOfReferenceUID = "!INVALID-FoR-@#$%^&*()"

                records.append(
                    SeriesMutationRecord(
                        strategy="frame_of_reference",
                        slice_index=slice_idx,
                        tag="FrameOfReferenceUID",
                        original_value=str(original) if original else "<none>",
                        mutated_value="!INVALID-FoR-@#$%^&*()",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "missing_for":
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                original = getattr(ds, "FrameOfReferenceUID", None)
                if hasattr(ds, "FrameOfReferenceUID"):
                    del ds.FrameOfReferenceUID

                records.append(
                    SeriesMutationRecord(
                        strategy="frame_of_reference",
                        slice_index=slice_idx,
                        tag="FrameOfReferenceUID",
                        original_value=str(original) if original else "<none>",
                        mutated_value="<deleted>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return datasets, records

    # =========================================================================
    # v1.8.0 - Cross-Slice Reference and Temporal Attacks
    # =========================================================================

    def _mutate_cross_slice_reference(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 11: Cross-Slice Reference Corruption.

        Manipulates ReferencedSOPInstanceUID and related cross-slice references:
        - Reference non-existent slices
        - Create circular references between slices
        - Use invalid UID format
        - Reference deleted/missing slices
        - Self-referencing (slice references itself)

        Targets: Series reconstruction, slice linking, registration algorithms
        """
        records: list[SeriesMutationRecord] = []

        # Collect existing SOPInstanceUIDs for reference
        existing_uids = []
        for ds in datasets:
            if hasattr(ds, "SOPInstanceUID"):
                existing_uids.append(str(ds.SOPInstanceUID))

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "reference_nonexistent",
                    "circular_reference",
                    "invalid_uid_format",
                    "self_reference",
                    "duplicate_references",
                    "missing_reference_chain",
                ]
            )

            if attack_type == "reference_nonexistent":
                # Add reference to a SOP Instance that doesn't exist
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                fake_uid = generate_uid() + ".NONEXISTENT.999"

                # Add to ReferencedImageSequence
                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                ref_item = pydicom.Dataset()
                ref_item.ReferencedSOPClassUID = (
                    "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
                )
                ref_item.ReferencedSOPInstanceUID = fake_uid
                ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedImageSequence",
                        original_value="<none>",
                        mutated_value=f"references {fake_uid[:40]}...",
                        severity=self.severity,
                        details={"attack_type": attack_type, "fake_uid": fake_uid},
                    )
                )

            elif attack_type == "circular_reference":
                # Create A -> B -> C -> A circular reference
                if len(datasets) >= 3:
                    for i in range(min(3, len(datasets))):
                        ds = datasets[i]
                        next_idx = (i + 1) % min(3, len(datasets))
                        next_uid = (
                            existing_uids[next_idx]
                            if next_idx < len(existing_uids)
                            else generate_uid()
                        )

                        if not hasattr(ds, "ReferencedImageSequence"):
                            ds.ReferencedImageSequence = pydicom.Sequence([])

                        ref_item = pydicom.Dataset()
                        ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                        ref_item.ReferencedSOPInstanceUID = next_uid
                        ds.ReferencedImageSequence.append(ref_item)

                    records.append(
                        SeriesMutationRecord(
                            strategy="cross_slice_reference",
                            slice_index=None,
                            tag="ReferencedImageSequence",
                            original_value="<no_circular>",
                            mutated_value="circular: 0->1->2->0",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "invalid_uid_format":
                # Use completely invalid UID format
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                invalid_uids = [
                    "",  # Empty
                    "not.a.valid.uid.format!@#$%",  # Special chars
                    "a" * 100,  # Too long, letters
                    "1.2.3.",  # Trailing dot
                    ".1.2.3",  # Leading dot
                    "1..2..3",  # Double dots
                    "\x00\x00\x00",  # Null bytes
                ]
                invalid_uid = random.choice(invalid_uids)

                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                ref_item = pydicom.Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_item.ReferencedSOPInstanceUID = invalid_uid
                ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedSOPInstanceUID",
                        original_value="<none>",
                        mutated_value=repr(invalid_uid)[:50],
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "self_reference":
                # Slice references itself
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                own_uid = getattr(ds, "SOPInstanceUID", generate_uid())

                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                ref_item = pydicom.Dataset()
                ref_item.ReferencedSOPClassUID = getattr(
                    ds, "SOPClassUID", "1.2.840.10008.5.1.4.1.1.2"
                )
                ref_item.ReferencedSOPInstanceUID = own_uid
                ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedImageSequence",
                        original_value="<none>",
                        mutated_value="<self_reference>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "duplicate_references":
                # Same slice referenced multiple times
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                target_uid = existing_uids[0] if existing_uids else generate_uid()

                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                # Add same reference 10 times
                for _ in range(10):
                    ref_item = pydicom.Dataset()
                    ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    ref_item.ReferencedSOPInstanceUID = target_uid
                    ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedImageSequence",
                        original_value="<none>",
                        mutated_value="10x duplicate references",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "missing_reference_chain":
                # Create broken reference chain A -> B -> [missing]
                if len(datasets) >= 2:
                    # First slice references second
                    ds0 = datasets[0]
                    if not hasattr(ds0, "ReferencedImageSequence"):
                        ds0.ReferencedImageSequence = pydicom.Sequence([])

                    ref_item = pydicom.Dataset()
                    ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    ref_item.ReferencedSOPInstanceUID = (
                        existing_uids[1] if len(existing_uids) > 1 else generate_uid()
                    )
                    ds0.ReferencedImageSequence.append(ref_item)

                    # Second slice references non-existent
                    ds1 = datasets[1]
                    if not hasattr(ds1, "ReferencedImageSequence"):
                        ds1.ReferencedImageSequence = pydicom.Sequence([])

                    ref_item2 = pydicom.Dataset()
                    ref_item2.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    ref_item2.ReferencedSOPInstanceUID = generate_uid() + ".MISSING"
                    ds1.ReferencedImageSequence.append(ref_item2)

                    records.append(
                        SeriesMutationRecord(
                            strategy="cross_slice_reference",
                            slice_index=None,
                            tag="ReferencedImageSequence",
                            original_value="<none>",
                            mutated_value="broken chain: 0->1->missing",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

        return datasets, records

    def _mutate_temporal_inconsistency(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 12: Temporal Inconsistency Injection.

        Creates temporal ordering conflicts across slices:
        - Randomized AcquisitionTime values
        - Duplicate timestamps across slices
        - Extreme time values (year 1900, year 9999)
        - Invalid time format strings
        - AcquisitionTime conflicts with InstanceNumber order

        Targets: 4D reconstruction, temporal sorting, cine viewers
        """
        records: list[SeriesMutationRecord] = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "randomize_acquisition_time",
                    "duplicate_timestamps",
                    "extreme_past_date",
                    "extreme_future_date",
                    "invalid_time_format",
                    "temporal_order_reversal",
                    "subsecond_conflicts",
                ]
            )

            if attack_type == "randomize_acquisition_time":
                # Completely randomize acquisition times
                for _i, ds in enumerate(datasets):
                    random_hour = random.randint(0, 23)
                    random_min = random.randint(0, 59)
                    random_sec = random.randint(0, 59)
                    ds.AcquisitionTime = (
                        f"{random_hour:02d}{random_min:02d}{random_sec:02d}"
                    )

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<sequential>",
                        mutated_value="<randomized>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "duplicate_timestamps":
                # All slices have identical timestamp
                duplicate_time = "120000.000000"
                for ds in datasets:
                    ds.AcquisitionTime = duplicate_time
                    ds.AcquisitionDateTime = "20230101120000.000000"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<unique>",
                        mutated_value=f"all={duplicate_time}",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_past_date":
                # Date from 1900
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                ds.AcquisitionDate = "19000101"
                ds.AcquisitionDateTime = "19000101000000.000000"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=slice_idx,
                        tag="AcquisitionDate",
                        original_value="<modern>",
                        mutated_value="19000101",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_future_date":
                # Date in year 9999
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                ds.AcquisitionDate = "99991231"
                ds.AcquisitionDateTime = "99991231235959.999999"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=slice_idx,
                        tag="AcquisitionDate",
                        original_value="<modern>",
                        mutated_value="99991231",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_time_format":
                # Invalid DICOM time format
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                invalid_times = [
                    "25:00:00",  # Invalid hour
                    "12:60:00",  # Invalid minute
                    "-1:00:00",  # Negative
                    "abc",  # Non-numeric
                    "",  # Empty
                    "999999999999",  # Too long
                    "12.34.56",  # Wrong separator
                ]
                ds.AcquisitionTime = random.choice(invalid_times)

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=slice_idx,
                        tag="AcquisitionTime",
                        original_value="<valid>",
                        mutated_value=repr(ds.AcquisitionTime),
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "temporal_order_reversal":
                # Acquisition times in reverse order vs InstanceNumber
                for i, ds in enumerate(datasets):
                    reversed_idx = len(datasets) - 1 - i
                    # Time increases as instance number decreases
                    ds.AcquisitionTime = f"12{reversed_idx:02d}00.000000"
                    # But keep InstanceNumber sequential
                    ds.InstanceNumber = i + 1

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<matches_instance_order>",
                        mutated_value="<reversed_vs_instance>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "subsecond_conflicts":
                # Multiple acquisitions in same millisecond
                base_time = "120000"
                for i, ds in enumerate(datasets):
                    # All within same millisecond but different microseconds
                    microsec = (i * 7) % 1000  # Spread within 1ms
                    ds.AcquisitionTime = f"{base_time}.{microsec:06d}"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<spread_over_seconds>",
                        mutated_value="<all_within_1ms>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return datasets, records
