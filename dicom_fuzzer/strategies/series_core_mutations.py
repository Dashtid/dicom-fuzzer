"""Core Series Mutation Strategies (Original v1.0)

This module provides the CoreMutationsMixin with the original five mutation
strategies for fuzzing complete DICOM series.

Strategies:
1. Metadata Corruption - Invalid UIDs, missing tags, type confusion
2. Slice Position Attack - Randomized positions, duplicates, extreme values
3. Boundary Slice Targeting - First/last/middle slice corruption
4. Gradient Mutation - Progressive corruption patterns
5. Inconsistency Injection - Mixed modalities, conflicting orientations
"""

from __future__ import annotations

import math
import random
from typing import TYPE_CHECKING

from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

if TYPE_CHECKING:
    from dicom_fuzzer.core.dicom_series import DicomSeries
    from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord


class CoreMutationsMixin:
    """Mixin providing core series mutation strategies.

    This mixin assumes the class has:
    - self.severity: str - The mutation severity level
    """

    severity: str  # Type hint for mixin

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []
        available_slices = list(range(len(datasets)))

        for _ in range(mutation_count):
            if not available_slices:
                break

            slice_idx = random.choice(available_slices)
            ds = datasets[slice_idx]

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
                ds.SeriesInstanceUID = generate_uid() + ".999.FUZZED"
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
                ds.SeriesInstanceUID = "1.2.840.ABC.INVALID"
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
                invalid_modalities = [
                    "999",
                    "",
                    "XXXXXXXXXXXXXXXXXXXX",
                    "CT\\MR",
                    "null",
                    "\x00\x00",
                    "A" * 100,
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

        Targets: CVE-2025-35975 (out-of-bounds write), CVE-2025-36521 (OOB read)
        """
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []
        available_slices = list(range(len(datasets)))

        for _ in range(mutation_count):
            if not available_slices:
                break

            slice_idx = random.choice(available_slices)
            ds = datasets[slice_idx]

            if not hasattr(ds, "ImagePositionPatient"):
                continue

            original = tuple(ds.ImagePositionPatient)

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []
        slice_count = len(datasets)

        first_idx = 0
        last_idx = slice_count - 1
        middle_idx = slice_count // 2

        boundary_indices = {
            "first": first_idx,
            "last": last_idx,
            "middle": middle_idx,
        }

        for _ in range(mutation_count):
            boundary_type = random.choice(["first", "last", "middle", "alternating"])

            if boundary_type == "alternating":
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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []
        slice_count = len(datasets)

        gradient_type = random.choice(["linear", "exponential", "sinusoidal"])

        intensities = []
        for i in range(slice_count):
            progress = i / (slice_count - 1) if slice_count > 1 else 0

            if gradient_type == "linear":
                intensity = progress
            elif gradient_type == "exponential":
                intensity = progress**3
            elif gradient_type == "sinusoidal":
                intensity = (math.sin(progress * math.pi * 2) + 1) / 2
            else:
                intensity = progress

            intensities.append(intensity)

        for idx, intensity in enumerate(intensities):
            if random.random() > intensity:
                continue

            ds = datasets[idx]

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []
        available_slices = list(range(len(datasets)))

        for _ in range(mutation_count):
            if not available_slices:
                break

            slice_idx = random.choice(available_slices)
            ds = datasets[slice_idx]

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
