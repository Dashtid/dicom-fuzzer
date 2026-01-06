"""3D Reconstruction Attack Strategies (v1.7.0)

This module provides the Reconstruction3DAttacksMixin with five specialized
mutation strategies targeting 3D volume reconstruction vulnerabilities.

Strategies:
6. Non-Orthogonal Orientation - Invalid ImageOrientationPatient vectors
7. Systematic Slice Gap - Removes slices to create gaps
8. Slice Overlap Injection - Creates overlapping slice positions
9. Voxel Aspect Ratio - Extreme non-isotropic voxel dimensions
10. Frame of Reference - Manipulates FrameOfReferenceUID consistency
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

if TYPE_CHECKING:
    from dicom_fuzzer.core.dicom_series import DicomSeries
    from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord


class Reconstruction3DAttacksMixin:
    """Mixin providing 3D reconstruction attack strategies.

    This mixin assumes the class has:
    - self.severity: str - The mutation severity level
    """

    severity: str  # Type hint for mixin

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

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

    # --- Slice Overlap Injection Helpers ---

    def _create_overlap_record(
        self,
        attack_type: str,
        slice_index: int | None,
        original_value: str,
        mutated_value: str,
        details: dict[str, Any] | None = None,
    ) -> SeriesMutationRecord:
        """Create a SeriesMutationRecord for slice overlap attacks."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        return SeriesMutationRecord(
            strategy="slice_overlap_injection",
            slice_index=slice_index,
            tag="ImagePositionPatient[2]",
            original_value=original_value,
            mutated_value=mutated_value,
            severity=self.severity,
            details={"attack_type": attack_type, **(details or {})},
        )

    def _handle_duplicate_position(
        self, datasets: list[Dataset]
    ) -> list[SeriesMutationRecord]:
        """Handle duplicate_position attack type."""
        records: list[SeriesMutationRecord] = []
        target_idx = random.randint(0, len(datasets) - 1)

        if not hasattr(datasets[target_idx], "ImagePositionPatient"):
            return records

        target_z = datasets[target_idx].ImagePositionPatient[2]

        for offset in [-1, 1]:
            adj_idx = target_idx + offset
            if 0 <= adj_idx < len(datasets):
                if hasattr(datasets[adj_idx], "ImagePositionPatient"):
                    original = list(datasets[adj_idx].ImagePositionPatient)
                    datasets[adj_idx].ImagePositionPatient[2] = target_z
                    records.append(
                        self._create_overlap_record(
                            attack_type="duplicate_position",
                            slice_index=adj_idx,
                            original_value=str(original[2]),
                            mutated_value=str(target_z),
                            details={"duplicated_from": target_idx},
                        )
                    )
        return records

    def _handle_physical_overlap(
        self, datasets: list[Dataset]
    ) -> list[SeriesMutationRecord]:
        """Handle physical_overlap attack type."""
        slice_thickness = 5.0
        if hasattr(datasets[0], "SliceThickness"):
            slice_thickness = float(datasets[0].SliceThickness)

        overlap_spacing = slice_thickness * 0.5
        base_z = 0.0
        if hasattr(datasets[0], "ImagePositionPatient"):
            base_z = datasets[0].ImagePositionPatient[2]

        for i, ds in enumerate(datasets):
            if hasattr(ds, "ImagePositionPatient"):
                ds.ImagePositionPatient[2] = base_z + i * overlap_spacing

        return [
            self._create_overlap_record(
                attack_type="physical_overlap",
                slice_index=None,
                original_value="<original_spacing>",
                mutated_value=f"spacing={overlap_spacing:.2f}mm (50% of thickness)",
                details={"overlap_spacing": overlap_spacing},
            )
        ]

    def _handle_reversed_order(
        self, datasets: list[Dataset]
    ) -> list[SeriesMutationRecord]:
        """Handle reversed_order attack type."""
        z_positions = [
            ds.ImagePositionPatient[2]
            for ds in datasets
            if hasattr(ds, "ImagePositionPatient")
        ]

        if not z_positions:
            return []

        z_positions.reverse()
        for i, ds in enumerate(datasets):
            if hasattr(ds, "ImagePositionPatient") and i < len(z_positions):
                ds.ImagePositionPatient[2] = z_positions[i]

        return [
            self._create_overlap_record(
                attack_type="reversed_order",
                slice_index=None,
                original_value="<ascending>",
                mutated_value="<descending>",
            )
        ]

    def _handle_micro_spacing(
        self, datasets: list[Dataset]
    ) -> list[SeriesMutationRecord]:
        """Handle micro_spacing attack type."""
        micro_spacing = 0.001
        base_z = 0.0
        if hasattr(datasets[0], "ImagePositionPatient"):
            base_z = datasets[0].ImagePositionPatient[2]

        for i, ds in enumerate(datasets):
            if hasattr(ds, "ImagePositionPatient"):
                ds.ImagePositionPatient[2] = base_z + i * micro_spacing

        return [
            self._create_overlap_record(
                attack_type="micro_spacing",
                slice_index=None,
                original_value="<normal_spacing>",
                mutated_value=f"spacing={micro_spacing}mm",
            )
        ]

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
        records: list[SeriesMutationRecord] = []

        attack_handlers = {
            "duplicate_position": self._handle_duplicate_position,
            "physical_overlap": self._handle_physical_overlap,
            "reversed_order": self._handle_reversed_order,
            "micro_spacing": self._handle_micro_spacing,
        }

        for _ in range(mutation_count):
            if len(datasets) < 2:
                break

            attack_type = random.choice(list(attack_handlers.keys()))
            handler = attack_handlers[attack_type]
            records.extend(handler(datasets))

        return datasets, records

    def _voxel_attack_extreme_ratio(
        self, ds: Dataset, slice_idx: int, records: list[SeriesMutationRecord]
    ) -> None:
        """Apply 100:1 aspect ratio attack."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        if not hasattr(ds, "PixelSpacing"):
            return
        original = list(ds.PixelSpacing)
        ds.PixelSpacing = [0.1, 10.0]
        records.append(
            SeriesMutationRecord(
                strategy="voxel_aspect_ratio",
                slice_index=slice_idx,
                tag="PixelSpacing",
                original_value=str(original),
                mutated_value="[0.1, 10.0] (100:1 ratio)",
                severity=self.severity,
                details={"attack_type": "extreme_ratio"},
            )
        )

    def _voxel_attack_non_square(
        self, ds: Dataset, slice_idx: int, records: list[SeriesMutationRecord]
    ) -> None:
        """Apply non-square pixels attack (4:1 ratio)."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        if not hasattr(ds, "PixelSpacing"):
            return
        original = list(ds.PixelSpacing)
        ds.PixelSpacing = [0.5, 2.0]
        records.append(
            SeriesMutationRecord(
                strategy="voxel_aspect_ratio",
                slice_index=slice_idx,
                tag="PixelSpacing",
                original_value=str(original),
                mutated_value="[0.5, 2.0] (4:1 ratio)",
                severity=self.severity,
                details={"attack_type": "non_square_pixels"},
            )
        )

    def _voxel_attack_pancake(
        self, ds: Dataset, slice_idx: int, records: list[SeriesMutationRecord]
    ) -> None:
        """Apply pancake voxels attack (100mm thickness)."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        if not hasattr(ds, "SliceThickness"):
            return
        original = ds.SliceThickness
        ds.SliceThickness = 100.0
        records.append(
            SeriesMutationRecord(
                strategy="voxel_aspect_ratio",
                slice_index=slice_idx,
                tag="SliceThickness",
                original_value=str(original),
                mutated_value="100.0mm (pancake)",
                severity=self.severity,
                details={"attack_type": "pancake_voxels"},
            )
        )

    def _voxel_attack_needle(
        self, ds: Dataset, slice_idx: int, records: list[SeriesMutationRecord]
    ) -> None:
        """Apply needle voxels attack (0.001mm thickness)."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        if not hasattr(ds, "SliceThickness"):
            return
        original = ds.SliceThickness
        ds.SliceThickness = 0.001
        records.append(
            SeriesMutationRecord(
                strategy="voxel_aspect_ratio",
                slice_index=slice_idx,
                tag="SliceThickness",
                original_value=str(original),
                mutated_value="0.001mm (needle)",
                severity=self.severity,
                details={"attack_type": "needle_voxels"},
            )
        )

    def _voxel_attack_zero(
        self, ds: Dataset, slice_idx: int, records: list[SeriesMutationRecord]
    ) -> None:
        """Apply zero dimension attack."""
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

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
                    details={"attack_type": "zero_dimension"},
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
                    details={"attack_type": "zero_dimension"},
                )
            )

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
        records: list[SeriesMutationRecord] = []
        handlers = [
            self._voxel_attack_extreme_ratio,
            self._voxel_attack_non_square,
            self._voxel_attack_pancake,
            self._voxel_attack_needle,
            self._voxel_attack_zero,
        ]

        for _ in range(mutation_count):
            slice_idx = random.randint(0, len(datasets) - 1)
            handler = random.choice(handlers)
            handler(datasets[slice_idx], slice_idx, records)

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

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
