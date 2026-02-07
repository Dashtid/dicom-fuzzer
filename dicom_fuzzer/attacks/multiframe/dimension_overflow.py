"""Dimension Overflow mutation strategy.

Strategy 6: Create dimension values that cause integer overflow:
- Frames x Rows x Columns > 2^31 or 2^63
- BitsAllocated combined with dimensions
- SamplesPerPixel multiplier

Targets: Buffer allocation, size calculations

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class DimensionOverflowStrategy(MutationStrategyBase):
    """Mutation strategy for dimension overflow attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "dimension_overflow"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply dimension overflow mutations.

        Args:
            dataset: pydicom Dataset to mutate
            mutation_count: Number of mutations to apply

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        records: list[MultiFrameMutationRecord] = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "frame_dimension_overflow",
                    "total_pixel_overflow",
                    "bits_multiplier_overflow",
                    "samples_multiplier_overflow",
                ]
            )

            if attack_type == "frame_dimension_overflow":
                # NumberOfFrames * Rows * Columns > 2^31
                original_frames = getattr(dataset, "NumberOfFrames", 1)
                dataset.NumberOfFrames = 50000
                dataset.Rows = 10000
                dataset.Columns = 10000
                # 50000 * 10000 * 10000 = 5 trillion > 2^32

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="NumberOfFrames/Rows/Columns",
                        original_value=f"frames={original_frames}",
                        mutated_value="50000x10000x10000 (5T pixels)",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "total_pixels": 5_000_000_000_000,
                        },
                    )
                )

            elif attack_type == "total_pixel_overflow":
                # Max 16-bit values
                dataset.NumberOfFrames = 65535
                dataset.Rows = 65535
                dataset.Columns = 65535

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="NumberOfFrames/Rows/Columns",
                        original_value="<original>",
                        mutated_value="65535x65535x65535",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "bits_multiplier_overflow":
                # BitsAllocated = 64 multiplies buffer size by 8
                original_bits = getattr(dataset, "BitsAllocated", 16)
                dataset.BitsAllocated = 64
                dataset.BitsStored = 64
                dataset.HighBit = 63

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="BitsAllocated",
                        original_value=str(original_bits),
                        mutated_value="64",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "samples_multiplier_overflow":
                # SamplesPerPixel = 255 (max uint8) multiplies size
                original_samples = getattr(dataset, "SamplesPerPixel", 1)
                dataset.SamplesPerPixel = 255

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="SamplesPerPixel",
                        original_value=str(original_samples),
                        mutated_value="255",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records


__all__ = ["DimensionOverflowStrategy"]
