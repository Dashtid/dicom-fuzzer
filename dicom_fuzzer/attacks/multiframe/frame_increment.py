"""Frame Increment Pointer Invalid mutation strategy.

Strategy 5: Corrupt FrameIncrementPointer:
- Point to non-existent tag
- Invalid tag format
- Circular references
- Point to PixelData itself

Targets: Temporal/spatial navigation, frame ordering

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class FrameIncrementStrategy(MutationStrategyBase):
    """Mutation strategy for frame increment pointer invalid attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "frame_increment_invalid"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply frame increment pointer invalid mutations.

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
                    "nonexistent_tag",
                    "invalid_format",
                    "point_to_pixel_data",
                    "multiple_invalid",
                ]
            )

            original = getattr(dataset, "FrameIncrementPointer", None)

            if attack_type == "nonexistent_tag":
                # Point to tag that doesn't exist
                dataset.FrameIncrementPointer = (0x9999, 0x9999)

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="(9999,9999)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_format":
                # Use invalid/unusual tag value (0xFFFF, 0xFFFF)
                # This creates a valid pydicom element but with an edge-case tag pointer
                dataset.FrameIncrementPointer = (0xFFFF, 0xFFFF)

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="(FFFF,FFFF)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "point_to_pixel_data":
                # Point to PixelData tag itself (circular)
                dataset.FrameIncrementPointer = (0x7FE0, 0x0010)

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="(7FE0,0010) [PixelData]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "multiple_invalid":
                # Multiple invalid pointers
                dataset.FrameIncrementPointer = [
                    (0x0000, 0x0000),
                    (0xFFFF, 0xFFFF),
                    (0x7FE0, 0x0010),
                ]

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameIncrementPointer",
                        original_value=str(original) if original else "<none>",
                        mutated_value="[(0,0), (FFFF,FFFF), (7FE0,0010)]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records


__all__ = ["FrameIncrementStrategy"]
