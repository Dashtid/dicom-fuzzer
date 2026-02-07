"""Frame Count Mismatch mutation strategy.

Strategy 1: NumberOfFrames tag doesn't match actual pixel data:
- NumberOfFrames > actual frames (buffer over-read)
- NumberOfFrames < actual frames (data ignored/truncated)
- NumberOfFrames = 0 (edge case)
- NumberOfFrames = -1 (signed/unsigned confusion)
- NumberOfFrames = 2^31 (integer overflow)

Targets: Frame indexing, buffer allocation, loop bounds

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class FrameCountMismatchStrategy(MutationStrategyBase):
    """Mutation strategy for frame count mismatch attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "frame_count_mismatch"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply frame count mismatch mutations.

        Args:
            dataset: pydicom Dataset to mutate
            mutation_count: Number of mutations to apply

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        records: list[MultiFrameMutationRecord] = []
        original = getattr(dataset, "NumberOfFrames", 1)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "too_large",
                    "too_small",
                    "zero",
                    "negative",
                    "overflow_32bit",
                    "extreme",
                ]
            )

            if attack_type == "too_large":
                # Claim more frames than pixel data contains
                actual_frames = self._calculate_actual_frames(dataset)
                dataset.NumberOfFrames = actual_frames * 10

            elif attack_type == "too_small":
                # Claim fewer frames than pixel data contains
                actual_frames = self._calculate_actual_frames(dataset)
                dataset.NumberOfFrames = max(1, actual_frames // 2)

            elif attack_type == "zero":
                dataset.NumberOfFrames = 0

            elif attack_type == "negative":
                # Store as negative to test signed/unsigned handling
                dataset.NumberOfFrames = -1

            elif attack_type == "overflow_32bit":
                # 2^31 - 1 (max signed 32-bit)
                dataset.NumberOfFrames = 2147483647

            elif attack_type == "extreme":
                # Very large but not overflow
                dataset.NumberOfFrames = 999999999

            records.append(
                MultiFrameMutationRecord(
                    strategy=self.strategy_name,
                    frame_number=None,
                    tag="NumberOfFrames",
                    original_value=str(original),
                    mutated_value=str(dataset.NumberOfFrames),
                    severity=self.severity,
                    details={"attack_type": attack_type},
                )
            )

        return dataset, records

    def _calculate_actual_frames(self, dataset: Dataset) -> int:
        """Calculate actual number of frames based on PixelData size.

        Args:
            dataset: pydicom Dataset

        Returns:
            Estimated number of frames in PixelData

        """
        if not hasattr(dataset, "PixelData"):
            return 0

        frame_size = self._calculate_frame_size(dataset)
        if frame_size == 0:
            return 0

        return len(dataset.PixelData) // frame_size


__all__ = ["FrameCountMismatchStrategy"]
