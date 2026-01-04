"""Per-Frame Dimension Mismatch mutation strategy.

Strategy 3: Create inconsistent dimensions across frames:
- Different pixel matrices per frame
- Inconsistent Rows/Columns in functional groups
- Varying bits allocated per frame

Targets: Frame extraction, buffer allocation per frame

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.multiframe_strategies.base import MutationStrategyBase
from dicom_fuzzer.core.multiframe_types import MultiFrameMutationRecord

if TYPE_CHECKING:
    pass


class PerFrameDimensionStrategy(MutationStrategyBase):
    """Mutation strategy for per-frame dimension mismatch attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "per_frame_dimension_mismatch"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply per-frame dimension mismatch mutations.

        Args:
            dataset: pydicom Dataset to mutate
            mutation_count: Number of mutations to apply

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        records: list[MultiFrameMutationRecord] = []
        per_frame_groups = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)

        if not per_frame_groups:
            # Create corrupt per-frame groups
            frame_count = self._get_frame_count(dataset)
            per_frame_groups = Sequence([Dataset() for _ in range(frame_count)])
            dataset.PerFrameFunctionalGroupsSequence = per_frame_groups

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "varying_matrix_size",
                    "zero_dimensions",
                    "extreme_dimensions",
                    "negative_dimensions",
                ]
            )

            if attack_type == "varying_matrix_size":
                # Different dimensions for different frames
                for fg in per_frame_groups:
                    if not hasattr(fg, "PixelMeasuresSequence"):
                        fg.PixelMeasuresSequence = Sequence([Dataset()])
                    pm = fg.PixelMeasuresSequence[0]

                    # Vary dimensions per frame
                    pm.Rows = random.choice([128, 256, 512, 1024])
                    pm.Columns = random.choice([128, 256, 512, 1024])

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="Rows/Columns",
                        original_value="<consistent>",
                        mutated_value="<varying_per_frame>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "zero_dimensions":
                frame_idx = random.randint(0, len(per_frame_groups) - 1)
                fg = per_frame_groups[frame_idx]
                if not hasattr(fg, "PixelMeasuresSequence"):
                    fg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = fg.PixelMeasuresSequence[0]
                pm.Rows = 0
                pm.Columns = 0

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        frame_number=frame_idx + 1,
                        tag="Rows/Columns",
                        original_value="<valid>",
                        mutated_value="0x0",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_dimensions":
                frame_idx = random.randint(0, len(per_frame_groups) - 1)
                fg = per_frame_groups[frame_idx]
                if not hasattr(fg, "PixelMeasuresSequence"):
                    fg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = fg.PixelMeasuresSequence[0]
                pm.Rows = 65535
                pm.Columns = 65535

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        frame_number=frame_idx + 1,
                        tag="Rows/Columns",
                        original_value="<valid>",
                        mutated_value="65535x65535",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "negative_dimensions":
                frame_idx = random.randint(0, len(per_frame_groups) - 1)
                fg = per_frame_groups[frame_idx]
                if not hasattr(fg, "PixelMeasuresSequence"):
                    fg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = fg.PixelMeasuresSequence[0]
                pm.Rows = -1
                pm.Columns = -1

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        frame_number=frame_idx + 1,
                        tag="Rows/Columns",
                        original_value="<valid>",
                        mutated_value="-1x-1",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records

    def _get_frame_count(self, dataset: Dataset) -> int:
        """Get number of frames in dataset.

        Args:
            dataset: pydicom Dataset

        Returns:
            Number of frames (1 if not multi-frame)

        """
        if not hasattr(dataset, "NumberOfFrames"):
            return 1
        try:
            return int(dataset.NumberOfFrames)
        except (ValueError, TypeError):
            return 1


__all__ = ["PerFrameDimensionStrategy"]
