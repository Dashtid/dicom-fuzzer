"""Per-Frame Dimension Mismatch mutation strategy.

Strategy 3: Create inconsistent dimensions across frames:
- Different pixel matrices per frame
- Inconsistent Rows/Columns in functional groups
- Varying bits allocated per frame

Targets: Frame extraction, buffer allocation per frame

"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase


class PerFrameDimensionStrategy(MutationStrategyBase):
    """Mutation strategy for per-frame dimension mismatch attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "per_frame_dimension_mismatch"

    def _ensure_pixel_measures(self, fg: Dataset) -> Dataset:
        """Ensure PixelMeasuresSequence exists and return first item."""
        if not hasattr(fg, "PixelMeasuresSequence"):
            fg.PixelMeasuresSequence = Sequence([Dataset()])
        return fg.PixelMeasuresSequence[0]  # type: ignore[no-any-return]

    def _attack_varying_size(
        self, per_frame_groups: Sequence
    ) -> MultiFrameMutationRecord:
        """Apply varying matrix sizes across frames."""
        for fg in per_frame_groups:
            pm = self._ensure_pixel_measures(fg)
            pm.Rows = random.choice([128, 256, 512, 1024])
            pm.Columns = random.choice([128, 256, 512, 1024])
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="Rows/Columns",
            original_value="<consistent>",
            mutated_value="<varying_per_frame>",
            severity=self.severity,
            details={"attack_type": "varying_matrix_size"},
        )

    def _attack_fixed_dims(
        self, per_frame_groups: Sequence, rows: int, cols: int, attack_type: str
    ) -> MultiFrameMutationRecord:
        """Apply fixed dimension values to a random frame."""
        frame_idx = random.randint(0, len(per_frame_groups) - 1)
        pm = self._ensure_pixel_measures(per_frame_groups[frame_idx])
        pm.Rows = rows
        pm.Columns = cols
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            frame_number=frame_idx + 1,
            tag="Rows/Columns",
            original_value="<valid>",
            mutated_value=f"{rows}x{cols}",
            severity=self.severity,
            details={"attack_type": attack_type},
        )

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply per-frame dimension mismatch mutations."""
        records: list[MultiFrameMutationRecord] = []
        per_frame_groups = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)

        if not per_frame_groups:
            frame_count = self._get_frame_count(dataset)
            per_frame_groups = Sequence([Dataset() for _ in range(frame_count)])
            dataset.PerFrameFunctionalGroupsSequence = per_frame_groups

        attacks = [
            ("varying", None, None),
            ("zero", 0, 0),
            ("extreme", 65535, 65535),
            ("negative", -1, -1),
        ]

        for _ in range(mutation_count):
            attack_key, rows, cols = random.choice(attacks)
            if attack_key == "varying":
                records.append(self._attack_varying_size(per_frame_groups))
            else:
                assert rows is not None and cols is not None
                records.append(
                    self._attack_fixed_dims(
                        per_frame_groups, rows, cols, f"{attack_key}_dimensions"
                    )
                )

        return dataset, records


__all__ = ["PerFrameDimensionStrategy"]
