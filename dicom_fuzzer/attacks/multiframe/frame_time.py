"""Frame Time Corruption mutation strategy.

Strategy 2: Corrupt temporal information in multi-frame:
- Invalid FrameTime (negative, zero, NaN)
- Corrupt FrameTimeVector (wrong length, invalid values)
- Invalid FrameDelay
- Corrupt TemporalPositionIndex

Targets: 4D viewers, cine playback, temporal interpolation

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class FrameTimeCorruptionStrategy(MutationStrategyBase):
    """Mutation strategy for frame time corruption attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "frame_time_corruption"

    def _set_frame_time(
        self, dataset: Dataset, value: float, display_value: str, attack_type: str
    ) -> MultiFrameMutationRecord:
        """Set FrameTime and return record."""
        original = getattr(dataset, "FrameTime", None)
        dataset.FrameTime = value
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="FrameTime",
            original_value=str(original) if original else "<none>",
            mutated_value=display_value,
            severity=self.severity,
            details={"attack_type": attack_type},
        )

    def _attack_invalid_vector(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create wrong-length FrameTimeVector."""
        frame_count = self._get_frame_count(dataset)
        original = getattr(dataset, "FrameTimeVector", None)
        wrong_length = random.choice([0, 1, frame_count + 10, frame_count * 2])
        dataset.FrameTimeVector = [33.33] * wrong_length
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="FrameTimeVector",
            original_value=f"length={len(original) if original else 0}",
            mutated_value=f"length={wrong_length}",
            severity=self.severity,
            details={
                "attack_type": "invalid_time_vector_length",
                "expected_length": frame_count - 1,
            },
        )

    def _attack_temporal_index(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord | None:
        """Corrupt TemporalPositionIndex in per-frame groups."""
        frame_count = self._get_frame_count(dataset)
        per_frame_groups = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
        if not per_frame_groups:
            return None
        for fg in per_frame_groups:
            frame_content_seq = getattr(fg, "FrameContentSequence", None)
            if frame_content_seq and len(frame_content_seq) > 0:
                frame_content_seq[0].TemporalPositionIndex = random.choice(
                    [0, -1, 999999, frame_count + 100]
                )
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="TemporalPositionIndex",
            original_value="<sequential>",
            mutated_value="<random_invalid>",
            severity=self.severity,
            details={"attack_type": "corrupt_temporal_index"},
        )

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply frame time corruption mutations."""
        records: list[MultiFrameMutationRecord] = []

        attack_types = [
            "negative_frame_time",
            "zero_frame_time",
            "nan_frame_time",
            "extreme_time_values",
            "invalid_time_vector",
            "corrupt_temporal_index",
        ]

        for _ in range(mutation_count):
            attack_type = random.choice(attack_types)

            if attack_type == "negative_frame_time":
                records.append(
                    self._set_frame_time(dataset, -33.33, "-33.33", attack_type)
                )
            elif attack_type == "zero_frame_time":
                records.append(self._set_frame_time(dataset, 0.0, "0.0", attack_type))
            elif attack_type == "nan_frame_time":
                records.append(
                    self._set_frame_time(dataset, float("nan"), "NaN", attack_type)
                )
            elif attack_type == "extreme_time_values":
                records.append(
                    self._set_frame_time(dataset, 1e308, "1e308", attack_type)
                )
            elif attack_type == "invalid_time_vector":
                records.append(self._attack_invalid_vector(dataset))
            elif attack_type == "corrupt_temporal_index":
                record = self._attack_temporal_index(dataset)
                if record:
                    records.append(record)
                else:
                    # Fall back to negative_frame_time when per-frame groups missing
                    records.append(
                        self._set_frame_time(
                            dataset, -33.33, "-33.33", "negative_frame_time"
                        )
                    )

        return dataset, records


__all__ = ["FrameTimeCorruptionStrategy"]
