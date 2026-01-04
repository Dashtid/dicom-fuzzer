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

from dicom_fuzzer.core.multiframe_strategies.base import MutationStrategyBase
from dicom_fuzzer.core.multiframe_types import MultiFrameMutationRecord

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class FrameTimeCorruptionStrategy(MutationStrategyBase):
    """Mutation strategy for frame time corruption attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "frame_time_corruption"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply frame time corruption mutations.

        Args:
            dataset: pydicom Dataset to mutate
            mutation_count: Number of mutations to apply

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        records: list[MultiFrameMutationRecord] = []
        frame_count = self._get_frame_count(dataset)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "negative_frame_time",
                    "zero_frame_time",
                    "nan_frame_time",
                    "invalid_time_vector_length",
                    "extreme_time_values",
                    "corrupt_temporal_index",
                ]
            )

            if attack_type == "negative_frame_time":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = -33.33  # Negative ms per frame

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="-33.33",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "zero_frame_time":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = 0.0

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="0.0",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "nan_frame_time":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = float("nan")

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="NaN",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_time_vector_length":
                # FrameTimeVector should have NumberOfFrames-1 elements
                original = getattr(dataset, "FrameTimeVector", None)
                # Create wrong-length vector
                wrong_length = random.choice([0, 1, frame_count + 10, frame_count * 2])
                dataset.FrameTimeVector = [33.33] * wrong_length

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameTimeVector",
                        original_value=f"length={len(original) if original else 0}",
                        mutated_value=f"length={wrong_length}",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "expected_length": frame_count - 1,
                        },
                    )
                )

            elif attack_type == "extreme_time_values":
                original = getattr(dataset, "FrameTime", None)
                dataset.FrameTime = 1e308  # Near max float

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="FrameTime",
                        original_value=str(original) if original else "<none>",
                        mutated_value="1e308",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "corrupt_temporal_index":
                # Add invalid TemporalPositionIndex to per-frame groups
                per_frame_groups = getattr(
                    dataset, "PerFrameFunctionalGroupsSequence", None
                )
                if per_frame_groups:
                    for fg in per_frame_groups:
                        frame_content_seq = getattr(fg, "FrameContentSequence", None)
                        if frame_content_seq and len(frame_content_seq) > 0:
                            frame_content_seq[0].TemporalPositionIndex = random.choice(
                                [0, -1, 999999, frame_count + 100]
                            )

                    records.append(
                        MultiFrameMutationRecord(
                            strategy=self.strategy_name,
                            tag="TemporalPositionIndex",
                            original_value="<sequential>",
                            mutated_value="<random_invalid>",
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


__all__ = ["FrameTimeCorruptionStrategy"]
