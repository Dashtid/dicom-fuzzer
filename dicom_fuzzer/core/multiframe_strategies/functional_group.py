"""Functional Group Attack mutation strategy.

Strategy 7: Corrupt per-frame and shared functional groups:
- Missing per-frame groups for some frames
- Extra per-frame groups beyond NumberOfFrames
- Empty functional group items
- Nested sequence corruption

Targets: Enhanced multi-frame parsing, per-frame indexing

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


class FunctionalGroupStrategy(MutationStrategyBase):
    """Mutation strategy for functional group attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "functional_group_attack"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply functional group attack mutations.

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
                    "missing_per_frame_groups",
                    "extra_per_frame_groups",
                    "empty_group_items",
                    "null_sequence_items",
                    "deeply_nested_corruption",
                ]
            )

            if attack_type == "missing_per_frame_groups":
                # Create fewer per-frame groups than frames
                fewer_count = max(1, frame_count // 2)
                dataset.PerFrameFunctionalGroupsSequence = Sequence(
                    [Dataset() for _ in range(fewer_count)]
                )

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value=f"{frame_count} items",
                        mutated_value=f"{fewer_count} items (missing)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extra_per_frame_groups":
                # Create more per-frame groups than frames
                extra_count = frame_count * 2
                dataset.PerFrameFunctionalGroupsSequence = Sequence(
                    [Dataset() for _ in range(extra_count)]
                )

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value=f"{frame_count} items",
                        mutated_value=f"{extra_count} items (extra)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_group_items":
                # Some items in sequence are empty
                per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
                if per_frame:
                    # Replace random items with empty datasets
                    for i in random.sample(
                        range(len(per_frame)), min(3, len(per_frame))
                    ):
                        per_frame[i] = Dataset()

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value="<populated>",
                        mutated_value="<some_items_empty>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "null_sequence_items":
                # Create corrupt dataset with invalid data
                per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
                if per_frame and len(per_frame) > 0:
                    corrupt_ds = Dataset()
                    corrupt_ds.add_new((0xFFFF, 0xFFFF), "UN", b"\x00" * 100)
                    per_frame[0] = corrupt_ds

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PerFrameFunctionalGroupsSequence[0]",
                        original_value="<valid>",
                        mutated_value="<corrupt_unknown_tag>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "deeply_nested_corruption":
                # Create deeply nested sequences
                if not hasattr(dataset, "PerFrameFunctionalGroupsSequence"):
                    dataset.PerFrameFunctionalGroupsSequence = Sequence([Dataset()])

                fg = dataset.PerFrameFunctionalGroupsSequence[0]

                # Create 10-level deep nesting
                current = fg
                for depth in range(10):
                    nested_seq = Sequence([Dataset()])
                    current.add_new((0x0040, 0x9096 + depth), "SQ", nested_seq)
                    current = nested_seq[0]

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PerFrameFunctionalGroupsSequence",
                        original_value="<normal_depth>",
                        mutated_value="<10_levels_deep>",
                        severity=self.severity,
                        details={"attack_type": attack_type, "nesting_depth": 10},
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


__all__ = ["FunctionalGroupStrategy"]
