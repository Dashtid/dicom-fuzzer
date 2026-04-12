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

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.multiframe.format_base import MultiFrameMutationRecord

from .format_base import MultiFrameFuzzerBase


class FunctionalGroupStrategy(MultiFrameFuzzerBase):
    """Mutation strategy for functional group attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "functional_group_attack"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate multiframe datasets (NumberOfFrames > 1)."""
        try:
            return int(getattr(dataset, "NumberOfFrames", 1)) > 1
        except (ValueError, TypeError):
            return False

    def _attack_missing_per_frame(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create fewer per-frame groups than frames."""
        frame_count = self._get_frame_count(dataset)
        fewer_count = max(1, frame_count // 2)
        dataset.PerFrameFunctionalGroupsSequence = Sequence(
            [Dataset() for _ in range(fewer_count)]
        )
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence",
            original_value=f"{frame_count} items",
            mutated_value=f"{fewer_count} items (missing)",
            severity=self.severity,
            details={"attack_type": "missing_per_frame_groups"},
        )

    def _attack_extra_per_frame(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create more per-frame groups than frames."""
        frame_count = self._get_frame_count(dataset)
        extra_count = frame_count * 2
        dataset.PerFrameFunctionalGroupsSequence = Sequence(
            [Dataset() for _ in range(extra_count)]
        )
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence",
            original_value=f"{frame_count} items",
            mutated_value=f"{extra_count} items (extra)",
            severity=self.severity,
            details={"attack_type": "extra_per_frame_groups"},
        )

    def _attack_empty_items(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Replace random items in sequence with empty datasets."""
        per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
        if per_frame:
            for i in random.sample(range(len(per_frame)), min(3, len(per_frame))):
                per_frame[i] = Dataset()
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence",
            original_value="<populated>",
            mutated_value="<some_items_empty>",
            severity=self.severity,
            details={"attack_type": "empty_group_items"},
        )

    def _attack_null_sequence(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create corrupt dataset with invalid data."""
        per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
        if per_frame and len(per_frame) > 0:
            corrupt_ds = Dataset()
            corrupt_ds.add_new((0xFFFF, 0xFFFF), "UN", b"\x00" * 100)
            per_frame[0] = corrupt_ds
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence[0]",
            original_value="<valid>",
            mutated_value="<corrupt_unknown_tag>",
            severity=self.severity,
            details={"attack_type": "null_sequence_items"},
        )

    def _attack_deeply_nested(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Create 10-level deep nested sequences."""
        if not hasattr(dataset, "PerFrameFunctionalGroupsSequence"):
            dataset.PerFrameFunctionalGroupsSequence = Sequence([Dataset()])
        fg = dataset.PerFrameFunctionalGroupsSequence[0]
        current = fg
        for depth in range(10):
            nested_seq = Sequence([Dataset()])
            current.add_new((0x0040, 0x9096 + depth), "SQ", nested_seq)
            current = nested_seq[0]
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence",
            original_value="<normal_depth>",
            mutated_value="<10_levels_deep>",
            severity=self.severity,
            details={"attack_type": "deeply_nested_corruption", "nesting_depth": 10},
        )

    def _attack_empty_frame_content(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Set FrameContentSequence to an empty Sequence within each per-frame group.

        Targets parsers that index into FrameContentSequence[0] without
        checking the item count. An empty sequence causes
        IndexOutOfRangeException on the first access.
        """
        frame_count = self._get_frame_count(dataset)
        items = []
        for _ in range(frame_count):
            fg = Dataset()
            fg.FrameContentSequence = Sequence([])  # empty -- no items
            items.append(fg)
        dataset.PerFrameFunctionalGroupsSequence = Sequence(items)
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence.FrameContentSequence",
            original_value="<populated>",
            mutated_value="<empty_sequence>",
            severity=self.severity,
            details={"attack_type": "empty_frame_content_sequence"},
        )

    def _attack_invalid_plane_position(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Set PlanePositionSequence with NaN/Inf/extreme ImagePositionPatient.

        Targets geometry pipelines that use ImagePositionPatient for
        slice positioning and 3D reconstruction. NaN propagates through
        all downstream calculations; Inf causes overflow in distance
        computations; extreme values cause coordinate-system overflow.
        """
        frame_count = self._get_frame_count(dataset)
        items = []
        invalid_positions = [
            [float("nan"), float("nan"), float("nan")],
            [float("inf"), 0.0, 0.0],
            [0.0, float("-inf"), 0.0],
            [1e15, 1e15, 1e15],
            [-1e15, -1e15, -1e15],
        ]
        for _i in range(frame_count):
            fg = Dataset()
            pos_item = Dataset()
            pos_item.ImagePositionPatient = random.choice(invalid_positions)
            fg.PlanePositionSequence = Sequence([pos_item])
            items.append(fg)
        dataset.PerFrameFunctionalGroupsSequence = Sequence(items)
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag="PerFrameFunctionalGroupsSequence.PlanePositionSequence",
            original_value="<valid_positions>",
            mutated_value="<nan_inf_extreme>",
            severity=self.severity,
            details={"attack_type": "invalid_plane_position"},
        )

    def _mutate_impl(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply functional group attack mutations."""
        records: list[MultiFrameMutationRecord] = []
        handlers = [
            self._attack_missing_per_frame,
            self._attack_extra_per_frame,
            self._attack_empty_items,
            self._attack_null_sequence,
            self._attack_deeply_nested,
            self._attack_empty_frame_content,
            self._attack_invalid_plane_position,
        ]

        for _ in range(mutation_count):
            handler = random.choice(handlers)
            records.append(handler(dataset))

        return dataset, records


__all__ = ["FunctionalGroupStrategy"]
