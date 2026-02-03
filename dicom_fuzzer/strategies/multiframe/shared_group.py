"""Shared Functional Groups Corruption mutation strategy.

Strategy 4: Corrupt SharedFunctionalGroupsSequence:
- Missing required sequences
- Corrupt pixel measures
- Invalid orientations
- Conflicting with per-frame groups

Targets: Enhanced multi-frame parsers, DICOM conformance

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

if TYPE_CHECKING:
    pass


class SharedGroupStrategy(MutationStrategyBase):
    """Mutation strategy for shared functional groups corruption attacks."""

    _ATTACK_TYPES = [
        "delete_shared_groups",
        "empty_shared_groups",
        "corrupt_pixel_measures",
        "invalid_orientation",
        "conflict_with_per_frame",
    ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "shared_group_corruption"

    def _ensure_sfg(self, dataset: Dataset) -> Any:
        """Ensure SharedFunctionalGroupsSequence exists and return first item."""
        if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
            dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
        return dataset.SharedFunctionalGroupsSequence[0]

    def _make_record(
        self, tag: str, original: str, mutated: str, attack_type: str
    ) -> MultiFrameMutationRecord:
        """Create a mutation record."""
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag=tag,
            original_value=original,
            mutated_value=mutated,
            severity=self.severity,
            details={"attack_type": attack_type},
        )

    def _attack_delete(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Delete shared groups."""
        original = hasattr(dataset, "SharedFunctionalGroupsSequence")
        if original:
            del dataset.SharedFunctionalGroupsSequence
        return self._make_record(
            "SharedFunctionalGroupsSequence",
            "<present>" if original else "<none>",
            "<deleted>",
            "delete_shared_groups",
        )

    def _attack_empty(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Empty shared groups."""
        dataset.SharedFunctionalGroupsSequence = Sequence([])
        return self._make_record(
            "SharedFunctionalGroupsSequence",
            "<has_items>",
            "<empty_sequence>",
            "empty_shared_groups",
        )

    def _attack_pixel_measures(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Corrupt pixel measures."""
        sfg = self._ensure_sfg(dataset)
        if not hasattr(sfg, "PixelMeasuresSequence"):
            sfg.PixelMeasuresSequence = Sequence([Dataset()])
        pm = sfg.PixelMeasuresSequence[0]
        pm.PixelSpacing = [0.0, 0.0]
        pm.SliceThickness = -1.0
        return self._make_record(
            "PixelMeasuresSequence",
            "<valid>",
            "PixelSpacing=[0,0], SliceThickness=-1",
            "corrupt_pixel_measures",
        )

    def _attack_orientation(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Invalid orientation."""
        sfg = self._ensure_sfg(dataset)
        if not hasattr(sfg, "PlaneOrientationSequence"):
            sfg.PlaneOrientationSequence = Sequence([Dataset()])
        po = sfg.PlaneOrientationSequence[0]
        po.ImageOrientationPatient = [float("nan"), 0.0, 0.0, 0.0, float("nan"), 0.0]
        return self._make_record(
            "ImageOrientationPatient",
            "<valid>",
            "[NaN, 0, 0, 0, NaN, 0]",
            "invalid_orientation",
        )

    def _attack_conflict(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Conflict with per-frame."""
        sfg = self._ensure_sfg(dataset)
        if not hasattr(sfg, "PixelMeasuresSequence"):
            sfg.PixelMeasuresSequence = Sequence([Dataset()])
        sfg.PixelMeasuresSequence[0].PixelSpacing = [1.0, 1.0]
        per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
        if per_frame and len(per_frame) > 0:
            if not hasattr(per_frame[0], "PixelMeasuresSequence"):
                per_frame[0].PixelMeasuresSequence = Sequence([Dataset()])
            per_frame[0].PixelMeasuresSequence[0].PixelSpacing = [2.0, 2.0]
        return self._make_record(
            "PixelSpacing",
            "<consistent>",
            "shared=[1,1], per_frame[0]=[2,2]",
            "conflict_with_per_frame",
        )

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply shared group corruption mutations."""
        handlers = {
            "delete_shared_groups": self._attack_delete,
            "empty_shared_groups": self._attack_empty,
            "corrupt_pixel_measures": self._attack_pixel_measures,
            "invalid_orientation": self._attack_orientation,
            "conflict_with_per_frame": self._attack_conflict,
        }
        records: list[MultiFrameMutationRecord] = []
        for _ in range(mutation_count):
            attack_type = random.choice(self._ATTACK_TYPES)
            records.append(handlers[attack_type](dataset))
        return dataset, records


__all__ = ["SharedGroupStrategy"]
