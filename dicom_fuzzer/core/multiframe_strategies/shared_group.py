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
from typing import TYPE_CHECKING

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.multiframe_strategies.base import MutationStrategyBase
from dicom_fuzzer.core.multiframe_types import MultiFrameMutationRecord

if TYPE_CHECKING:
    pass


class SharedGroupStrategy(MutationStrategyBase):
    """Mutation strategy for shared functional groups corruption attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "shared_group_corruption"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply shared group corruption mutations.

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
                    "delete_shared_groups",
                    "empty_shared_groups",
                    "corrupt_pixel_measures",
                    "invalid_orientation",
                    "conflict_with_per_frame",
                ]
            )

            if attack_type == "delete_shared_groups":
                original = hasattr(dataset, "SharedFunctionalGroupsSequence")
                if original:
                    del dataset.SharedFunctionalGroupsSequence

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="SharedFunctionalGroupsSequence",
                        original_value="<present>" if original else "<none>",
                        mutated_value="<deleted>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_shared_groups":
                dataset.SharedFunctionalGroupsSequence = Sequence([])

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="SharedFunctionalGroupsSequence",
                        original_value="<has_items>",
                        mutated_value="<empty_sequence>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "corrupt_pixel_measures":
                if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
                    dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
                sfg = dataset.SharedFunctionalGroupsSequence[0]

                if not hasattr(sfg, "PixelMeasuresSequence"):
                    sfg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = sfg.PixelMeasuresSequence[0]

                # Invalid pixel spacing
                pm.PixelSpacing = [0.0, 0.0]
                pm.SliceThickness = -1.0

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PixelMeasuresSequence",
                        original_value="<valid>",
                        mutated_value="PixelSpacing=[0,0], SliceThickness=-1",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_orientation":
                if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
                    dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
                sfg = dataset.SharedFunctionalGroupsSequence[0]

                if not hasattr(sfg, "PlaneOrientationSequence"):
                    sfg.PlaneOrientationSequence = Sequence([Dataset()])
                po = sfg.PlaneOrientationSequence[0]

                # Non-orthogonal, non-unit orientation with NaN values
                po.ImageOrientationPatient = [
                    float("nan"),
                    0.0,
                    0.0,
                    0.0,
                    float("nan"),
                    0.0,
                ]

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="ImageOrientationPatient",
                        original_value="<valid>",
                        mutated_value="[NaN, 0, 0, 0, NaN, 0]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "conflict_with_per_frame":
                # Create conflicting info in shared vs per-frame
                if not hasattr(dataset, "SharedFunctionalGroupsSequence"):
                    dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
                sfg = dataset.SharedFunctionalGroupsSequence[0]

                if not hasattr(sfg, "PixelMeasuresSequence"):
                    sfg.PixelMeasuresSequence = Sequence([Dataset()])
                pm = sfg.PixelMeasuresSequence[0]
                pm.PixelSpacing = [1.0, 1.0]

                # Now set different per-frame
                per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
                if per_frame and len(per_frame) > 0:
                    if not hasattr(per_frame[0], "PixelMeasuresSequence"):
                        per_frame[0].PixelMeasuresSequence = Sequence([Dataset()])
                    per_frame[0].PixelMeasuresSequence[0].PixelSpacing = [2.0, 2.0]

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PixelSpacing",
                        original_value="<consistent>",
                        mutated_value="shared=[1,1], per_frame[0]=[2,2]",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records


__all__ = ["SharedGroupStrategy"]
