"""Dimension Index Module mutation strategy.

Strategy 10: Corrupt the Multi-frame Dimension Module (C.7.6.17):
- DimensionIndexPointer referencing non-existent tags
- DimensionIndexValues array length mismatches
- DimensionOrganizationType inconsistencies
- Missing DimensionIndexValues for some frames
- Invalid/out-of-range index values

Targets: Frame ordering, spatial reconstruction, dimension-based
navigation, multi-planar reformatting.

Context:
- OHIF Viewers #174: Hanging when FIP points to unsupported vector
- DICOM Part 3 Section C.7.6.17: Multi-frame Dimension Module

"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase


class DimensionIndexStrategy(MutationStrategyBase):
    """Mutation strategy for dimension index module attacks."""

    _ATTACK_TYPES = [
        "invalid_index_pointer",
        "index_values_length_mismatch",
        "missing_index_values",
        "out_of_range_index_values",
        "organization_type_mismatch",
        "empty_dimension_sequence",
        "duplicate_dimension_pointers",
    ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "dimension_index_attack"

    def _make_record(
        self,
        tag: str,
        original: str,
        mutated: str,
        attack_type: str,
        **extra: object,
    ) -> MultiFrameMutationRecord:
        """Create a mutation record."""
        details: dict[str, object] = {"attack_type": attack_type}
        details.update(extra)
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag=tag,
            original_value=original,
            mutated_value=mutated,
            severity=self.severity,
            details=details,
        )

    def _ensure_dimension_index_seq(self, dataset: Dataset) -> Sequence:
        """Ensure DimensionIndexSequence exists with at least one item."""
        if not hasattr(dataset, "DimensionIndexSequence"):
            # Create a minimal valid dimension index sequence
            dim_item = Dataset()
            dim_item.DimensionIndexPointer = Tag(0x0020, 0x0032)  # ImagePositionPatient
            dim_item.FunctionalGroupPointer = Tag(
                0x0020, 0x9113
            )  # PlanePositionSequence
            dataset.DimensionIndexSequence = Sequence([dim_item])
        return dataset.DimensionIndexSequence  # type: ignore[no-any-return]

    def _ensure_per_frame_index_values(self, dataset: Dataset) -> None:
        """Ensure per-frame groups have DimensionIndexValues."""
        frame_count = self._get_frame_count(dataset)
        if not hasattr(dataset, "PerFrameFunctionalGroupsSequence"):
            dataset.PerFrameFunctionalGroupsSequence = Sequence(
                [Dataset() for _ in range(frame_count)]
            )

        dim_count = len(
            getattr(dataset, "DimensionIndexSequence", Sequence([Dataset()]))
        )
        for i, fg in enumerate(dataset.PerFrameFunctionalGroupsSequence):
            if not hasattr(fg, "FrameContentSequence"):
                fc = Dataset()
                fc.DimensionIndexValues = [i + 1] * dim_count
                fg.FrameContentSequence = Sequence([fc])

    # --- Attack handlers ---

    def _attack_invalid_index_pointer(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Set DimensionIndexPointer to a non-existent tag."""
        dim_seq = self._ensure_dimension_index_seq(dataset)

        # Pick a random item and corrupt its pointer
        idx = random.randint(0, len(dim_seq) - 1)
        bad_tag = Tag(0x9999, 0x9999)
        dim_seq[idx].DimensionIndexPointer = bad_tag

        return self._make_record(
            "DimensionIndexSequence/DimensionIndexPointer",
            "<valid tag>",
            f"({bad_tag.group:04X},{bad_tag.elem:04X}) (non-existent)",
            "invalid_index_pointer",
        )

    def _attack_index_values_length_mismatch(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Set DimensionIndexValues with wrong number of elements."""
        self._ensure_dimension_index_seq(dataset)
        self._ensure_per_frame_index_values(dataset)

        dim_count = len(dataset.DimensionIndexSequence)
        # Give wrong number of index values to a random frame
        pfg = dataset.PerFrameFunctionalGroupsSequence
        frame_idx = random.randint(0, len(pfg) - 1)

        if not hasattr(pfg[frame_idx], "FrameContentSequence"):
            fc = Dataset()
            pfg[frame_idx].FrameContentSequence = Sequence([fc])

        # Wrong length: either too few or too many
        wrong_counts = [0, 1, dim_count + 5, dim_count * 3]
        wrong_count = wrong_counts[random.randint(0, len(wrong_counts) - 1)]
        pfg[frame_idx].FrameContentSequence[0].DimensionIndexValues = [1] * wrong_count

        return self._make_record(
            "DimensionIndexValues",
            f"{dim_count} values (matches dimensions)",
            f"{wrong_count} values (frame {frame_idx + 1})",
            "index_values_length_mismatch",
            frame_number=frame_idx + 1,
        )

    def _attack_missing_index_values(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Remove DimensionIndexValues from random frames."""
        self._ensure_dimension_index_seq(dataset)
        self._ensure_per_frame_index_values(dataset)

        pfg = dataset.PerFrameFunctionalGroupsSequence
        # Remove index values from ~half the frames
        removed_frames = []
        for i in range(len(pfg)):
            if random.random() < 0.5:
                if hasattr(pfg[i], "FrameContentSequence"):
                    fc = pfg[i].FrameContentSequence[0]
                    if hasattr(fc, "DimensionIndexValues"):
                        del fc.DimensionIndexValues
                        removed_frames.append(i + 1)

        if not removed_frames:
            # Guarantee at least one removal
            fc = pfg[0].FrameContentSequence[0]
            if hasattr(fc, "DimensionIndexValues"):
                del fc.DimensionIndexValues
            removed_frames = [1]

        return self._make_record(
            "DimensionIndexValues",
            "<present on all frames>",
            f"<missing on frames {removed_frames[:5]}{'...' if len(removed_frames) > 5 else ''}>",
            "missing_index_values",
            removed_count=len(removed_frames),
        )

    def _attack_out_of_range_index_values(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Set DimensionIndexValues to invalid values (negative, zero, huge)."""
        self._ensure_dimension_index_seq(dataset)
        self._ensure_per_frame_index_values(dataset)

        pfg = dataset.PerFrameFunctionalGroupsSequence
        dim_count = len(dataset.DimensionIndexSequence)
        frame_idx = random.randint(0, len(pfg) - 1)

        _types = ["negative", "zero", "huge", "mixed"]
        bad_values_type = _types[random.randint(0, len(_types) - 1)]
        if bad_values_type == "negative":
            bad_values = [-1] * dim_count
        elif bad_values_type == "zero":
            bad_values = [0] * dim_count
        elif bad_values_type == "huge":
            bad_values = [2147483647] * dim_count
        else:  # mixed
            bad_values = [-1, 0, 2147483647, -999][:dim_count]
            while len(bad_values) < dim_count:
                bad_values.append(-1)

        pfg[frame_idx].FrameContentSequence[0].DimensionIndexValues = bad_values

        return self._make_record(
            "DimensionIndexValues",
            "<valid indices>",
            f"{bad_values_type}: {bad_values} (frame {frame_idx + 1})",
            "out_of_range_index_values",
            frame_number=frame_idx + 1,
            value_type=bad_values_type,
        )

    def _attack_organization_type_mismatch(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Set DimensionOrganizationType inconsistent with actual structure."""
        self._ensure_dimension_index_seq(dataset)

        # Claim 3D organization but only provide 1 dimension index
        dataset.DimensionOrganizationType = "3D"
        # Keep only 1 dimension in the sequence
        if len(dataset.DimensionIndexSequence) > 1:
            dataset.DimensionIndexSequence = Sequence(
                [dataset.DimensionIndexSequence[0]]
            )

        return self._make_record(
            "DimensionOrganizationType",
            "<consistent>",
            "3D with 1 dimension index",
            "organization_type_mismatch",
        )

    def _attack_empty_dimension_sequence(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Set DimensionIndexSequence to empty while frames have index values."""
        self._ensure_dimension_index_seq(dataset)
        self._ensure_per_frame_index_values(dataset)

        original_count = len(dataset.DimensionIndexSequence)
        dataset.DimensionIndexSequence = Sequence([])

        return self._make_record(
            "DimensionIndexSequence",
            f"{original_count} items",
            "0 items (empty, but frames have DimensionIndexValues)",
            "empty_dimension_sequence",
        )

    def _attack_duplicate_dimension_pointers(
        self, dataset: Dataset
    ) -> MultiFrameMutationRecord:
        """Create multiple dimension index items pointing to the same tag."""
        dim_seq = self._ensure_dimension_index_seq(dataset)

        # Add duplicate items all pointing to ImagePositionPatient
        dup_tag = Tag(0x0020, 0x0032)  # ImagePositionPatient
        for _ in range(3):
            dup_item = Dataset()
            dup_item.DimensionIndexPointer = dup_tag
            dup_item.FunctionalGroupPointer = Tag(0x0020, 0x9113)
            dim_seq.append(dup_item)

        return self._make_record(
            "DimensionIndexSequence",
            "<unique pointers>",
            f"4 items all pointing to ({dup_tag.group:04X},{dup_tag.elem:04X})",
            "duplicate_dimension_pointers",
        )

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply dimension index module mutations."""
        handlers = {
            "invalid_index_pointer": self._attack_invalid_index_pointer,
            "index_values_length_mismatch": self._attack_index_values_length_mismatch,
            "missing_index_values": self._attack_missing_index_values,
            "out_of_range_index_values": self._attack_out_of_range_index_values,
            "organization_type_mismatch": self._attack_organization_type_mismatch,
            "empty_dimension_sequence": self._attack_empty_dimension_sequence,
            "duplicate_dimension_pointers": self._attack_duplicate_dimension_pointers,
        }
        records: list[MultiFrameMutationRecord] = []
        for _ in range(mutation_count):
            attack_type = random.choice(self._ATTACK_TYPES)
            records.append(handlers[attack_type](dataset))
        return dataset, records


__all__ = ["DimensionIndexStrategy"]
