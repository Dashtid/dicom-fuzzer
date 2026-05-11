"""Shared/per-frame functional-group ambiguity mutation strategy.

PS3.3 C.7.6.16.1.1 requires a functional-group sequence to appear in
*either* SharedFunctionalGroupsSequence *or* PerFrameFunctionalGroups-
Sequence, never both. Enhanced multi-frame parsers rely on that mutual
exclusivity -- they read a macro from one place without checking the
other. Placing the same macro in both is an illegal state that probes:

- parsers that read only the first/last copy found (silent wrong value)
- viewers whose precedence logic is undefined when the copies agree
  vs. disagree
- code that crashes on the unexpected duplicate

Distinct from SharedGroupStrategy's narrow ``conflict_with_per_frame``
attack-type (PixelMeasures only, per-frame[0] only, conflicting
values): this strategy covers four functional-group macros, both
agree-and-disagree value modes, and all-frames vs. partial duplication.

Targets: Enhanced MR/CT/PET multi-frame parsers, MPR/oblique reformat
pipelines, window/level display logic.
"""

from __future__ import annotations

import copy
import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from .format_base import MultiFrameFuzzerBase, MultiFrameMutationRecord

# Functional-group macros we duplicate across both sequences. Each
# builder returns the *inner* dataset that goes inside the macro
# sequence; the macro itself is Sequence([inner]). ``variant`` keys
# three distinct value sets so the agree/disagree modes can pick the
# same or different ones.


def _build_pixel_measures(variant: int) -> Dataset:
    spacing = [(1.0 + variant), (1.0 + variant)]
    inner = Dataset()
    inner.PixelSpacing = spacing
    inner.SliceThickness = float(1 + variant)
    return inner


def _build_plane_orientation(variant: int) -> Dataset:
    # Three distinct unit-ish orientation triplets.
    orientations = [
        [1.0, 0.0, 0.0, 0.0, 1.0, 0.0],
        [0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        [1.0, 0.0, 0.0, 0.0, 0.0, 1.0],
    ]
    inner = Dataset()
    inner.ImageOrientationPatient = orientations[variant % 3]
    return inner


def _build_plane_position(variant: int) -> Dataset:
    inner = Dataset()
    inner.ImagePositionPatient = [float(variant), float(variant), float(variant)]
    return inner


def _build_frame_voilut(variant: int) -> Dataset:
    inner = Dataset()
    inner.WindowCenter = float(40 + variant * 10)
    inner.WindowWidth = float(400 + variant * 100)
    return inner


_MACRO_BUILDERS = {
    "PixelMeasuresSequence": _build_pixel_measures,
    "PlaneOrientationSequence": _build_plane_orientation,
    "PlanePositionSequence": _build_plane_position,
    "FrameVOILUTSequence": _build_frame_voilut,
}


class SharedPerFrameAmbiguityStrategy(MultiFrameFuzzerBase):
    """Duplicate functional-group macros across shared + per-frame sequences."""

    _ATTACK_TYPES = [
        "identical_in_both",
        "conflicting_in_both",
        "partial_per_frame",
        "all_macros_conflicting",
    ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "shared_per_frame_ambiguity"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate multiframe datasets (NumberOfFrames > 1)."""
        try:
            return int(getattr(dataset, "NumberOfFrames", 1)) > 1
        except (ValueError, TypeError):
            return False

    # -- helpers -------------------------------------------------------

    def _ensure_sfg(self, dataset: Dataset) -> Dataset:
        """Return the first item of SharedFunctionalGroupsSequence, creating it."""
        sfg = getattr(dataset, "SharedFunctionalGroupsSequence", None)
        if sfg is None or len(sfg) == 0:
            dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])
        return dataset.SharedFunctionalGroupsSequence[0]  # type: ignore[no-any-return]

    def _ensure_per_frame(self, dataset: Dataset, count: int) -> Sequence:
        """Ensure PerFrameFunctionalGroupsSequence has at least *count* items."""
        per_frame = getattr(dataset, "PerFrameFunctionalGroupsSequence", None)
        if per_frame is None or len(per_frame) < count:
            existing = list(per_frame) if per_frame else []
            while len(existing) < count:
                existing.append(Dataset())
            dataset.PerFrameFunctionalGroupsSequence = Sequence(existing)
        return dataset.PerFrameFunctionalGroupsSequence  # type: ignore[no-any-return]

    def _set_macro(self, holder: Dataset, macro: str, inner: Dataset) -> None:
        """Attach Sequence([inner]) under *macro* on *holder*."""
        setattr(holder, macro, Sequence([inner]))

    def _record(
        self, tag: str, mutated: str, attack_type: str, **extra: object
    ) -> MultiFrameMutationRecord:
        details: dict[str, object] = {"attack_type": attack_type}
        details.update(extra)
        return MultiFrameMutationRecord(
            strategy=self.strategy_name,
            tag=tag,
            original_value="<spec-exclusive>",
            mutated_value=mutated,
            severity=self.severity,
            details=details,
        )

    # -- attacks -------------------------------------------------------

    def _attack_identical(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Same macro, same value, in shared + every per-frame item."""
        macro = random.choice(list(_MACRO_BUILDERS))
        n = self._get_frame_count(dataset)
        sfg = self._ensure_sfg(dataset)
        per_frame = self._ensure_per_frame(dataset, n)

        inner = _MACRO_BUILDERS[macro](0)
        self._set_macro(sfg, macro, copy.deepcopy(inner))
        for item in per_frame[:n]:
            self._set_macro(item, macro, copy.deepcopy(inner))
        return self._record(
            macro,
            f"identical copy in shared + {n} per-frame items",
            "identical_in_both",
            macro=macro,
            frame_count=n,
        )

    def _attack_conflicting(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Same macro, different values: variant 1 in shared, variant 2 per-frame."""
        macro = random.choice(list(_MACRO_BUILDERS))
        n = self._get_frame_count(dataset)
        sfg = self._ensure_sfg(dataset)
        per_frame = self._ensure_per_frame(dataset, n)

        self._set_macro(sfg, macro, _MACRO_BUILDERS[macro](1))
        for item in per_frame[:n]:
            self._set_macro(item, macro, _MACRO_BUILDERS[macro](2))
        return self._record(
            macro,
            f"shared=variant1, {n} per-frame items=variant2",
            "conflicting_in_both",
            macro=macro,
            frame_count=n,
        )

    def _attack_partial(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """Macro in shared + only the first half of per-frame items (same value)."""
        macro = random.choice(list(_MACRO_BUILDERS))
        n = self._get_frame_count(dataset)
        half = max(1, n // 2)
        sfg = self._ensure_sfg(dataset)
        per_frame = self._ensure_per_frame(dataset, n)

        inner = _MACRO_BUILDERS[macro](1)
        self._set_macro(sfg, macro, copy.deepcopy(inner))
        for item in per_frame[:half]:
            self._set_macro(item, macro, copy.deepcopy(inner))
        return self._record(
            macro,
            f"shared + first {half}/{n} per-frame items only",
            "partial_per_frame",
            macro=macro,
            frame_count=n,
            partial_count=half,
        )

    def _attack_all_macros(self, dataset: Dataset) -> MultiFrameMutationRecord:
        """All four macros at once, conflicting values, shared vs. every per-frame."""
        n = self._get_frame_count(dataset)
        sfg = self._ensure_sfg(dataset)
        per_frame = self._ensure_per_frame(dataset, n)

        for macro, builder in _MACRO_BUILDERS.items():
            self._set_macro(sfg, macro, builder(1))
            for item in per_frame[:n]:
                self._set_macro(item, macro, builder(2))
        return self._record(
            "+".join(_MACRO_BUILDERS),
            f"all {len(_MACRO_BUILDERS)} macros conflicting across shared + {n} frames",
            "all_macros_conflicting",
            frame_count=n,
            macro_count=len(_MACRO_BUILDERS),
        )

    # -- dispatch ------------------------------------------------------

    def _mutate_impl(
        self, dataset: Dataset, mutation_count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply shared/per-frame ambiguity mutations."""
        handlers = {
            "identical_in_both": self._attack_identical,
            "conflicting_in_both": self._attack_conflicting,
            "partial_per_frame": self._attack_partial,
            "all_macros_conflicting": self._attack_all_macros,
        }
        records: list[MultiFrameMutationRecord] = []
        for _ in range(mutation_count):
            attack_type = random.choice(self._ATTACK_TYPES)
            records.append(handlers[attack_type](dataset))
        return dataset, records


__all__ = ["SharedPerFrameAmbiguityStrategy"]
