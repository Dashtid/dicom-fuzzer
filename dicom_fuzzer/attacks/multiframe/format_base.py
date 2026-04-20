"""Base class for multi-frame format fuzzers.

Bridges MutationStrategyBase semantics into the FormatFuzzerBase pipeline.
All multiframe strategies inherit from this class so they can be registered
in DicomMutator._register_default_strategies() alongside format fuzzers.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.attacks.format.base import FormatFuzzerBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


@dataclass
class MultiFrameMutationRecord:
    """Record of a multi-frame mutation.

    Attributes:
        strategy: Name of the mutation strategy applied
        frame_number: Which frame was mutated (None = all/dataset-level)
        tag: DICOM tag that was mutated
        original_value: Value before mutation
        mutated_value: Value after mutation
        severity: Mutation severity level
        details: Additional mutation details

    """

    strategy: str
    frame_number: int | None = (
        None  # Which frame was mutated (None = all/dataset-level)
    )
    tag: str | None = None
    original_value: str | None = None
    mutated_value: str | None = None
    severity: str = "moderate"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary for serialization.

        Returns:
            Dictionary representation of the record

        """
        data = {
            "strategy": self.strategy,
            "frame_number": self.frame_number,
            "tag": self.tag,
            "original_value": str(self.original_value)
            if self.original_value is not None
            else None,
            "mutated_value": str(self.mutated_value)
            if self.mutated_value is not None
            else None,
            "severity": self.severity,
            "details": self.details,
        }
        return data


class MultiFrameFuzzerBase(FormatFuzzerBase):
    """Abstract base class for multi-frame DICOM fuzzers.

    Extends FormatFuzzerBase with helpers shared across all multiframe
    strategies: _get_frame_count() and _calculate_frame_size().

    Severity is kept as a class attribute (default "moderate") so that
    MultiFrameMutationRecord entries remain meaningful even though the
    FormatFuzzerBase pipeline does not use it.

    """

    severity: str = "moderate"

    # Maximum frame count to iterate over -- prevents OOM when NumberOfFrames
    # has been set to a huge value by a prior FrameCountMismatch mutation.
    _MAX_FRAME_COUNT: int = 100

    def _mutate_impl(
        self, dataset: Dataset, count: int
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply *count* mutations. Subclasses must override."""
        raise NotImplementedError

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply one mutation and capture the attack type as last_variant."""
        ds, records = self._mutate_impl(dataset, 1)
        if records:
            self.last_variant = records[0].details.get("attack_type", "")
        return ds

    @staticmethod
    def _safe_int(value: Any, default: int) -> int:
        """Coerce a pydicom value to int, returning default on failure.

        Upstream strategies may set image-geometry tags to strings or
        negative values; downstream code that does arithmetic or struct
        packing needs a well-formed positive int.
        """
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def _get_frame_count(self, dataset: Dataset) -> int:
        """Return the number of frames declared in the dataset (1 if absent).

        Capped at _MAX_FRAME_COUNT to prevent allocation failures when the
        tag contains an attacker-controlled large value. Clamped to >= 1
        because negative counts break struct-pack format strings
        (`struct.pack(f"<{-5}I", ...)` -> "bad char in struct format").
        """
        if not hasattr(dataset, "NumberOfFrames"):
            return 1
        raw = self._safe_int(dataset.NumberOfFrames, 1)
        return max(1, min(raw, self._MAX_FRAME_COUNT))

    def _calculate_frame_size(self, dataset: Dataset) -> int:
        """Return the expected byte size of a single frame (capped for safety)."""
        rows = min(self._safe_int(getattr(dataset, "Rows", 0), 0), 4096)
        cols = min(self._safe_int(getattr(dataset, "Columns", 0), 0), 4096)
        bits_allocated = min(
            self._safe_int(getattr(dataset, "BitsAllocated", 8), 8), 64
        )
        samples_per_pixel = min(
            self._safe_int(getattr(dataset, "SamplesPerPixel", 1), 1), 4
        )
        return rows * cols * (bits_allocated // 8) * samples_per_pixel


__all__ = ["MultiFrameFuzzerBase", "MultiFrameMutationRecord"]
