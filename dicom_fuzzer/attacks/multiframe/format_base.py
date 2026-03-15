"""Base class for multi-frame format fuzzers.

Bridges MutationStrategyBase semantics into the FormatFuzzerBase pipeline.
All multiframe strategies inherit from this class so they can be registered
in DicomMutator._register_default_strategies() alongside format fuzzers.

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dicom_fuzzer.attacks.format.base import FormatFuzzerBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


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

    def _get_frame_count(self, dataset: Dataset) -> int:
        """Return the number of frames declared in the dataset (1 if absent).

        Capped at _MAX_FRAME_COUNT to prevent allocation failures when the
        tag contains an attacker-controlled large value.
        """
        if not hasattr(dataset, "NumberOfFrames"):
            return 1
        try:
            return min(int(dataset.NumberOfFrames), self._MAX_FRAME_COUNT)
        except (ValueError, TypeError):
            return 1

    def _calculate_frame_size(self, dataset: Dataset) -> int:
        """Return the expected byte size of a single frame (capped for safety)."""
        rows = min(getattr(dataset, "Rows", 0), 4096)
        cols = min(getattr(dataset, "Columns", 0), 4096)
        bits_allocated = min(getattr(dataset, "BitsAllocated", 8), 64)
        samples_per_pixel = min(getattr(dataset, "SamplesPerPixel", 1), 4)
        return rows * cols * (bits_allocated // 8) * samples_per_pixel


__all__ = ["MultiFrameFuzzerBase"]
