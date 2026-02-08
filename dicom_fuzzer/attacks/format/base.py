"""Base class for DICOM format fuzzers.

All format fuzzers inherit from FormatFuzzerBase and implement
the mutate() method and strategy_name property.

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydicom.dataset import Dataset

    from dicom_fuzzer.core.types import MutationSeverity


class FormatFuzzerBase(ABC):
    """Abstract base class for DICOM format fuzzers.

    All format fuzzers must inherit from this class and implement
    the mutate() method and strategy_name property.

    Conforms to the MutationStrategy protocol defined in
    dicom_fuzzer.core.mutation.mutator so all fuzzers can be
    registered and orchestrated through DicomMutator.

    """

    @abstractmethod
    def mutate(
        self, dataset: Dataset, severity: MutationSeverity | None = None
    ) -> Dataset:
        """Apply mutations to a DICOM dataset.

        Args:
            dataset: pydicom Dataset to mutate
            severity: Optional mutation severity level (unused by most fuzzers)

        Returns:
            The mutated Dataset (same object, modified in place)

        """

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""

    def get_strategy_name(self) -> str:
        """Protocol-compatible wrapper around strategy_name property."""
        return self.strategy_name

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can mutate the dataset. Override if needed."""
        return True


__all__ = ["FormatFuzzerBase"]
