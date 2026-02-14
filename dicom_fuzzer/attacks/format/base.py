"""Base class for DICOM format fuzzers.

All format fuzzers inherit from FormatFuzzerBase and implement
the mutate() method and strategy_name property.

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class FormatFuzzerBase(ABC):
    """Abstract base class for DICOM format fuzzers.

    All format fuzzers must inherit from this class and implement
    the mutate() method and strategy_name property.

    Conforms to the MutationStrategy protocol defined in
    dicom_fuzzer.core.mutation.mutator so all fuzzers can be
    registered and orchestrated through DicomMutator.

    Subclasses must be instantiable with no arguments because
    DicomMutator registers them via fuzzer_cls().

    """

    def __init__(self) -> None:  # noqa: B027
        """Initialize the fuzzer. Subclasses may override but must accept no arguments."""

    @abstractmethod
    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply mutations to a DICOM dataset.

        The engine copies the dataset before passing it here, so
        the original is never modified. This method mutates the
        copy in place and returns it.

        Args:
            dataset: pydicom Dataset to mutate (already a copy)

        Returns:
            The mutated Dataset

        """

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can mutate the dataset. Override if needed."""
        return True


__all__ = ["FormatFuzzerBase"]
