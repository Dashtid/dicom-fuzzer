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

    def __init__(self) -> None:
        """Initialize the fuzzer. Subclasses may override but must accept no arguments."""
        self.last_variant: str | None = (
            None  # Set by mutate() to record chosen sub-attack(s)
        )
        self._applied_binary_mutations: list[
            str
        ] = []  # Set by mutate_bytes() to record which binary attacks ran

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

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Apply binary-level mutations to an already-serialized DICOM byte stream.

        Called by the engine after mutate() and dcmwrite(), giving the strategy
        a second pass on the raw bytes. Override in subclasses that need to
        corrupt data that pydicom would correct during serialization (e.g. tag
        ordering, duplicate tags, length fields).

        The default implementation returns file_data unchanged.

        Args:
            file_data: Complete DICOM file bytes (preamble + DICM + elements)

        Returns:
            Possibly-modified byte string

        """
        return file_data


__all__ = ["FormatFuzzerBase"]
