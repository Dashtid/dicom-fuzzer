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

    """

    @abstractmethod
    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply mutations to a DICOM dataset.

        Args:
            dataset: pydicom Dataset to mutate

        Returns:
            The mutated Dataset (same object, modified in place)

        """

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""


__all__ = ["FormatFuzzerBase"]
