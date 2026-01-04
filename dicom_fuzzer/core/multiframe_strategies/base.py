"""Base class for multi-frame mutation strategies.

This module provides the abstract base class that all mutation strategies
must implement.

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydicom.dataset import Dataset

    from dicom_fuzzer.core.multiframe_types import MultiFrameMutationRecord


class MutationStrategyBase(ABC):
    """Abstract base class for multi-frame mutation strategies.

    All mutation strategies must inherit from this class and implement
    the mutate() method.

    Attributes:
        severity: Mutation severity level (minimal, moderate, aggressive, extreme)

    """

    def __init__(self, severity: str = "moderate"):
        """Initialize the strategy.

        Args:
            severity: Mutation severity level

        """
        self.severity = severity

    @abstractmethod
    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply mutation to dataset.

        Args:
            dataset: pydicom Dataset to mutate
            mutation_count: Number of mutations to apply

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        pass  # Abstract method - implemented by subclasses

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Return the strategy name for record-keeping."""
        pass  # Abstract property - implemented by subclasses


__all__ = ["MutationStrategyBase"]
