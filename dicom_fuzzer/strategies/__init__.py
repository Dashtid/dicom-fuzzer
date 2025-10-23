"""Mutation strategies for DICOM fuzzing."""

from .parallel_mutator import ParallelSeriesMutator, get_optimal_workers
from .series_mutator import (
    Series3DMutator,
    SeriesMutationRecord,
    SeriesMutationStrategy,
)

__all__ = [
    # 3D Series mutation (v2.0.0-alpha)
    "Series3DMutator",
    "SeriesMutationRecord",
    "SeriesMutationStrategy",
    # Parallel processing (v2.0.0-alpha Phase 4)
    "ParallelSeriesMutator",
    "get_optimal_workers",
]
