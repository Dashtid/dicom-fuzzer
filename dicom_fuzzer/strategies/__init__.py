"""Mutation strategies for DICOM fuzzing."""

from .parallel_mutator import ParallelSeriesMutator, get_optimal_workers
from .security_patterns import SecurityPatternFuzzer
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
    # Security patterns (v1.3.0)
    "SecurityPatternFuzzer",
]
