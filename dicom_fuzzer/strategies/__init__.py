"""Mutation strategies for DICOM fuzzing."""

from .cve_fuzzer import CVEFuzzer
from .cve_mutations import (
    CVE_MUTATIONS,
    CVECategory,
    CVEMutation,
    apply_cve_mutation,
    get_available_cves,
    get_mutations_by_category,
)
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
    # CVE-inspired mutations (v1.6.0)
    "CVE_MUTATIONS",
    "CVECategory",
    "CVEMutation",
    "apply_cve_mutation",
    "get_available_cves",
    "get_mutations_by_category",
    # CVE Fuzzer for default pipeline (v1.7.2)
    "CVEFuzzer",
]
