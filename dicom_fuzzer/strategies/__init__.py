"""Mutation strategies for DICOM fuzzing.

Organized into subpackages:
- robustness/: Edge case testing for parser robustness
- exploit/: CVE-based security validation patterns
- series/: Multi-slice 3D volume mutations
"""

# Exploit patterns (CVE-based security validation)
from .exploit import (
    CVE_MUTATIONS,
    CVECategory,
    CVEFuzzer,
    CVEMutation,
    ExploitPatternApplicator,
    SecurityPatternFuzzer,
    apply_cve_mutation,
    get_available_cves,
    get_mutations_by_category,
)

# Robustness fuzzers (edge case testing)
from .robustness import (
    HeaderFuzzer,
    MetadataFuzzer,
    PixelFuzzer,
    StructureFuzzer,
)

# Series-level mutations
from .series import (
    Series3DMutator,
    SeriesMutationRecord,
    SeriesMutationStrategy,
)

# Parallel processing
from .parallel_mutator import ParallelSeriesMutator, get_optimal_workers

__all__ = [
    # Robustness fuzzers
    "HeaderFuzzer",
    "MetadataFuzzer",
    "PixelFuzzer",
    "StructureFuzzer",
    # Exploit patterns
    "ExploitPatternApplicator",
    "CVEFuzzer",
    "SecurityPatternFuzzer",
    "CVE_MUTATIONS",
    "CVECategory",
    "CVEMutation",
    "apply_cve_mutation",
    "get_available_cves",
    "get_mutations_by_category",
    # Series mutations
    "Series3DMutator",
    "SeriesMutationRecord",
    "SeriesMutationStrategy",
    # Parallel processing
    "ParallelSeriesMutator",
    "get_optimal_workers",
]
