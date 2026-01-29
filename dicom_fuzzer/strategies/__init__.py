"""Mutation strategies for DICOM fuzzing.

Organized into subpackages:
- robustness/: Edge case testing for parser robustness (random mutations)
- series/: Multi-slice 3D volume mutations

Note: CVE replication has been moved to dicom_fuzzer.cve module.
CVE file generation is NOT fuzzing - it produces deterministic output.
"""

# Robustness fuzzers (edge case testing)
from .robustness import (
    CompressedPixelFuzzer,
    ConformanceFuzzer,
    EncodingFuzzer,
    HeaderFuzzer,
    MetadataFuzzer,
    MultiFrameFuzzer,
    PixelFuzzer,
    PrivateTagFuzzer,
    ReferenceFuzzer,
    SequenceFuzzer,
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
    "CompressedPixelFuzzer",
    "ConformanceFuzzer",
    "EncodingFuzzer",
    "HeaderFuzzer",
    "MetadataFuzzer",
    "MultiFrameFuzzer",
    "PixelFuzzer",
    "PrivateTagFuzzer",
    "ReferenceFuzzer",
    "SequenceFuzzer",
    "StructureFuzzer",
    # Series mutations
    "Series3DMutator",
    "SeriesMutationRecord",
    "SeriesMutationStrategy",
    # Parallel processing
    "ParallelSeriesMutator",
    "get_optimal_workers",
]
