"""Mutation strategies for DICOM fuzzing.

Organized into subpackages:
- robustness/: Edge case testing for parser robustness (random mutations)
- series/: Multi-slice 3D volume mutations
- network/: Network protocol fuzzing (PDU, TLS, DIMSE, stateful)
- multiframe/: Multi-frame mutation strategies

Note: CVE replication has been moved to dicom_fuzzer.cve module.
CVE file generation is NOT fuzzing - it produces deterministic output.
"""

# Robustness fuzzers (edge case testing)
from .robustness import (
    CalibrationFuzzer,
    CompressedPixelFuzzer,
    ConformanceFuzzer,
    DictionaryFuzzer,
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
    ParallelSeriesMutator,
    Series3DMutator,
    SeriesMutationRecord,
    SeriesMutationStrategy,
    StudyMutationStrategy,
    StudyMutator,
    get_optimal_workers,
)

__all__ = [
    # Robustness fuzzers
    "CalibrationFuzzer",
    "CompressedPixelFuzzer",
    "ConformanceFuzzer",
    "DictionaryFuzzer",
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
    "StudyMutator",
    "StudyMutationStrategy",
    # Parallel processing
    "ParallelSeriesMutator",
    "get_optimal_workers",
]
