"""Attack modules for DICOM fuzzing.

Organized into subpackages:
- format/: DICOM file format edge case testing (tags, encoding, structure)
- series/: Multi-slice 3D volume mutations
- network/: Network protocol fuzzing (PDU, TLS, DIMSE, stateful)
- multiframe/: Multi-frame mutation strategies

Note: CVE replication lives in dicom_fuzzer.cve module.
CVE file generation is NOT fuzzing - it produces deterministic output.
"""

# Format fuzzers (DICOM file format edge cases)
from .format import (
    CalibrationFuzzer,
    CompressedPixelFuzzer,
    ConformanceFuzzer,
    DictionaryFuzzer,
    EncodingFuzzer,
    HeaderFuzzer,
    MetadataFuzzer,
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
    # Format fuzzers
    "CalibrationFuzzer",
    "CompressedPixelFuzzer",
    "ConformanceFuzzer",
    "DictionaryFuzzer",
    "EncodingFuzzer",
    "HeaderFuzzer",
    "MetadataFuzzer",
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
