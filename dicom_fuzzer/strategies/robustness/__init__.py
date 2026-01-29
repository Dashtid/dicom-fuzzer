"""Robustness fuzzing strategies for DICOM parser edge case testing.

This subpackage contains fuzzers that test parser robustness by generating
edge cases and malformed data. Unlike exploit patterns, these are for
discovering unknown bugs through random mutations.

Fuzzers:
- HeaderFuzzer: VR and tag mutations
- PixelFuzzer: Image dimension and pixel data mutations
- StructureFuzzer: File structure and length field mutations
- MetadataFuzzer: Patient/study metadata mutations
"""

from .header_fuzzer import HeaderFuzzer
from .metadata_fuzzer import MetadataFuzzer
from .pixel_fuzzer import PixelFuzzer
from .structure_fuzzer import StructureFuzzer

__all__ = [
    "HeaderFuzzer",
    "MetadataFuzzer",
    "PixelFuzzer",
    "StructureFuzzer",
]
