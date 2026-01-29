"""Robustness fuzzing strategies for DICOM parser edge case testing.

This subpackage contains fuzzers that test parser robustness by generating
edge cases and malformed data. Unlike exploit patterns, these are for
discovering unknown bugs through random mutations.

Fuzzers:
- HeaderFuzzer: VR and tag mutations (all 27 DICOM VRs)
- PixelFuzzer: Image dimension and pixel data mutations
- StructureFuzzer: File structure and length field mutations
- MetadataFuzzer: Patient/study metadata mutations
- SequenceFuzzer: Nested sequence and item structure attacks
- CompressedPixelFuzzer: JPEG/JPEG2000/RLE encapsulation corruption
- EncodingFuzzer: Character set and text encoding violations
- ConformanceFuzzer: SOP Class and Transfer Syntax validation
- ReferenceFuzzer: Link integrity and reference chain attacks
- PrivateTagFuzzer: Vendor-specific tag violations
"""

from .compressed_pixel_fuzzer import CompressedPixelFuzzer
from .conformance_fuzzer import ConformanceFuzzer
from .encoding_fuzzer import EncodingFuzzer
from .header_fuzzer import HeaderFuzzer
from .metadata_fuzzer import MetadataFuzzer
from .pixel_fuzzer import PixelFuzzer
from .private_tag_fuzzer import PrivateTagFuzzer
from .reference_fuzzer import ReferenceFuzzer
from .sequence_fuzzer import SequenceFuzzer
from .structure_fuzzer import StructureFuzzer

__all__ = [
    "CompressedPixelFuzzer",
    "ConformanceFuzzer",
    "EncodingFuzzer",
    "HeaderFuzzer",
    "MetadataFuzzer",
    "PixelFuzzer",
    "PrivateTagFuzzer",
    "ReferenceFuzzer",
    "SequenceFuzzer",
    "StructureFuzzer",
]
