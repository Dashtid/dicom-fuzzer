"""DICOM file format fuzzing attacks.

This subpackage contains fuzzers targeting the DICOM file format: tags, VRs,
encoding, pixel data, sequences, structure, compression, and conformance.
These generate edge cases and malformed data for discovering parser bugs.

Generic fuzzers (work on any SOP class):
- CalibrationFuzzer: Deterministic calibration mutations for testing
- CompressedPixelFuzzer: JPEG/JPEG2000/RLE encapsulation corruption
- ConformanceFuzzer: SOP Class and Transfer Syntax validation
- DictionaryFuzzer: Domain-aware mutations from DICOM data dictionaries
- EncodingFuzzer: Character set and text encoding violations
- HeaderFuzzer: VR and tag mutations (all 27 DICOM VRs)
- MetadataFuzzer: Patient/study metadata mutations
- PixelFuzzer: Image dimension and pixel data mutations
- PrivateTagFuzzer: Vendor-specific tag violations
- ReferenceFuzzer: Link integrity and reference chain attacks
- SequenceFuzzer: Nested sequence and item structure attacks
- StructureFuzzer: File structure and length field mutations

Modality-specific fuzzers (require matching seed files):
- EncapsulatedPdfFuzzer: Encapsulated PDF document payload mutations
- NuclearMedicineFuzzer: NM energy window, detector, rotation attacks
- PetFuzzer: PET SUV calibration chain and decay parameter attacks
- RTDoseFuzzer: RT Dose grid scaling and DVH structure attacks
- RTStructureSetFuzzer: RT Structure Set contour and ROI attacks
- SegmentationFuzzer: Segmentation segment/frame mapping attacks
"""

from .base import FormatFuzzerBase
from .calibration_fuzzer import CalibrationFuzzer
from .compressed_pixel_fuzzer import CompressedPixelFuzzer
from .conformance_fuzzer import ConformanceFuzzer
from .dictionary_fuzzer import DictionaryFuzzer
from .encapsulated_pdf_fuzzer import EncapsulatedPdfFuzzer
from .encoding_fuzzer import EncodingFuzzer
from .header_fuzzer import HeaderFuzzer
from .metadata_fuzzer import MetadataFuzzer
from .nm_fuzzer import NuclearMedicineFuzzer
from .pet_fuzzer import PetFuzzer
from .pixel_fuzzer import PixelFuzzer
from .private_tag_fuzzer import PrivateTagFuzzer
from .reference_fuzzer import ReferenceFuzzer
from .rt_dose_fuzzer import RTDoseFuzzer
from .rtss_fuzzer import RTStructureSetFuzzer
from .seg_fuzzer import SegmentationFuzzer
from .sequence_fuzzer import SequenceFuzzer
from .structure_fuzzer import StructureFuzzer

__all__ = [
    "CalibrationFuzzer",
    "CompressedPixelFuzzer",
    "ConformanceFuzzer",
    "DictionaryFuzzer",
    "EncapsulatedPdfFuzzer",
    "EncodingFuzzer",
    "FormatFuzzerBase",
    "HeaderFuzzer",
    "MetadataFuzzer",
    "NuclearMedicineFuzzer",
    "PetFuzzer",
    "PixelFuzzer",
    "PrivateTagFuzzer",
    "RTDoseFuzzer",
    "RTStructureSetFuzzer",
    "ReferenceFuzzer",
    "SegmentationFuzzer",
    "SequenceFuzzer",
    "StructureFuzzer",
]
