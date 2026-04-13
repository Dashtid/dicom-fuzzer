"""DICOM file format fuzzing attacks.

This subpackage contains fuzzers targeting the DICOM file format: tags, VRs,
encoding, pixel data, sequences, structure, compression, and conformance.
These generate edge cases and malformed data for discovering parser bugs.

Generic fuzzers (work on any SOP class):
- CalibrationFuzzer: Deterministic calibration mutations for testing
- DeflateBombFuzzer: Decompression bomb via Deflated LE transfer syntax
- DicomdirFuzzer: DICOMDIR path traversal and deep-nesting attacks
- CompressedPixelFuzzer: JPEG/JPEG2000/RLE encapsulation corruption
- ConformanceFuzzer: SOP Class and Transfer Syntax validation
- DictionaryFuzzer: Domain-aware mutations from DICOM data dictionaries
- EmptyValueFuzzer: Present-but-empty tag mutations (.NET Get<T>() crash pattern)
- EncodingFuzzer: Character set and text encoding violations
- HeaderFuzzer: VR and tag mutations (all 27 DICOM VRs)
- MetadataFuzzer: Patient/study metadata mutations
- PixelFuzzer: Image dimension and pixel data mutations
- PixelReencodingFuzzer: Re-encode uncompressed pixels as RLE then mutate
- PrivateTagFuzzer: Vendor-specific tag violations
- ReferenceFuzzer: Link integrity and reference chain attacks
- SequenceFuzzer: Nested sequence and item structure attacks
- StructureFuzzer: File structure and length field mutations
- StructuredReportFuzzer: SR ContentSequence tree corruption, type mismatch, and nesting attacks
- WaveformFuzzer: Waveform/ECG channel-count/sample-count overflow and OOB attacks

Modality-specific fuzzers (require matching seed files):
- EncapsulatedPdfFuzzer: Encapsulated PDF document payload mutations
- NuclearMedicineFuzzer: NM energy window, detector, rotation attacks
- PetFuzzer: PET SUV calibration chain and decay parameter attacks
- RTDoseFuzzer: RT Dose grid scaling and DVH structure attacks
- RTStructureSetFuzzer: RT Structure Set contour and ROI attacks
- SegmentationFuzzer: Segmentation segment/frame mapping attacks
- UltrasoundFuzzer: US frame-count, Doppler region, and pixel geometry attacks
"""

from .base import FormatFuzzerBase
from .calibration_fuzzer import CalibrationFuzzer
from .compressed_pixel_fuzzer import CompressedPixelFuzzer
from .conformance_fuzzer import ConformanceFuzzer
from .deflate_bomb_fuzzer import DeflateBombFuzzer
from .dicomdir_fuzzer import DicomdirFuzzer
from .dictionary_fuzzer import DictionaryFuzzer
from .empty_value_fuzzer import EmptyValueFuzzer
from .encapsulated_pdf_fuzzer import EncapsulatedPdfFuzzer
from .encoding_fuzzer import EncodingFuzzer
from .header_fuzzer import HeaderFuzzer
from .mammography_fuzzer import MammographyFuzzer
from .metadata_fuzzer import MetadataFuzzer
from .nm_fuzzer import NuclearMedicineFuzzer
from .pet_fuzzer import PetFuzzer
from .pixel_fuzzer import PixelFuzzer
from .pixel_reencoding_fuzzer import PixelReencodingFuzzer
from .private_tag_fuzzer import PrivateTagFuzzer
from .reference_fuzzer import ReferenceFuzzer
from .rt_dose_fuzzer import RTDoseFuzzer
from .rtss_fuzzer import RTStructureSetFuzzer
from .seg_fuzzer import SegmentationFuzzer
from .sequence_fuzzer import SequenceFuzzer
from .sr_fuzzer import StructuredReportFuzzer
from .structure_fuzzer import StructureFuzzer
from .ultrasound_fuzzer import UltrasoundFuzzer
from .waveform_fuzzer import WaveformFuzzer

__all__ = [
    "CalibrationFuzzer",
    "CompressedPixelFuzzer",
    "DeflateBombFuzzer",
    "DicomdirFuzzer",
    "ConformanceFuzzer",
    "DictionaryFuzzer",
    "EmptyValueFuzzer",
    "EncapsulatedPdfFuzzer",
    "EncodingFuzzer",
    "FormatFuzzerBase",
    "HeaderFuzzer",
    "MammographyFuzzer",
    "MetadataFuzzer",
    "NuclearMedicineFuzzer",
    "PetFuzzer",
    "PixelFuzzer",
    "PixelReencodingFuzzer",
    "PrivateTagFuzzer",
    "RTDoseFuzzer",
    "RTStructureSetFuzzer",
    "ReferenceFuzzer",
    "SegmentationFuzzer",
    "SequenceFuzzer",
    "StructuredReportFuzzer",
    "StructureFuzzer",
    "UltrasoundFuzzer",
    "WaveformFuzzer",
]
