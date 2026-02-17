"""DICOM File I/O -- Parsing, Validation, Series Detection, and Writing.

Exports:
- DicomParser: parse and validate individual DICOM files
- DicomSeries: dataclass representing a 3D series (slices sharing a SeriesInstanceUID)
- SeriesDetector: group DICOM files into series by SeriesInstanceUID
- SeriesWriter / SeriesMetadata: write fuzzed series to disk with metadata tracking
- DicomValidator: validate datasets for structural correctness and security
"""

from .dicom_series import DicomSeries
from .parser import DicomParser
from .series_detector import SeriesDetector
from .series_writer import SeriesMetadata, SeriesWriter
from .validator import DicomValidator

__all__ = [
    "DicomParser",
    "DicomSeries",
    "DicomValidator",
    "SeriesDetector",
    "SeriesMetadata",
    "SeriesWriter",
]
