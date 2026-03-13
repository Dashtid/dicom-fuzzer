"""DICOM File I/O -- Parsing, Series Detection, and Writing.

Exports:
- DicomParser: parse individual DICOM files
- DicomSeries: dataclass representing a 3D series (slices sharing a SeriesInstanceUID)
- SeriesDetector: group DICOM files into series by SeriesInstanceUID
"""

from .parser import DicomParser
from .series import DicomSeries
from .series_detector import SeriesDetector

__all__ = [
    "DicomParser",
    "DicomSeries",
    "SeriesDetector",
]
