"""Synthetic DICOM seed generators for SEG, RTSS, and Encapsulated PDF.

These factories create minimal but structurally complete DICOM datasets from
scratch for SOP classes that are rarely present in real-world seed corpora.
Each generated dataset passes the matching format fuzzer's can_mutate() check
so the modality-specific fuzzers (SegmentationFuzzer, RTStructureSetFuzzer,
EncapsulatedPdfFuzzer) can operate without requiring actual clinical input files.

Usage::

    from dicom_fuzzer.core.corpus.synthetic_seeds import SEED_FACTORIES

    dataset = SEED_FACTORIES["seg"]()
    dataset = SEED_FACTORIES["rtss"]()
    dataset = SEED_FACTORIES["pdf"]()
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.sequence import Sequence
from pydicom.uid import UID, ExplicitVRLittleEndian, generate_uid

# SOP class UIDs
_SEG_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.66.4"
_RTSS_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.481.3"
_PDF_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.104.1"

# Minimal valid PDF bytes (well-formed enough to be recognized as PDF)
_MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    b"xref\n0 4\n0000000000 65535 f \n"
    b"0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
    b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n197\n%%EOF\n"
)


def _common_meta(sop_class_uid: str) -> tuple[FileMetaDataset, str, str, str]:
    """Return (file_meta, sop_instance_uid, study_uid, series_uid)."""
    sop_instance_uid = generate_uid()
    study_uid = generate_uid()
    series_uid = generate_uid()

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = UID(sop_class_uid)
    meta.MediaStorageSOPInstanceUID = sop_instance_uid
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.ImplementationClassUID = generate_uid()

    return meta, sop_instance_uid, study_uid, series_uid


def create_seg_seed() -> Dataset:
    """Create a minimal valid DICOM Segmentation Storage dataset.

    Produces a 2-segment binary SEG with a 64x64x2-frame pixel array.
    Passes SegmentationFuzzer.can_mutate() and exercises all four of its
    mutation strategies (SegmentSequence, PerFrameFunctionalGroups,
    BinaryPixelType, ReferencedSeries).

    Returns:
        Dataset configured as Segmentation Storage (1.2.840.10008.5.1.4.1.1.66.4).

    """
    meta, sop_uid, study_uid, series_uid = _common_meta(_SEG_SOP_CLASS_UID)

    ds = Dataset()
    ds.file_meta = meta
    ds.is_implicit_VR = False
    ds.is_little_endian = True

    # Patient / study / series identifiers
    ds.PatientName = "Synthetic^SEG"
    ds.PatientID = "SYN-SEG-001"
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = series_uid
    ds.SOPClassUID = _SEG_SOP_CLASS_UID
    ds.SOPInstanceUID = sop_uid
    ds.StudyDate = "20240101"
    ds.StudyTime = "120000.000000"
    ds.SeriesDate = "20240101"
    ds.SeriesTime = "120000.000000"
    ds.Modality = "SEG"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1

    # Segmentation type and pixel layout
    ds.SegmentationType = "BINARY"
    ds.BitsAllocated = 1
    ds.BitsStored = 1
    ds.HighBit = 0
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.Rows = 64
    ds.Columns = 64
    ds.NumberOfFrames = 2

    # Pixel data: 2 frames x 64 x 64 bits packed = 2 x 512 bytes = 1024 bytes
    ds.PixelData = b"\x00" * 1024

    # SegmentSequence: 2 segments
    seg1 = Dataset()
    seg1.SegmentNumber = 1
    seg1.SegmentLabel = "Lesion"
    seg1.SegmentAlgorithmType = "AUTOMATIC"

    seg2 = Dataset()
    seg2.SegmentNumber = 2
    seg2.SegmentLabel = "Background"
    seg2.SegmentAlgorithmType = "SEMIAUTOMATIC"

    ds.SegmentSequence = Sequence([seg1, seg2])

    # PerFrameFunctionalGroupsSequence: one entry per frame
    frame1 = Dataset()
    sid1 = Dataset()
    sid1.ReferencedSegmentNumber = 1
    frame1.SegmentIdentificationSequence = Sequence([sid1])

    frame2 = Dataset()
    sid2 = Dataset()
    sid2.ReferencedSegmentNumber = 2
    frame2.SegmentIdentificationSequence = Sequence([sid2])

    ds.PerFrameFunctionalGroupsSequence = Sequence([frame1, frame2])

    # ReferencedSeriesSequence: points to a synthetic CT series
    ref_series = Dataset()
    ref_series.SeriesInstanceUID = generate_uid()
    ref_inst = Dataset()
    ref_inst.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT
    ref_inst.ReferencedSOPInstanceUID = generate_uid()
    ref_series.ReferencedInstanceSequence = Sequence([ref_inst])
    ds.ReferencedSeriesSequence = Sequence([ref_series])

    return ds


def create_rtss_seed() -> Dataset:
    """Create a minimal valid DICOM RT Structure Set Storage dataset.

    Produces a 2-ROI RTSS with CLOSED_PLANAR contours, observations, and a
    frame-of-reference link.  Passes RTStructureSetFuzzer.can_mutate() and
    exercises all five of its mutation strategies.

    Returns:
        Dataset configured as RT Structure Set Storage (1.2.840.10008.5.1.4.1.1.481.3).

    """
    meta, sop_uid, study_uid, series_uid = _common_meta(_RTSS_SOP_CLASS_UID)
    for_uid = generate_uid()  # Frame Of Reference UID

    ds = Dataset()
    ds.file_meta = meta
    ds.is_implicit_VR = False
    ds.is_little_endian = True

    # Patient / study / series identifiers
    ds.PatientName = "Synthetic^RTSS"
    ds.PatientID = "SYN-RTSS-001"
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = series_uid
    ds.SOPClassUID = _RTSS_SOP_CLASS_UID
    ds.SOPInstanceUID = sop_uid
    ds.StudyDate = "20240101"
    ds.StudyTime = "120000.000000"
    ds.SeriesDate = "20240101"
    ds.SeriesTime = "120000.000000"
    ds.Modality = "RTSTRUCT"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1
    ds.FrameOfReferenceUID = for_uid

    # Structure set metadata
    ds.StructureSetLabel = "SyntheticRS"
    ds.StructureSetDate = "20240101"
    ds.StructureSetTime = "120000.000000"

    # StructureSetROISequence: 2 ROIs
    roi1 = Dataset()
    roi1.ROINumber = 1
    roi1.ROIName = "Body"
    roi1.ROIGenerationAlgorithm = "AUTOMATIC"
    roi1.ReferencedFrameOfReferenceUID = for_uid

    roi2 = Dataset()
    roi2.ROINumber = 2
    roi2.ROIName = "PTV"
    roi2.ROIGenerationAlgorithm = "MANUAL"
    roi2.ReferencedFrameOfReferenceUID = for_uid

    ds.StructureSetROISequence = Sequence([roi1, roi2])

    # ROIContourSequence: one CLOSED_PLANAR square contour per ROI
    def _square_contour(x0: float, y0: float, z: float, size: float) -> Dataset:
        contour = Dataset()
        contour.ContourGeometricType = "CLOSED_PLANAR"
        contour.NumberOfContourPoints = 4
        contour.ContourData = [
            str(x0),
            str(y0),
            str(z),
            str(x0 + size),
            str(y0),
            str(z),
            str(x0 + size),
            str(y0 + size),
            str(z),
            str(x0),
            str(y0 + size),
            str(z),
        ]
        return contour

    roi_contour1 = Dataset()
    roi_contour1.ReferencedROINumber = 1
    roi_contour1.ContourSequence = Sequence([_square_contour(0.0, 0.0, 0.0, 100.0)])

    roi_contour2 = Dataset()
    roi_contour2.ReferencedROINumber = 2
    roi_contour2.ContourSequence = Sequence([_square_contour(10.0, 10.0, 0.0, 80.0)])

    ds.ROIContourSequence = Sequence([roi_contour1, roi_contour2])

    # RTROIObservationsSequence
    obs1 = Dataset()
    obs1.ObservationNumber = 1
    obs1.ReferencedROINumber = 1
    obs1.RTROIInterpretedType = "EXTERNAL"

    obs2 = Dataset()
    obs2.ObservationNumber = 2
    obs2.ReferencedROINumber = 2
    obs2.RTROIInterpretedType = "PTV"

    ds.RTROIObservationsSequence = Sequence([obs1, obs2])

    # ReferencedFrameOfReferenceSequence
    study_ref = Dataset()
    study_ref.ReferencedSOPClassUID = "1.2.840.10008.3.1.2.3.1"
    study_ref.ReferencedSOPInstanceUID = generate_uid()

    frame_ref = Dataset()
    frame_ref.FrameOfReferenceUID = for_uid
    frame_ref.RTReferencedStudySequence = Sequence([study_ref])

    ds.ReferencedFrameOfReferenceSequence = Sequence([frame_ref])

    return ds


def create_pdf_seed() -> Dataset:
    """Create a minimal valid DICOM Encapsulated PDF Storage dataset.

    Wraps a well-formed minimal PDF byte string in EncapsulatedDocument
    (0042,0011) with the required metadata tags.  Passes
    EncapsulatedPdfFuzzer.can_mutate() and exercises all six of its
    mutation strategies.

    Returns:
        Dataset configured as Encapsulated PDF Storage (1.2.840.10008.5.1.4.1.1.104.1).

    """
    meta, sop_uid, study_uid, series_uid = _common_meta(_PDF_SOP_CLASS_UID)

    ds = Dataset()
    ds.file_meta = meta
    ds.is_implicit_VR = False
    ds.is_little_endian = True

    # Patient / study / series identifiers
    ds.PatientName = "Synthetic^PDF"
    ds.PatientID = "SYN-PDF-001"
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = series_uid
    ds.SOPClassUID = _PDF_SOP_CLASS_UID
    ds.SOPInstanceUID = sop_uid
    ds.StudyDate = "20240101"
    ds.StudyTime = "120000.000000"
    ds.SeriesDate = "20240101"
    ds.SeriesTime = "120000.000000"
    ds.Modality = "DOC"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1

    # Encapsulated document payload
    ds.EncapsulatedDocument = _MINIMAL_PDF
    ds.MIMETypeOfEncapsulatedDocument = "application/pdf"
    ds.BurnedInAnnotation = "NO"
    ds.DocumentTitle = "Synthetic Radiology Report"

    # ConceptNameCodeSequence (required by IHE XDS-SD and common in practice)
    concept = Dataset()
    concept.CodeValue = "11528-7"
    concept.CodingSchemeDesignator = "LN"
    concept.CodeMeaning = "Radiology Report"
    ds.ConceptNameCodeSequence = Sequence([concept])

    return ds


def save_seed(dataset: Dataset, output_dir: Path, filename: str) -> Path:
    """Serialise a synthetic seed dataset to a DICOM file.

    Args:
        dataset: Dataset returned by one of the create_*_seed() functions.
        output_dir: Directory to write into (created if absent).
        filename: File name (e.g. ``"seg_seed_001.dcm"``).

    Returns:
        Path to the written file.

    """
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / filename

    file_ds = FileDataset(
        str(out_path),
        dataset,
        file_meta=dataset.file_meta,
        preamble=b"\x00" * 128,
    )
    file_ds.save_as(str(out_path), write_like_original=False)
    return out_path


# Public registry: maps CLI modality key → factory function
SEED_FACTORIES: dict[str, Callable[[], Dataset]] = {
    "seg": create_seg_seed,
    "rtss": create_rtss_seed,
    "pdf": create_pdf_seed,
}

__all__ = [
    "SEED_FACTORIES",
    "create_pdf_seed",
    "create_rtss_seed",
    "create_seg_seed",
    "save_seed",
]
