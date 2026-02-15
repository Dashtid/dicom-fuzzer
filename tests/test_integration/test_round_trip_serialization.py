"""Round-Trip Serialization Tests.

Verifies that mutated DICOM datasets survive the serialize-deserialize round-trip:
    mutate -> dcmwrite(BytesIO) -> dcmread(BytesIO) -> mutation survived

This is the actual production code path in DICOMGenerator._save_mutated_file().

Categories:
- Format fuzzers (11 of 12; CompressedPixelFuzzer skipped -- binary-level)
- Multiframe strategies (10)
- Calibration deterministic (8 exact-value tests)
- NaN/Inf edge cases (4)
- File format enforcement (2)
- Deep nesting boundary (2)
"""

from __future__ import annotations

import copy
import math
import struct
import sys
from io import BytesIO

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.calibration_fuzzer import CalibrationFuzzer
from dicom_fuzzer.attacks.format.conformance_fuzzer import ConformanceFuzzer
from dicom_fuzzer.attacks.format.dictionary_fuzzer import DictionaryFuzzer
from dicom_fuzzer.attacks.format.encoding_fuzzer import EncodingFuzzer
from dicom_fuzzer.attacks.format.header_fuzzer import HeaderFuzzer
from dicom_fuzzer.attacks.format.metadata_fuzzer import MetadataFuzzer
from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer
from dicom_fuzzer.attacks.format.private_tag_fuzzer import PrivateTagFuzzer
from dicom_fuzzer.attacks.format.reference_fuzzer import ReferenceFuzzer
from dicom_fuzzer.attacks.format.sequence_fuzzer import SequenceFuzzer
from dicom_fuzzer.attacks.format.structure_fuzzer import StructureFuzzer
from dicom_fuzzer.attacks.multiframe.dimension_index import DimensionIndexStrategy
from dicom_fuzzer.attacks.multiframe.dimension_overflow import DimensionOverflowStrategy
from dicom_fuzzer.attacks.multiframe.encapsulated_pixel import EncapsulatedPixelStrategy
from dicom_fuzzer.attacks.multiframe.frame_count import FrameCountMismatchStrategy
from dicom_fuzzer.attacks.multiframe.frame_increment import FrameIncrementStrategy
from dicom_fuzzer.attacks.multiframe.frame_time import FrameTimeCorruptionStrategy
from dicom_fuzzer.attacks.multiframe.functional_group import FunctionalGroupStrategy
from dicom_fuzzer.attacks.multiframe.per_frame_dimension import (
    PerFrameDimensionStrategy,
)
from dicom_fuzzer.attacks.multiframe.pixel_truncation import (
    PixelDataTruncationStrategy,
)
from dicom_fuzzer.attacks.multiframe.shared_group import SharedGroupStrategy

# =============================================================================
# Constants
# =============================================================================
ROUND_TRIP_ATTEMPTS = 25
RECURSION_LIMIT = 10000  # Matches generator.py:240


# =============================================================================
# Helpers
# =============================================================================
def round_trip(dataset: Dataset, enforce: bool = False) -> Dataset | None:
    """Serialize dataset to BytesIO, read it back. Returns None on failure.

    Uses enforce_file_format=False by default to match DICOMGenerator behavior.
    Temporarily bumps recursion limit for deep nesting strategies.
    """
    buf = BytesIO()
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old_limit, RECURSION_LIMIT))
    try:
        pydicom.dcmwrite(buf, dataset, enforce_file_format=enforce)
        buf.seek(0)
        return pydicom.dcmread(buf)
    except (
        RecursionError,
        OSError,
        struct.error,
        ValueError,
        TypeError,
        AttributeError,
        OverflowError,
        UnicodeEncodeError,
        UnicodeDecodeError,
        Exception,
    ):
        return None
    finally:
        sys.setrecursionlimit(old_limit)


def _datasets_differ(ds1: Dataset, ds2: Dataset) -> bool:
    """Check if two datasets differ in any commonly-mutated tag."""
    if len(ds1) != len(ds2):
        return True
    check_tags = [
        "PatientName",
        "PatientID",
        "StudyDate",
        "Modality",
        "Rows",
        "Columns",
        "BitsAllocated",
        "BitsStored",
        "HighBit",
        "PixelSpacing",
        "RescaleSlope",
        "RescaleIntercept",
        "WindowCenter",
        "WindowWidth",
        "InstitutionName",
        "SliceThickness",
        "SeriesInstanceUID",
        "SOPInstanceUID",
        "PhotometricInterpretation",
        "SamplesPerPixel",
        "FrameOfReferenceUID",
        "SpecificCharacterSet",
    ]
    for tag_name in check_tags:
        v1 = getattr(ds1, tag_name, None)
        v2 = getattr(ds2, tag_name, None)
        # Handle NaN (NaN != NaN)
        if _is_nan(v1) and _is_nan(v2):
            continue
        if v1 != v2:
            return True
    return False


def _is_nan(val) -> bool:
    """Check if a value is NaN (scalar or list)."""
    try:
        if isinstance(val, (list, tuple)):
            return any(math.isnan(float(v)) for v in val)
        return math.isnan(float(val))
    except (TypeError, ValueError):
        return False


def run_statistical_round_trip(
    fuzzer_cls,
    dataset: Dataset,
    attempts: int = ROUND_TRIP_ATTEMPTS,
    returns_tuple: bool = False,
) -> dict:
    """Run N attempts: deepcopy -> mutate -> round_trip.

    Args:
        fuzzer_cls: Fuzzer class to instantiate.
        dataset: Base dataset to mutate.
        attempts: Number of attempts.
        returns_tuple: If True, mutate() returns (Dataset, records).
            DictionaryFuzzer returns Dataset directly.

    Returns:
        Dict with success_rate, mutations_survived, etc.
    """
    success_count = 0
    mutations_survived = 0

    for _ in range(attempts):
        ds = copy.deepcopy(dataset)
        original = copy.deepcopy(ds)

        fuzzer = fuzzer_cls()
        result = fuzzer.mutate(ds)

        # DictionaryFuzzer returns a new Dataset; others mutate in-place
        if isinstance(result, Dataset):
            target = result
        elif isinstance(result, tuple):
            target = result[0]
        else:
            target = ds

        rt = round_trip(target)
        if rt is not None:
            success_count += 1
            if _datasets_differ(original, rt):
                mutations_survived += 1

    return {
        "success_count": success_count,
        "fail_count": attempts - success_count,
        "total": attempts,
        "success_rate": success_count / attempts,
        "mutations_survived": mutations_survived,
    }


def run_multiframe_round_trip(
    strategy_cls,
    dataset: Dataset,
    attempts: int = ROUND_TRIP_ATTEMPTS,
) -> dict:
    """Run N attempts for multiframe strategies (mutate(ds, mutation_count))."""
    success_count = 0

    for _ in range(attempts):
        ds = copy.deepcopy(dataset)
        strategy = strategy_cls()
        result_ds, _records = strategy.mutate(ds, mutation_count=1)
        rt = round_trip(result_ds)
        if rt is not None:
            success_count += 1

    return {
        "success_count": success_count,
        "total": attempts,
        "success_rate": success_count / attempts,
    }


# =============================================================================
# Fixtures
# =============================================================================
@pytest.fixture
def serializable_dataset() -> Dataset:
    """Dataset with full file_meta, pixel data, and all tags needed by fuzzers.

    Configured for ExplicitVRLittleEndian with enforce_file_format=False.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    ds.preamble = b"\x00" * 128

    # Patient / Study / Series
    ds.PatientName = "RoundTrip^Test"
    ds.PatientID = "RT001"
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "M"
    ds.PatientAge = "044Y"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.StudyDate = "20240101"
    ds.StudyTime = "120000"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1
    ds.InstitutionName = "Test Hospital"
    ds.Manufacturer = "TestCorp"
    ds.StationName = "STATION01"
    ds.StudyDescription = "Round Trip Test Study"
    ds.SpecificCharacterSet = "ISO_IR 192"
    ds.FrameOfReferenceUID = generate_uid()

    # Image properties
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    # Calibration tags
    ds.PixelSpacing = [0.5, 0.5]
    ds.SliceThickness = 2.5
    ds.ImagePositionPatient = [0.0, 0.0, 0.0]
    ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
    ds.RescaleSlope = 1.0
    ds.RescaleIntercept = -1024.0
    ds.WindowCenter = 40
    ds.WindowWidth = 400

    return ds


@pytest.fixture
def multiframe_dataset(serializable_dataset) -> Dataset:
    """4-frame multiframe dataset for multiframe strategy testing."""
    ds = copy.deepcopy(serializable_dataset)
    ds.NumberOfFrames = 4
    frame_size = 64 * 64 * 2
    ds.PixelData = b"\x00" * (frame_size * 4)
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2.1"  # Enhanced CT

    # Per-frame functional groups
    per_frame = []
    for i in range(4):
        fg = Dataset()
        plane_pos = Dataset()
        plane_pos.ImagePositionPatient = [0.0, 0.0, float(i * 5.0)]
        fg.PlanePositionSequence = Sequence([plane_pos])

        plane_orient = Dataset()
        plane_orient.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        fg.PlaneOrientationSequence = Sequence([plane_orient])

        frame_content = Dataset()
        frame_content.FrameAcquisitionDateTime = f"2023010112{i:02d}00.000000"
        frame_content.TemporalPositionIndex = i + 1
        fg.FrameContentSequence = Sequence([frame_content])

        per_frame.append(fg)

    ds.PerFrameFunctionalGroupsSequence = Sequence(per_frame)

    sfg = Dataset()
    pixel_measures = Dataset()
    pixel_measures.PixelSpacing = [0.5, 0.5]
    pixel_measures.SliceThickness = 5.0
    sfg.PixelMeasuresSequence = Sequence([pixel_measures])
    ds.SharedFunctionalGroupsSequence = Sequence([sfg])

    # DimensionIndex needs this
    dim_item1 = Dataset()
    dim_item1.DimensionIndexPointer = Tag(0x0020, 0x0032)  # ImagePositionPatient
    dim_item2 = Dataset()
    dim_item2.DimensionIndexPointer = Tag(0x0020, 0x0037)  # ImageOrientationPatient
    ds.DimensionIndexSequence = Sequence([dim_item1, dim_item2])

    ds.FrameTime = 33.33
    return ds


# =============================================================================
# 1. Clean Format Fuzzers (high round-trip rate expected)
# =============================================================================
class TestCleanFuzzerRoundTrip:
    """Format fuzzers that operate at Dataset API level -- should round-trip cleanly."""

    @pytest.mark.parametrize(
        ("fuzzer_cls", "threshold"),
        [
            (MetadataFuzzer, 0.80),
            (PixelFuzzer, 0.80),
            (ReferenceFuzzer, 0.80),
            (DictionaryFuzzer, 0.60),
            (PrivateTagFuzzer, 0.50),
            (StructureFuzzer, 0.30),
        ],
    )
    def test_round_trip_rate(self, serializable_dataset, fuzzer_cls, threshold):
        stats = run_statistical_round_trip(
            fuzzer_cls=fuzzer_cls,
            dataset=serializable_dataset,
        )
        assert stats["success_rate"] >= threshold, (
            f"{fuzzer_cls.__name__} round-trip {stats['success_rate']:.0%} "
            f"< {threshold:.0%} ({stats})"
        )
        assert stats["mutations_survived"] > 0, (
            f"{fuzzer_cls.__name__}: no mutations survived round-trip"
        )


# =============================================================================
# 2. Expected-Failure Format Fuzzers (lower thresholds)
# =============================================================================
class TestExpectedFailureFuzzerRoundTrip:
    """Fuzzers that use _value bypass, invalid encoding, or deep nesting."""

    @pytest.mark.parametrize(
        ("fuzzer_cls", "threshold"),
        [
            (HeaderFuzzer, 0.20),
            (EncodingFuzzer, 0.20),
            (SequenceFuzzer, 0.20),
            (ConformanceFuzzer, 0.20),
        ],
    )
    def test_round_trip_rate(self, serializable_dataset, fuzzer_cls, threshold):
        stats = run_statistical_round_trip(
            fuzzer_cls=fuzzer_cls,
            dataset=serializable_dataset,
        )
        assert stats["success_rate"] >= threshold, (
            f"{fuzzer_cls.__name__} round-trip {stats['success_rate']:.0%} "
            f"< {threshold:.0%} ({stats})"
        )


# =============================================================================
# 3. Calibration Deterministic Round-Trip
# =============================================================================
class TestCalibrationRoundTrip:
    """CalibrationFuzzer with deterministic attack_type -- exact value assertions."""

    @pytest.mark.parametrize(
        ("method", "attack_type", "tag", "expected"),
        [
            ("fuzz_pixel_spacing", "zero", "PixelSpacing", [0.0, 0.0]),
            ("fuzz_pixel_spacing", "nan", "PixelSpacing", "nan"),
            ("fuzz_hounsfield_rescale", "zero_slope", "RescaleSlope", 0.0),
            ("fuzz_hounsfield_rescale", "nan_slope", "RescaleSlope", "nan"),
            ("fuzz_hounsfield_rescale", "inf_slope", "RescaleSlope", "inf"),
            ("fuzz_window_level", "zero_width", "WindowWidth", 0),
            ("fuzz_window_level", "nan_values", "WindowCenter", "nan"),
            ("fuzz_slice_thickness", "negative", "SliceThickness", -5.0),
        ],
    )
    def test_value_survives_round_trip(
        self, serializable_dataset, method, attack_type, tag, expected
    ):
        ds = copy.deepcopy(serializable_dataset)
        fuzzer = CalibrationFuzzer()
        getattr(fuzzer, method)(ds, attack_type=attack_type)

        result = round_trip(ds)
        assert result is not None, f"Serialization failed for {method}({attack_type})"

        actual = getattr(result, tag)
        if expected == "nan":
            if isinstance(actual, (list, pydicom.multival.MultiValue)):
                assert all(math.isnan(float(v)) for v in actual)
            else:
                assert math.isnan(float(actual))
        elif expected == "inf":
            assert math.isinf(float(actual))
        elif isinstance(expected, list):
            assert [float(v) for v in actual] == pytest.approx(expected)
        else:
            assert float(actual) == pytest.approx(float(expected))


# =============================================================================
# 4. Multiframe Strategy Round-Trip
# =============================================================================
class TestMultiframeRoundTrip:
    """All 10 multiframe strategies -- statistical round-trip."""

    @pytest.mark.parametrize(
        ("strategy_cls", "threshold"),
        [
            (FrameCountMismatchStrategy, 0.80),
            (FrameTimeCorruptionStrategy, 0.60),
            (PerFrameDimensionStrategy, 0.50),
            (SharedGroupStrategy, 0.80),
            (FrameIncrementStrategy, 0.80),
            (DimensionOverflowStrategy, 0.80),
            (FunctionalGroupStrategy, 0.80),
            (PixelDataTruncationStrategy, 0.70),
            (EncapsulatedPixelStrategy, 0.50),
            (DimensionIndexStrategy, 0.80),
        ],
    )
    def test_round_trip_rate(self, multiframe_dataset, strategy_cls, threshold):
        stats = run_multiframe_round_trip(
            strategy_cls=strategy_cls,
            dataset=multiframe_dataset,
        )
        assert stats["success_rate"] >= threshold, (
            f"{strategy_cls.__name__} round-trip {stats['success_rate']:.0%} "
            f"< {threshold:.0%} ({stats})"
        )


# =============================================================================
# 5. NaN/Inf Serialization Edge Cases
# =============================================================================
class TestNaNInfSerialization:
    """Verify NaN/Inf values survive the pydicom round-trip."""

    def test_nan_scalar_ds_vr(self, serializable_dataset):
        ds = copy.deepcopy(serializable_dataset)
        ds.RescaleSlope = float("nan")
        result = round_trip(ds)
        assert result is not None
        assert math.isnan(float(result.RescaleSlope))

    def test_inf_scalar_ds_vr(self, serializable_dataset):
        ds = copy.deepcopy(serializable_dataset)
        ds.RescaleSlope = float("inf")
        result = round_trip(ds)
        assert result is not None
        assert math.isinf(float(result.RescaleSlope))

    def test_negative_inf_ds_vr(self, serializable_dataset):
        ds = copy.deepcopy(serializable_dataset)
        ds.RescaleSlope = float("-inf")
        result = round_trip(ds)
        assert result is not None
        actual = float(result.RescaleSlope)
        assert math.isinf(actual) and actual < 0

    def test_nan_list_ds_vr(self, serializable_dataset):
        ds = copy.deepcopy(serializable_dataset)
        ds.PixelSpacing = [float("nan"), float("nan")]
        result = round_trip(ds)
        assert result is not None
        assert all(math.isnan(float(v)) for v in result.PixelSpacing)


# =============================================================================
# 6. File Format Enforcement
# =============================================================================
class TestEnforceFileFormat:
    """Verify behavioral difference between enforce_file_format True/False."""

    def test_enforce_false_is_lenient(self, serializable_dataset):
        """enforce_file_format=False allows datasets to be written."""
        ds = copy.deepcopy(serializable_dataset)
        result = round_trip(ds, enforce=False)
        assert result is not None

    def test_enforce_true_requires_valid_meta(self, serializable_dataset):
        """enforce_file_format=True rejects missing TransferSyntaxUID."""
        ds = copy.deepcopy(serializable_dataset)
        if hasattr(ds, "file_meta") and ds.file_meta is not None:
            del ds.file_meta.TransferSyntaxUID
        result = round_trip(ds, enforce=True)
        assert result is None, (
            "Expected failure with enforce=True and no TransferSyntaxUID"
        )


# =============================================================================
# 7. Deep Nesting Boundary
# =============================================================================
class TestDeepNestingBoundary:
    """Verify recursion limit behavior for nested sequences."""

    def test_depth_50_round_trips(self, serializable_dataset):
        """Moderate nesting depth should survive round-trip."""
        ds = copy.deepcopy(serializable_dataset)

        def _nested(depth: int) -> Dataset:
            item = Dataset()
            item.add_new(Tag(0x0008, 0x0100), "SH", f"L{depth}")
            if depth > 0:
                item.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([_nested(depth - 1)]))
            return item

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(5000)
        try:
            ds.add_new(Tag(0x0040, 0xA730), "SQ", Sequence([_nested(50)]))
        finally:
            sys.setrecursionlimit(old_limit)

        result = round_trip(ds)
        assert result is not None

    def test_depth_500_needs_limit_bump(self, serializable_dataset):
        """Deep nesting needs recursion limit bump (which round_trip provides)."""
        ds = copy.deepcopy(serializable_dataset)

        def _nested(depth: int) -> Dataset:
            item = Dataset()
            item.add_new(Tag(0x0008, 0x0100), "SH", f"L{depth}")
            if depth > 0:
                item.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([_nested(depth - 1)]))
            return item

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(RECURSION_LIMIT)
        try:
            ds.add_new(Tag(0x0040, 0xA730), "SQ", Sequence([_nested(500)]))
        finally:
            sys.setrecursionlimit(old_limit)

        # round_trip bumps limit to RECURSION_LIMIT, so this should succeed
        result = round_trip(ds)
        assert result is not None


# =============================================================================
# 8. Skipped Categories (documentation only)
# =============================================================================
class TestSkippedCategories:
    """Document strategies intentionally excluded from round-trip testing."""

    @pytest.mark.skip(reason="CVE payloads operate at raw byte level, not Dataset")
    def test_cve_payloads(self):
        pass

    @pytest.mark.skip(
        reason="CompressedPixelFuzzer creates binary corruption via encapsulate()"
    )
    def test_compressed_pixel_fuzzer(self):
        pass

    @pytest.mark.skip(
        reason="StructureFuzzer.corrupt_file_header operates on raw file bytes"
    )
    def test_structure_corrupt_file_header(self):
        pass
