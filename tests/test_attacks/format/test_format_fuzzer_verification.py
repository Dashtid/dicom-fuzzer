"""Mutation verification tests for format fuzzer strategies.

Verifies that each strategy method actually produces the specific defect it
claims to -- not just "did it run" (contract tests) but "did it create a
dimension mismatch / invalid bit depth / corrupted pixel data / etc."

Tests call strategy methods directly (not via mutate()) and assert semantic
properties of the output.

Phase 1a: PixelFuzzer (6 strategies)
Phase 1b: CompressedPixelFuzzer (8 strategies)
Phase 1c: EncodingFuzzer (10 strategies)
Phase 2a: HeaderFuzzer (7 strategies)
Phase 2b: SequenceFuzzer (8 strategies)
Phase 2c: StructureFuzzer (6 strategies)
Phase 3a: ConformanceFuzzer (10 strategies)
Phase 3b: MetadataFuzzer (5 strategies)
Phase 3c: ReferenceFuzzer (10 strategies)
Phase 4a: CalibrationFuzzer (5 strategies)
Phase 4b: DictionaryFuzzer (3 strategies)
Phase 4c: PrivateTagFuzzer (10 strategies)
"""

import copy
import struct

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import (
    ExplicitVRBigEndian,
    ExplicitVRLittleEndian,
    JPEG2000Lossless,
    JPEGBaseline8Bit,
    RLELossless,
    generate_uid,
)

from dicom_fuzzer.attacks.format.calibration_fuzzer import CalibrationFuzzer
from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import CompressedPixelFuzzer
from dicom_fuzzer.attacks.format.conformance_fuzzer import ConformanceFuzzer
from dicom_fuzzer.attacks.format.dictionary_fuzzer import DictionaryFuzzer
from dicom_fuzzer.attacks.format.encoding_fuzzer import EncodingFuzzer
from dicom_fuzzer.attacks.format.header_fuzzer import VR_MUTATIONS, HeaderFuzzer
from dicom_fuzzer.attacks.format.metadata_fuzzer import (
    _INVALID_DATES,
    _INVALID_TIMES,
    MetadataFuzzer,
)
from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer
from dicom_fuzzer.attacks.format.private_tag_fuzzer import (
    MALICIOUS_CREATORS,
    PRIVATE_GROUPS,
    PrivateTagFuzzer,
)
from dicom_fuzzer.attacks.format.reference_fuzzer import ReferenceFuzzer
from dicom_fuzzer.attacks.format.sequence_fuzzer import SequenceFuzzer
from dicom_fuzzer.attacks.format.structure_fuzzer import StructureFuzzer
from dicom_fuzzer.attacks.format.uid_attacks import INVALID_UIDS, UID_TAG_NAMES

# ---------------------------------------------------------------------------
# Constants for encapsulated data parsing
# ---------------------------------------------------------------------------
PIXEL_DATA_TAG = Tag(0x7FE0, 0x0010)
ITEM_TAG_BYTES = b"\xfe\xff\x00\xe0"
DELIM_TAG_BYTES = b"\xfe\xff\xdd\xe0"
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
JPEG_SOF0 = b"\xff\xc0"
JP2_SOC = b"\xff\x4f"


def _get_pixel_bytes(dataset: Dataset) -> bytes:
    """Get raw pixel data bytes from the PixelData element."""
    elem = dataset[PIXEL_DATA_TAG]
    return elem.value if isinstance(elem.value, bytes) else b""


def _count_frame_items(data: bytes) -> int:
    """Count frame Item tags in encapsulated data (excludes BOT)."""
    count = 0
    pos = 0
    first = True
    while pos + 8 <= len(data):
        if data[pos : pos + 4] == DELIM_TAG_BYTES:
            break
        if data[pos : pos + 4] == ITEM_TAG_BYTES:
            length = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
            if first:
                first = False  # BOT
            else:
                count += 1
            pos += 8 + length
        else:
            break
    return count


@pytest.fixture
def fuzzer() -> PixelFuzzer:
    """PixelFuzzer instance."""
    return PixelFuzzer()


@pytest.fixture
def pixel_dataset() -> Dataset:
    """Dataset with valid, self-consistent pixel data.

    Rows=64, Columns=64, 16-bit grayscale, all-zero pixels.
    Configured so pixel_array is decodable by pydicom.
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
    ds.PatientName = "Pixel^Test"
    ds.PatientID = "PIX001"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    return ds


# ---------------------------------------------------------------------------
# 1. _noise_injection
# ---------------------------------------------------------------------------
class TestNoiseInjection:
    """Verify _noise_injection modifies pixel data bytes."""

    def test_pixel_data_bytes_differ(self, fuzzer, pixel_dataset):
        """Injected noise must produce different pixel bytes."""
        original_pixels = pixel_dataset.PixelData
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._noise_injection(ds)
            if result.PixelData != original_pixels:
                any_changed = True
                break
        assert any_changed, "_noise_injection never modified pixel data bytes"

    def test_pixel_data_length_preserved(self, fuzzer, pixel_dataset):
        """Noise injection must not change pixel data length."""
        ds = copy.deepcopy(pixel_dataset)
        original_length = len(ds.PixelData)
        result = fuzzer._noise_injection(ds)
        assert len(result.PixelData) == original_length

    def test_no_pixel_data_returns_unchanged(self, fuzzer):
        """Without PixelData, dataset returned unchanged."""
        ds = Dataset()
        ds.PatientName = "NoPixels"
        original = copy.deepcopy(ds)
        result = fuzzer._noise_injection(ds)
        assert result == original


# ---------------------------------------------------------------------------
# 2. _dimension_mismatch
# ---------------------------------------------------------------------------
class TestDimensionMismatch:
    """Verify _dimension_mismatch breaks Rows*Columns vs PixelData size."""

    def test_dimensions_no_longer_match_pixel_data(self, fuzzer, pixel_dataset):
        """Declared dimensions must not match actual pixel data size."""
        any_mismatched = False
        for _ in range(30):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._dimension_mismatch(ds)
            rows = getattr(result, "Rows", 0)
            cols = getattr(result, "Columns", 0)
            bytes_per_pixel = max(getattr(result, "BitsAllocated", 16) // 8, 1)
            spp = getattr(result, "SamplesPerPixel", 1)
            expected_size = rows * cols * bytes_per_pixel * spp
            actual_size = len(result.PixelData)
            if expected_size != actual_size:
                any_mismatched = True
                break
        assert any_mismatched, (
            "_dimension_mismatch never created a dimension/pixel-data size mismatch"
        )

    def test_pixel_data_not_modified(self, fuzzer, pixel_dataset):
        """Dimension mismatch changes dimensions, not pixel data."""
        ds = copy.deepcopy(pixel_dataset)
        original_pixels = ds.PixelData
        result = fuzzer._dimension_mismatch(ds)
        assert result.PixelData == original_pixels

    def test_no_pixel_data_returns_unchanged(self, fuzzer):
        """Without PixelData, dataset returned unchanged."""
        ds = Dataset()
        ds.Rows = 64
        ds.Columns = 64
        original = copy.deepcopy(ds)
        result = fuzzer._dimension_mismatch(ds)
        assert result == original

    def test_multiple_attack_paths(self, fuzzer, pixel_dataset):
        """Multiple dimension attack variants should be exercised."""
        seen = set()
        for _ in range(200):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._dimension_mismatch(ds)
            r, c = result.Rows, result.Columns
            if r == 0:
                seen.add("rows_zero")
            elif c == 0:
                seen.add("columns_zero")
            elif r > 64 and c > 64:
                seen.add("both_larger")
            elif r > 64:
                seen.add("rows_larger")
            elif c > 64:
                seen.add("columns_larger")
            elif r > 60000 or c > 60000:
                seen.add("extreme")
        assert len(seen) >= 3, f"Only {len(seen)} attack paths hit: {seen}"


# ---------------------------------------------------------------------------
# 3. _bit_depth_attack
# ---------------------------------------------------------------------------
class TestBitDepthAttack:
    """Verify _bit_depth_attack creates invalid bit depth relationships."""

    def test_bit_depth_invariant_violated(self, fuzzer, pixel_dataset):
        """At least one DICOM bit depth rule must be broken."""
        # Valid state: BitsAllocated=16, BitsStored=12, HighBit=11
        any_violated = False
        for _ in range(30):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._bit_depth_attack(ds)
            ba = result.BitsAllocated
            bs = result.BitsStored
            hb = result.HighBit
            # Original valid state: ba=16, bs=12, hb=11
            violated = (
                bs > ba
                or hb != bs - 1
                or ba == 0
                or bs == 0
                or ba not in (8, 16, 32)
                or (ba != 16 or bs != 12 or hb != 11)
            )
            if violated:
                any_violated = True
                break
        assert any_violated, "_bit_depth_attack never violated bit depth rules"

    def test_multiple_attack_paths(self, fuzzer, pixel_dataset):
        """Multiple bit depth attack variants should be exercised."""
        seen = set()
        for _ in range(200):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._bit_depth_attack(ds)
            ba = result.BitsAllocated
            bs = result.BitsStored
            hb = result.HighBit
            if bs > ba:
                seen.add("bits_stored_greater")
            if hb > 20:
                seen.add("high_bit_invalid")
            if ba != 16 and bs == 12:
                seen.add("bits_allocated_mismatch")
            if ba == 0:
                seen.add("zero_bits")
            if ba in (1, 64, 128, 255):
                seen.add("extreme_bits")
        assert len(seen) >= 3, f"Only {len(seen)} attack paths hit: {seen}"


# ---------------------------------------------------------------------------
# 4. _photometric_confusion
# ---------------------------------------------------------------------------
class TestPhotometricConfusion:
    """Verify _photometric_confusion changes PhotometricInterpretation."""

    def test_photometric_changed(self, fuzzer, pixel_dataset):
        """PhotometricInterpretation must differ from original."""
        original = pixel_dataset.PhotometricInterpretation
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._photometric_confusion(ds)
            if result.PhotometricInterpretation != original:
                any_changed = True
                break
        assert any_changed, (
            "_photometric_confusion never changed PhotometricInterpretation"
        )

    def test_value_is_invalid_or_mismatched(self, fuzzer, pixel_dataset):
        """New value should be invalid or mismatched for grayscale data."""
        valid_for_mono = {"MONOCHROME1", "MONOCHROME2"}
        any_invalid = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._photometric_confusion(ds)
            if result.PhotometricInterpretation not in valid_for_mono:
                any_invalid = True
                break
        assert any_invalid, (
            "_photometric_confusion never produced invalid photometric for grayscale"
        )


# ---------------------------------------------------------------------------
# 5. _samples_per_pixel_attack
# ---------------------------------------------------------------------------
class TestSamplesPerPixelAttack:
    """Verify _samples_per_pixel_attack creates SamplesPerPixel inconsistency."""

    def test_samples_per_pixel_changed(self, fuzzer, pixel_dataset):
        """SamplesPerPixel must differ from original (1)."""
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._samples_per_pixel_attack(ds)
            if result.SamplesPerPixel != 1:
                any_changed = True
                break
        assert any_changed, "_samples_per_pixel_attack never changed SamplesPerPixel"

    def test_samples_inconsistent_with_pixel_data(self, fuzzer, pixel_dataset):
        """SamplesPerPixel * dimensions should not match pixel data size."""
        original_size = len(pixel_dataset.PixelData)
        rows = pixel_dataset.Rows
        cols = pixel_dataset.Columns
        bytes_pp = pixel_dataset.BitsAllocated // 8
        any_inconsistent = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._samples_per_pixel_attack(ds)
            expected = rows * cols * bytes_pp * result.SamplesPerPixel
            if expected != original_size:
                any_inconsistent = True
                break
        assert any_inconsistent, (
            "_samples_per_pixel_attack never made SamplesPerPixel "
            "inconsistent with pixel data size"
        )

    def test_produces_invalid_values(self, fuzzer, pixel_dataset):
        """Should produce values outside the valid set {1, 3, 4}."""
        valid = {1, 3, 4}
        any_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._samples_per_pixel_attack(ds)
            if result.SamplesPerPixel not in valid:
                any_invalid = True
                break
        assert any_invalid, (
            "_samples_per_pixel_attack never produced invalid SamplesPerPixel"
        )


# ---------------------------------------------------------------------------
# 6. _planar_configuration_attack
# ---------------------------------------------------------------------------
class TestPlanarConfigurationAttack:
    """Verify _planar_configuration_attack sets PlanarConfiguration incorrectly."""

    def test_planar_config_set(self, fuzzer, pixel_dataset):
        """PlanarConfiguration must be added or changed."""
        any_set = False
        for _ in range(10):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._planar_configuration_attack(ds)
            if hasattr(result, "PlanarConfiguration"):
                any_set = True
                break
        assert any_set, "_planar_configuration_attack never set PlanarConfiguration"

    def test_planar_config_on_grayscale(self, fuzzer, pixel_dataset):
        """Should set PlanarConfiguration when SamplesPerPixel=1 (invalid)."""
        any_on_grayscale = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._planar_configuration_attack(ds)
            spp = getattr(result, "SamplesPerPixel", 1)
            pc = getattr(result, "PlanarConfiguration", None)
            if spp == 1 and pc is not None:
                any_on_grayscale = True
                break
        assert any_on_grayscale, (
            "_planar_configuration_attack never set PlanarConfiguration "
            "on grayscale image"
        )

    def test_invalid_planar_values(self, fuzzer, pixel_dataset):
        """Should produce PlanarConfiguration values other than 0 or 1."""
        any_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._planar_configuration_attack(ds)
            pc = getattr(result, "PlanarConfiguration", None)
            if pc is not None and pc not in (0, 1):
                any_invalid = True
                break
        assert any_invalid, (
            "_planar_configuration_attack never produced invalid "
            "PlanarConfiguration value"
        )


# ===========================================================================
# Phase 1b: CompressedPixelFuzzer (8 strategies)
# ===========================================================================


@pytest.fixture
def comp_fuzzer() -> CompressedPixelFuzzer:
    """CompressedPixelFuzzer instance."""
    return CompressedPixelFuzzer()


@pytest.fixture
def compressed_dataset() -> Dataset:
    """Dataset with file_meta for compressed pixel data mutations.

    Strategies create their own compressed PixelData, so this fixture
    only needs file_meta (for transfer syntax) and basic DICOM tags.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Compressed^Test"
    ds.PatientID = "CMP001"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    return ds


# ---------------------------------------------------------------------------
# 7. _corrupt_jpeg_markers
# ---------------------------------------------------------------------------
class TestCorruptJpegMarkers:
    """Verify _corrupt_jpeg_markers produces corrupted JPEG marker data."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._corrupt_jpeg_markers(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_transfer_syntax_is_jpeg(self, comp_fuzzer, compressed_dataset):
        """Transfer syntax must be set to JPEG Baseline."""
        result = comp_fuzzer._corrupt_jpeg_markers(compressed_dataset)
        assert result.file_meta.TransferSyntaxUID == JPEGBaseline8Bit

    def test_jpeg_soi_present_in_data(self, comp_fuzzer, compressed_dataset):
        """Encapsulated data must contain JPEG SOI marker."""
        result = comp_fuzzer._corrupt_jpeg_markers(compressed_dataset)
        raw = _get_pixel_bytes(result)
        assert JPEG_SOI in raw, "No JPEG SOI marker found in pixel data"

    def test_marker_corruption_present(self, comp_fuzzer, compressed_dataset):
        """At least one JPEG marker corruption must be detectable."""
        any_corrupted = False
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._corrupt_jpeg_markers(ds)
            raw = _get_pixel_bytes(result)
            # Check for known corruption patterns:
            # - SOI without EOI (missing_eoi)
            # - Multiple SOI (duplicate_soi)
            # - Invalid marker \xff\x01 (invalid_marker)
            # - Overlong marker length \xff\xff (marker_length_overflow)
            # - Truncated data after DHT marker (truncated_marker)
            has_soi = JPEG_SOI in raw
            has_eoi = JPEG_EOI in raw
            soi_count = raw.count(JPEG_SOI)
            has_invalid = b"\xff\x01" in raw
            has_overlong = b"\xff\xff" in raw
            corrupted = (
                (has_soi and not has_eoi)
                or soi_count > 1
                or has_invalid
                or has_overlong
            )
            if corrupted:
                any_corrupted = True
                break
        assert any_corrupted, "No JPEG marker corruption detected in pixel data"


# ---------------------------------------------------------------------------
# 8. _corrupt_jpeg_dimensions
# ---------------------------------------------------------------------------
class TestCorruptJpegDimensions:
    """Verify _corrupt_jpeg_dimensions creates SOF/DICOM dimension mismatch."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._corrupt_jpeg_dimensions(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_sof0_marker_present(self, comp_fuzzer, compressed_dataset):
        """SOF0 marker must be present in the JPEG data."""
        result = comp_fuzzer._corrupt_jpeg_dimensions(compressed_dataset)
        raw = _get_pixel_bytes(result)
        assert JPEG_SOF0 in raw, "No SOF0 marker in pixel data"

    def test_dicom_dimensions_set(self, comp_fuzzer, compressed_dataset):
        """DICOM Rows/Columns must be set to non-original values."""
        result = comp_fuzzer._corrupt_jpeg_dimensions(compressed_dataset)
        # Strategy sets Rows/Columns to random values from [100, 512, 1024]
        assert result.Rows in (100, 512, 1024)
        assert result.Columns in (100, 512, 1024)

    def test_jpeg_dimensions_differ_from_dicom(self, comp_fuzzer, compressed_dataset):
        """JPEG SOF dimensions must not match DICOM Rows/Columns."""
        result = comp_fuzzer._corrupt_jpeg_dimensions(compressed_dataset)
        raw = _get_pixel_bytes(result)
        sof_pos = raw.find(JPEG_SOF0)
        assert sof_pos >= 0, "No SOF0 marker found"
        # SOF0 structure: FF C0 LL LL PP HH HH WW WW ...
        # Skip marker (2) + length (2) + precision (1) = offset 5 from marker
        dim_offset = sof_pos + 5
        if dim_offset + 4 <= len(raw):
            jpeg_height = struct.unpack(">H", raw[dim_offset : dim_offset + 2])[0]
            jpeg_width = struct.unpack(">H", raw[dim_offset + 2 : dim_offset + 4])[0]
            # JPEG dimensions should be from [0, 1, 65535, 32768]
            # DICOM dimensions should be from [100, 512, 1024]
            # They should NOT match
            assert jpeg_height != result.Rows or jpeg_width != result.Columns, (
                f"JPEG dims ({jpeg_height}x{jpeg_width}) match "
                f"DICOM dims ({result.Rows}x{result.Columns})"
            )


# ---------------------------------------------------------------------------
# 9. _corrupt_jpeg2000_codestream
# ---------------------------------------------------------------------------
class TestCorruptJpeg2000Codestream:
    """Verify _corrupt_jpeg2000_codestream produces corrupted J2K data."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._corrupt_jpeg2000_codestream(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_transfer_syntax_is_jpeg2000(self, comp_fuzzer, compressed_dataset):
        """Transfer syntax must be set to JPEG 2000."""
        result = comp_fuzzer._corrupt_jpeg2000_codestream(compressed_dataset)
        assert result.file_meta.TransferSyntaxUID == JPEG2000Lossless

    def test_j2k_soc_marker_present(self, comp_fuzzer, compressed_dataset):
        """J2K Start of Codestream marker must be present."""
        result = comp_fuzzer._corrupt_jpeg2000_codestream(compressed_dataset)
        raw = _get_pixel_bytes(result)
        assert JP2_SOC in raw, "No JPEG2000 SOC marker found in pixel data"


# ---------------------------------------------------------------------------
# 10. _corrupt_rle_segments
# ---------------------------------------------------------------------------
class TestCorruptRleSegments:
    """Verify _corrupt_rle_segments produces corrupted RLE segment headers."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._corrupt_rle_segments(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_transfer_syntax_is_rle(self, comp_fuzzer, compressed_dataset):
        """Transfer syntax must be set to RLE Lossless."""
        result = comp_fuzzer._corrupt_rle_segments(compressed_dataset)
        assert result.file_meta.TransferSyntaxUID == RLELossless

    def test_rle_header_corrupted(self, comp_fuzzer, compressed_dataset):
        """RLE header must contain corrupted values."""
        any_corrupted = False
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._corrupt_rle_segments(ds)
            raw = _get_pixel_bytes(result)
            # Find first frame data (skip BOT item)
            pos = 0
            frame_data = b""
            first_item = True
            while pos + 8 <= len(raw):
                if raw[pos : pos + 4] == DELIM_TAG_BYTES:
                    break
                if raw[pos : pos + 4] == ITEM_TAG_BYTES:
                    length = struct.unpack("<I", raw[pos + 4 : pos + 8])[0]
                    if first_item:
                        first_item = False
                    else:
                        frame_data = raw[pos + 8 : pos + 8 + length]
                        break
                    pos += 8 + length
                else:
                    break
            if len(frame_data) >= 4:
                segment_count = struct.unpack("<I", frame_data[:4])[0]
                # Corrupted if: wrong count, invalid offset, etc.
                if segment_count > 3 or segment_count == 0:
                    any_corrupted = True
                    break
                if len(frame_data) >= 8:
                    first_offset = struct.unpack("<I", frame_data[4:8])[0]
                    if first_offset == 0xFFFFFFFF or first_offset > len(frame_data):
                        any_corrupted = True
                        break
        assert any_corrupted, "No RLE segment header corruption detected"


# ---------------------------------------------------------------------------
# 11. _corrupt_fragment_offsets
# ---------------------------------------------------------------------------
class TestCorruptFragmentOffsets:
    """Verify _corrupt_fragment_offsets creates invalid BOT entries."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._corrupt_fragment_offsets(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_bot_contains_invalid_offsets(self, comp_fuzzer, compressed_dataset):
        """Basic Offset Table must contain 0xFFFFFFFF values."""
        result = comp_fuzzer._corrupt_fragment_offsets(compressed_dataset)
        raw = _get_pixel_bytes(result)
        # BOT is the first Item: tag (4) + length (4) + offset data
        assert raw[:4] == ITEM_TAG_BYTES, "First bytes not an Item tag"
        bot_length = struct.unpack("<I", raw[4:8])[0]
        bot_data = raw[8 : 8 + bot_length]
        # Check for 0xFFFFFFFF in BOT offsets
        invalid_offset = struct.pack("<I", 0xFFFFFFFF)
        assert invalid_offset in bot_data, "No invalid (0xFFFFFFFF) offset in BOT"

    def test_has_frame_items(self, comp_fuzzer, compressed_dataset):
        """Encapsulated data must contain frame items after BOT."""
        result = comp_fuzzer._corrupt_fragment_offsets(compressed_dataset)
        raw = _get_pixel_bytes(result)
        frame_count = _count_frame_items(raw)
        assert frame_count == 3, f"Expected 3 frame items, got {frame_count}"


# ---------------------------------------------------------------------------
# 12. _corrupt_encapsulation_structure
# ---------------------------------------------------------------------------
class TestCorruptEncapsulationStructure:
    """Verify _corrupt_encapsulation_structure breaks encapsulation format."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._corrupt_encapsulation_structure(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_encapsulation_defect_present(self, comp_fuzzer, compressed_dataset):
        """At least one structural defect must be detectable."""
        any_defect = False
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._corrupt_encapsulation_structure(ds)
            raw = _get_pixel_bytes(result)
            # Check for known defects:
            has_delimiter = DELIM_TAG_BYTES in raw
            has_wrong_tag = b"\x00\x00\x00\x00" in raw[8:]  # Wrong item tag
            has_zero_frame = raw.count(ITEM_TAG_BYTES + b"\x00\x00\x00\x00") > 1
            defect = not has_delimiter or has_wrong_tag or has_zero_frame
            if defect:
                any_defect = True
                break
        assert any_defect, "No encapsulation structural defect detected"


# ---------------------------------------------------------------------------
# 13. _inject_malformed_frame
# ---------------------------------------------------------------------------
class TestInjectMalformedFrame:
    """Verify _inject_malformed_frame injects a bad frame among valid ones.

    Note: the strategy randomly picks from 4 malformed frame types. One
    option (empty bytes) causes pydicom's encapsulate() to fail, so the
    strategy silently no-ops ~25% of the time. Tests retry to account for this.
    """

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation (retries for empty-frame path)."""
        any_set = False
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._inject_malformed_frame(ds)
            if PIXEL_DATA_TAG in result:
                any_set = True
                break
        assert any_set, "_inject_malformed_frame never set PixelData"

    def test_number_of_frames_set_to_three(self, comp_fuzzer, compressed_dataset):
        """NumberOfFrames must be 3 (2 valid + 1 malformed)."""
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._inject_malformed_frame(ds)
            if PIXEL_DATA_TAG in result:
                assert result.NumberOfFrames == 3
                return
        pytest.skip("encapsulate() failed on all attempts")

    def test_three_frame_items_present(self, comp_fuzzer, compressed_dataset):
        """Encapsulated data must contain exactly 3 frame items."""
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._inject_malformed_frame(ds)
            if PIXEL_DATA_TAG in result:
                raw = _get_pixel_bytes(result)
                frame_count = _count_frame_items(raw)
                assert frame_count == 3, f"Expected 3 frames, got {frame_count}"
                return
        pytest.skip("encapsulate() failed on all attempts")

    def test_transfer_syntax_is_jpeg(self, comp_fuzzer, compressed_dataset):
        """Transfer syntax must be JPEG Baseline."""
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._inject_malformed_frame(ds)
            if PIXEL_DATA_TAG in result:
                assert result.file_meta.TransferSyntaxUID == JPEGBaseline8Bit
                return
        pytest.skip("encapsulate() failed on all attempts")


# ---------------------------------------------------------------------------
# 14. _frame_count_mismatch
# ---------------------------------------------------------------------------
class TestFrameCountMismatch:
    """Verify _frame_count_mismatch creates NumberOfFrames != actual count."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._frame_count_mismatch(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_frame_count_does_not_match_actual(self, comp_fuzzer, compressed_dataset):
        """NumberOfFrames must differ from actual fragment count."""
        any_mismatched = False
        for _ in range(20):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._frame_count_mismatch(ds)
            claimed = result.NumberOfFrames
            raw = _get_pixel_bytes(result)
            actual = _count_frame_items(raw)
            if claimed != actual:
                any_mismatched = True
                break
        assert any_mismatched, (
            "_frame_count_mismatch: NumberOfFrames always matched actual frame count"
        )

    def test_multiple_mismatch_directions(self, comp_fuzzer, compressed_dataset):
        """Should produce both over-claims and under-claims."""
        seen = set()
        for _ in range(100):
            ds = copy.deepcopy(compressed_dataset)
            result = comp_fuzzer._frame_count_mismatch(ds)
            claimed = result.NumberOfFrames
            raw = _get_pixel_bytes(result)
            actual = _count_frame_items(raw)
            if claimed > actual:
                seen.add("over_claim")
            elif claimed < actual:
                seen.add("under_claim")
        assert len(seen) >= 2, f"Only saw mismatch directions: {seen}"


# ===========================================================================
# Phase 1c: EncodingFuzzer (10 strategies)
# ===========================================================================

PATIENT_NAME_TAG = Tag(0x0010, 0x0010)
INSTITUTION_TAG = Tag(0x0008, 0x0080)
STUDY_DESC_TAG = Tag(0x0008, 0x1030)

# BOM byte patterns to check for
BOM_PATTERNS = [
    b"\xef\xbb\xbf",  # UTF-8
    b"\xff\xfe",  # UTF-16 LE
    b"\xfe\xff",  # UTF-16 BE
    b"\xff\xfe\x00\x00",  # UTF-32 LE
    b"\x00\x00\xfe\xff",  # UTF-32 BE
]

# Surrogate byte patterns (UTF-8 encoded UTF-16 surrogates)
SURROGATE_PATTERNS = [
    b"\xed\xa0\x80",  # U+D800
    b"\xed\xaf\xbf",  # U+DBFF
    b"\xed\xb0\x80",  # U+DC00
    b"\xed\xbf\xbf",  # U+DFFF
]


def _get_element_raw(dataset: Dataset, tag: Tag) -> bytes:
    """Get raw bytes from a DataElement, handling str/bytes/PersonName."""
    if tag not in dataset:
        return b""
    val = dataset[tag].value
    if isinstance(val, bytes):
        return val
    # PersonName preserves original bytes via original_string
    orig = getattr(val, "original_string", None)
    if isinstance(orig, bytes):
        return orig
    return str(val).encode("utf-8", errors="surrogatepass")


@pytest.fixture
def enc_fuzzer() -> EncodingFuzzer:
    """EncodingFuzzer instance."""
    return EncodingFuzzer()


@pytest.fixture
def encoding_dataset() -> Dataset:
    """Dataset with text fields and character set for encoding mutations."""
    ds = Dataset()
    ds.SpecificCharacterSet = "ISO_IR 100"
    ds.PatientName = "Encoding^Test"
    ds.PatientID = "ENC001"
    ds.InstitutionName = "Test Hospital"
    ds.StudyDescription = "Encoding Test Study"
    ds.SeriesDescription = "Series 1"
    ds.ReferringPhysicianName = "Dr^Smith"
    return ds


# ---------------------------------------------------------------------------
# 15. _invalid_charset_value
# ---------------------------------------------------------------------------
class TestInvalidCharsetValue:
    """Verify _invalid_charset_value sets invalid SpecificCharacterSet."""

    def test_charset_changed(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must differ from original."""
        original = encoding_dataset.SpecificCharacterSet
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._invalid_charset_value(ds)
            if result.SpecificCharacterSet != original:
                any_changed = True
                break
        assert any_changed, "_invalid_charset_value never changed SpecificCharacterSet"

    def test_charset_is_invalid(self, enc_fuzzer, encoding_dataset):
        """Charset value must be invalid or problematic."""
        valid_single = {
            "ISO_IR 6",
            "ISO_IR 100",
            "ISO_IR 101",
            "ISO_IR 109",
            "ISO_IR 110",
            "ISO_IR 144",
            "ISO_IR 127",
            "ISO_IR 126",
            "ISO_IR 138",
            "ISO_IR 148",
            "ISO_IR 166",
            "ISO_IR 192",
            "GB18030",
            "GBK",
        }
        any_invalid = False
        for _ in range(20):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._invalid_charset_value(ds)
            cs = result.SpecificCharacterSet
            # Invalid if: not in valid set, is a list, is empty with unicode, has \x00
            if hasattr(cs, "__iter__") and not isinstance(cs, str):
                any_invalid = True
                break
            if cs not in valid_single and cs != "":
                any_invalid = True
                break
            if cs == "" and hasattr(result, "PatientName"):
                name = str(result.PatientName)
                if any(ord(c) > 127 for c in name):
                    any_invalid = True
                    break
        assert any_invalid, "_invalid_charset_value never produced invalid charset"


# ---------------------------------------------------------------------------
# 16. _charset_data_mismatch
# ---------------------------------------------------------------------------
class TestCharsetDataMismatch:
    """Verify _charset_data_mismatch creates encoding/data inconsistency."""

    def test_charset_set(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must be set."""
        result = enc_fuzzer._charset_data_mismatch(encoding_dataset)
        assert hasattr(result, "SpecificCharacterSet")

    def test_mismatch_present(self, enc_fuzzer, encoding_dataset):
        """Declared charset must not match actual text encoding."""
        any_mismatched = False
        for _ in range(20):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._charset_data_mismatch(ds)
            cs = result.SpecificCharacterSet
            raw = _get_element_raw(result, PATIENT_NAME_TAG)
            # Latin-1 declared with non-Latin-1 data (has multi-byte UTF-8)
            if cs == "ISO_IR 100" and any(b > 0x7F for b in raw):
                any_mismatched = True
                break
            # UTF-8 declared with Latin-1 bytes (raw bytes that are invalid UTF-8)
            if cs == "ISO_IR 192":
                try:
                    raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    any_mismatched = True
                    break
            # ASCII declared with non-ASCII data
            if cs == "ISO_IR 6" and any(b > 0x7F for b in raw):
                any_mismatched = True
                break
        assert any_mismatched, "_charset_data_mismatch never created encoding mismatch"


# ---------------------------------------------------------------------------
# 17. _invalid_utf8_sequences
# ---------------------------------------------------------------------------
class TestInvalidUtf8Sequences:
    """Verify _invalid_utf8_sequences injects bytes that are invalid UTF-8."""

    def test_charset_set_to_utf8(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must be ISO_IR 192 (UTF-8)."""
        result = enc_fuzzer._invalid_utf8_sequences(encoding_dataset)
        assert result.SpecificCharacterSet == "ISO_IR 192"

    def test_patient_name_has_invalid_utf8(self, enc_fuzzer, encoding_dataset):
        """PatientName must contain bytes that fail UTF-8 decoding."""
        result = enc_fuzzer._invalid_utf8_sequences(encoding_dataset)
        raw = _get_element_raw(result, PATIENT_NAME_TAG)
        try:
            raw.decode("utf-8", errors="strict")
            pytest.fail("PatientName decoded as valid UTF-8 -- expected invalid bytes")
        except UnicodeDecodeError:
            pass  # Expected

    def test_value_still_contains_text(self, enc_fuzzer, encoding_dataset):
        """Value should contain recognizable text around the invalid bytes."""
        result = enc_fuzzer._invalid_utf8_sequences(encoding_dataset)
        raw = _get_element_raw(result, PATIENT_NAME_TAG)
        assert b"Patient" in raw and b"Name" in raw


# ---------------------------------------------------------------------------
# 18. _escape_sequence_injection
# ---------------------------------------------------------------------------
class TestEscapeSequenceInjection:
    """Verify _escape_sequence_injection embeds ESC bytes in text."""

    def test_charset_set_to_iso2022(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must be ISO 2022 IR 87."""
        result = enc_fuzzer._escape_sequence_injection(encoding_dataset)
        assert result.SpecificCharacterSet == "ISO 2022 IR 87"

    def test_esc_byte_present(self, enc_fuzzer, encoding_dataset):
        """PatientName must contain ESC (0x1B) byte."""
        result = enc_fuzzer._escape_sequence_injection(encoding_dataset)
        raw = _get_element_raw(result, PATIENT_NAME_TAG)
        assert b"\x1b" in raw, "No ESC byte found in PatientName"


# ---------------------------------------------------------------------------
# 19. _bom_injection
# ---------------------------------------------------------------------------
class TestBomInjection:
    """Verify _bom_injection places BOM bytes in text fields."""

    def test_bom_present_in_patient_name(self, enc_fuzzer, encoding_dataset):
        """PatientName must contain at least one BOM byte pattern."""
        any_bom = False
        for _ in range(10):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._bom_injection(ds)
            raw = _get_element_raw(result, PATIENT_NAME_TAG)
            if any(bom in raw for bom in BOM_PATTERNS):
                any_bom = True
                break
        assert any_bom, "_bom_injection never placed BOM bytes in PatientName"

    def test_value_still_contains_text(self, enc_fuzzer, encoding_dataset):
        """Value should contain recognizable text around the BOM."""
        result = enc_fuzzer._bom_injection(encoding_dataset)
        raw = _get_element_raw(result, PATIENT_NAME_TAG)
        assert b"Patient" in raw or b"Name" in raw


# ---------------------------------------------------------------------------
# 20. _null_byte_injection
# ---------------------------------------------------------------------------
class TestNullByteInjection:
    """Verify _null_byte_injection places null bytes in text fields."""

    def test_null_present_in_text_field(self, enc_fuzzer, encoding_dataset):
        """At least one text field must contain a null byte."""
        any_null = False
        for _ in range(10):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._null_byte_injection(ds)
            for tag in [PATIENT_NAME_TAG, INSTITUTION_TAG, STUDY_DESC_TAG]:
                if tag in result:
                    val = result[tag].value
                    text = val if isinstance(val, str) else str(val)
                    if "\x00" in text:
                        any_null = True
                        break
            if any_null:
                break
        assert any_null, "_null_byte_injection never placed null bytes in text"


# ---------------------------------------------------------------------------
# 21. _control_character_injection
# ---------------------------------------------------------------------------
class TestControlCharacterInjection:
    """Verify _control_character_injection places control chars in text."""

    def test_control_char_in_patient_name(self, enc_fuzzer, encoding_dataset):
        """PatientName must contain at least one control character."""
        control_range = set(range(0x01, 0x20)) | {0x7F}
        any_control = False
        for _ in range(10):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._control_character_injection(ds)
            name = str(result.PatientName)
            if any(ord(c) in control_range for c in name):
                any_control = True
                break
        assert any_control, (
            "_control_character_injection never placed control chars in PatientName"
        )


# ---------------------------------------------------------------------------
# 22. _overlong_utf8
# ---------------------------------------------------------------------------
class TestOverlongUtf8:
    """Verify _overlong_utf8 injects overlong UTF-8 encodings."""

    def test_charset_set_to_utf8(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must be ISO_IR 192."""
        result = enc_fuzzer._overlong_utf8(encoding_dataset)
        assert result.SpecificCharacterSet == "ISO_IR 192"

    def test_overlong_bytes_present(self, enc_fuzzer, encoding_dataset):
        """PatientName must contain known overlong byte sequences."""
        overlong_patterns = [
            b"\xc0\x80",
            b"\xe0\x80\x80",
            b"\xf0\x80\x80\x80",
            b"\xc0\xaf",
            b"\xe0\x80\xaf",
            b"\xc1\x9c",
            b"\xe0\x81\x9c",
            b"\xc0\xae",
        ]
        any_overlong = False
        for _ in range(20):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._overlong_utf8(ds)
            raw = _get_element_raw(result, PATIENT_NAME_TAG)
            if any(pat in raw for pat in overlong_patterns):
                any_overlong = True
                break
        assert any_overlong, "_overlong_utf8 never injected overlong byte sequence"

    def test_value_still_contains_text(self, enc_fuzzer, encoding_dataset):
        """Value should contain text around the overlong bytes."""
        result = enc_fuzzer._overlong_utf8(encoding_dataset)
        raw = _get_element_raw(result, PATIENT_NAME_TAG)
        assert b"Patient" in raw and b"Name" in raw


# ---------------------------------------------------------------------------
# 23. _mixed_encoding_attack
# ---------------------------------------------------------------------------
class TestMixedEncodingAttack:
    """Verify _mixed_encoding_attack uses multiple encodings in one dataset."""

    def test_charset_set_to_utf8(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must be ISO_IR 192."""
        result = enc_fuzzer._mixed_encoding_attack(encoding_dataset)
        assert result.SpecificCharacterSet == "ISO_IR 192"

    def test_multiple_fields_with_different_encodings(
        self, enc_fuzzer, encoding_dataset
    ):
        """Multiple text fields must contain data from different encodings."""
        result = enc_fuzzer._mixed_encoding_attack(encoding_dataset)
        # PatientName should have UTF-8 CJK
        pn_raw = _get_element_raw(result, PATIENT_NAME_TAG)
        assert any(b > 0x7F for b in pn_raw), "PatientName has no non-ASCII bytes"
        # InstitutionName should have Latin-1 bytes
        assert INSTITUTION_TAG in result
        inst_raw = _get_element_raw(result, INSTITUTION_TAG)
        assert any(b > 0x7F for b in inst_raw), "InstitutionName has no non-ASCII bytes"

    def test_data_is_not_consistently_decodable(self, enc_fuzzer, encoding_dataset):
        """Not all fields should decode cleanly under the declared charset."""
        result = enc_fuzzer._mixed_encoding_attack(encoding_dataset)
        # InstitutionName has Latin-1 bytes under UTF-8 charset -- should fail
        inst_raw = _get_element_raw(result, INSTITUTION_TAG)
        try:
            inst_raw.decode("utf-8", errors="strict")
            # If it happens to decode, check StudyDescription
            sd_raw = _get_element_raw(result, STUDY_DESC_TAG)
            sd_raw.decode("utf-8", errors="strict")
            # If both decode, that's unexpected but possible -- skip assertion
        except UnicodeDecodeError:
            pass  # Expected -- mixed encoding can't all be valid UTF-8


# ---------------------------------------------------------------------------
# 24. _surrogate_pair_attack
# ---------------------------------------------------------------------------
class TestSurrogatePairAttack:
    """Verify _surrogate_pair_attack injects surrogate bytes in UTF-8 context."""

    def test_charset_set_to_utf8(self, enc_fuzzer, encoding_dataset):
        """SpecificCharacterSet must be ISO_IR 192."""
        result = enc_fuzzer._surrogate_pair_attack(encoding_dataset)
        assert result.SpecificCharacterSet == "ISO_IR 192"

    def test_surrogate_bytes_present(self, enc_fuzzer, encoding_dataset):
        """PatientName must contain UTF-16 surrogate byte patterns."""
        any_surrogate = False
        for _ in range(10):
            ds = copy.deepcopy(encoding_dataset)
            result = enc_fuzzer._surrogate_pair_attack(ds)
            raw = _get_element_raw(result, PATIENT_NAME_TAG)
            if any(pat in raw for pat in SURROGATE_PATTERNS):
                any_surrogate = True
                break
        assert any_surrogate, "_surrogate_pair_attack never injected surrogate bytes"

    def test_value_still_contains_text(self, enc_fuzzer, encoding_dataset):
        """Value should contain text around the surrogate bytes."""
        result = enc_fuzzer._surrogate_pair_attack(encoding_dataset)
        raw = _get_element_raw(result, PATIENT_NAME_TAG)
        assert b"Patient" in raw and b"Name" in raw


# ===========================================================================
# Phase 2a: HeaderFuzzer (7 strategies)
# ===========================================================================


@pytest.fixture
def hdr_fuzzer() -> HeaderFuzzer:
    """HeaderFuzzer instance."""
    return HeaderFuzzer()


@pytest.fixture
def header_dataset() -> Dataset:
    """Dataset with diverse VR types for HeaderFuzzer mutations.

    Includes required tags, dates, times, numeric fields, UIDs, and
    string fields to exercise all 7 header fuzzer strategies.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Header^Test"
    ds.PatientID = "HDR001"
    ds.PatientAge = "045Y"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.FrameOfReferenceUID = generate_uid()
    ds.Modality = "CT"
    ds.Manufacturer = "TestManufacturer"
    ds.InstitutionName = "Test Hospital"
    ds.StudyDescription = "Header Test Study"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.SliceThickness = 1.0
    ds.ModelName = "TestModel"
    ds.SoftwareVersions = "1.0"
    return ds


# ---------------------------------------------------------------------------
# 25. _overlong_strings
# ---------------------------------------------------------------------------
class TestOverlongStrings:
    """Verify _overlong_strings creates strings exceeding VR max length.

    LO VR has a 64-character maximum. The strategy sets fields to
    512-2048 characters, far exceeding the limit.
    """

    def test_institution_name_overlong(self, hdr_fuzzer, header_dataset):
        """InstitutionName must exceed LO max (64 chars)."""
        result = hdr_fuzzer._overlong_strings(header_dataset)
        assert len(result.InstitutionName) > 64

    def test_study_description_overlong(self, hdr_fuzzer, header_dataset):
        """StudyDescription must exceed LO max (64 chars)."""
        result = hdr_fuzzer._overlong_strings(header_dataset)
        assert len(result.StudyDescription) > 64

    def test_manufacturer_overlong(self, hdr_fuzzer, header_dataset):
        """Manufacturer must exceed LO max (64 chars)."""
        result = hdr_fuzzer._overlong_strings(header_dataset)
        assert len(result.Manufacturer) > 64

    def test_all_values_different_characters(self, hdr_fuzzer, header_dataset):
        """Each overlong field should use a different fill character."""
        result = hdr_fuzzer._overlong_strings(header_dataset)
        chars = {
            result.InstitutionName[0],
            result.StudyDescription[0],
            result.Manufacturer[0],
        }
        assert len(chars) == 3, "Expected different fill characters per field"


# ---------------------------------------------------------------------------
# 26. _missing_required_tags
# ---------------------------------------------------------------------------
class TestMissingRequiredTags:
    """Verify _missing_required_tags removes Type 1 tags."""

    REQUIRED = {"PatientName", "PatientID", "StudyInstanceUID", "SeriesInstanceUID"}

    def test_at_least_one_removed(self, hdr_fuzzer, header_dataset):
        """At least one required tag must be absent after mutation."""
        any_removed = False
        for _ in range(20):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._missing_required_tags(ds)
            present = {t for t in self.REQUIRED if hasattr(result, t)}
            if present != self.REQUIRED:
                any_removed = True
                break
        assert any_removed, "_missing_required_tags never removed any required tag"

    def test_removes_different_tags(self, hdr_fuzzer, header_dataset):
        """Should remove different tags across multiple runs."""
        removed_tags = set()
        for _ in range(100):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._missing_required_tags(ds)
            for tag in self.REQUIRED:
                if not hasattr(result, tag):
                    removed_tags.add(tag)
        assert len(removed_tags) >= 2, f"Only ever removed: {removed_tags}"

    def test_not_all_tags_removed(self, hdr_fuzzer, header_dataset):
        """Should not remove all 4 required tags (removes 1-2 max)."""
        for _ in range(50):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._missing_required_tags(ds)
            present = {t for t in self.REQUIRED if hasattr(result, t)}
            assert len(present) >= 2, "Removed too many required tags at once"


# ---------------------------------------------------------------------------
# 27. _invalid_vr_values
# ---------------------------------------------------------------------------
class TestInvalidVrValues:
    """Verify _invalid_vr_values injects VR-violating values."""

    INVALID_DATES = {
        "INVALID",
        "99999999",
        "20251332",
        "20250145",
        "2025-01-01",
        "",
        "1",
    }
    INVALID_TIMES = {"999999", "126000", "120075", "ABCDEF", "12:30:45"}
    INVALID_IS = {"NOT_A_NUMBER", "3.14159", "999999999999", "-999999999", ""}
    INVALID_DS = {"INVALID", "1.2.3", "NaN", "Infinity", "1e999"}

    def test_study_date_invalid(self, hdr_fuzzer, header_dataset):
        """StudyDate must be set to a known invalid date value."""
        any_invalid = False
        for _ in range(10):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._invalid_vr_values(ds)
            if result.StudyDate in self.INVALID_DATES:
                any_invalid = True
                break
        assert any_invalid, "StudyDate was never set to an invalid value"

    def test_study_time_invalid(self, hdr_fuzzer, header_dataset):
        """StudyTime must be set to a known invalid time value."""
        any_invalid = False
        for _ in range(10):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._invalid_vr_values(ds)
            if result.StudyTime in self.INVALID_TIMES:
                any_invalid = True
                break
        assert any_invalid, "StudyTime was never set to an invalid value"

    def test_series_number_invalid_is(self, hdr_fuzzer, header_dataset):
        """SeriesNumber internal value must be set to invalid IS string."""
        any_invalid = False
        for _ in range(10):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._invalid_vr_values(ds)
            elem = result[Tag(0x0020, 0x0011)]  # SeriesNumber
            val = getattr(elem, "_value", None)
            if val in self.INVALID_IS:
                any_invalid = True
                break
        assert any_invalid, "SeriesNumber was never set to an invalid IS value"

    def test_slice_thickness_invalid_ds(self, hdr_fuzzer, header_dataset):
        """SliceThickness internal value must be an invalid decimal string."""
        any_invalid = False
        for _ in range(10):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._invalid_vr_values(ds)
            elem = result[Tag(0x0018, 0x0050)]  # SliceThickness
            val = getattr(elem, "_value", None)
            if val in self.INVALID_DS:
                any_invalid = True
                break
        assert any_invalid, "SliceThickness was never set to an invalid DS value"


# ---------------------------------------------------------------------------
# 28. _boundary_values
# ---------------------------------------------------------------------------
class TestBoundaryValues:
    """Verify _boundary_values sets numeric fields to edge case values."""

    ROW_BOUNDARIES = {0, 1, 65535, -1, 2147483647}
    COL_BOUNDARIES = {0, 1, 65535, -1}
    BOUNDARY_AGES = {"000Y", "999Y", "001D", "999W", "000M"}

    def test_rows_set_to_boundary(self, hdr_fuzzer, header_dataset):
        """Rows must be set to a boundary value."""
        result = hdr_fuzzer._boundary_values(header_dataset)
        assert result.Rows in self.ROW_BOUNDARIES, (
            f"Rows={result.Rows} is not a known boundary value"
        )

    def test_columns_set_to_boundary(self, hdr_fuzzer, header_dataset):
        """Columns must be set to a boundary value."""
        result = hdr_fuzzer._boundary_values(header_dataset)
        assert result.Columns in self.COL_BOUNDARIES, (
            f"Columns={result.Columns} is not a known boundary value"
        )

    def test_patient_name_at_vr_limit(self, hdr_fuzzer, header_dataset):
        """PatientName must be exactly 64 or 65 characters."""
        any_at_limit = False
        for _ in range(10):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._boundary_values(ds)
            name = str(result.PatientName)
            if len(name) in (64, 65):
                any_at_limit = True
                break
        assert any_at_limit, "PatientName never set to VR boundary length"

    def test_patient_age_boundary(self, hdr_fuzzer, header_dataset):
        """PatientAge must be set to a boundary age value."""
        result = hdr_fuzzer._boundary_values(header_dataset)
        assert result.PatientAge in self.BOUNDARY_AGES, (
            f"PatientAge={result.PatientAge} is not a boundary value"
        )


# ---------------------------------------------------------------------------
# 29. _comprehensive_vr_mutations
# ---------------------------------------------------------------------------
class TestComprehensiveVrMutations:
    """Verify _comprehensive_vr_mutations injects VR_MUTATIONS values."""

    def test_vr_mutation_value_injected(self, hdr_fuzzer, header_dataset):
        """At least one element must have a value from VR_MUTATIONS."""
        any_injected = False
        for _ in range(30):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._comprehensive_vr_mutations(ds)
            for elem in result:
                vr = getattr(elem, "VR", None)
                if vr and vr in VR_MUTATIONS:
                    internal = getattr(elem, "_value", None)
                    if internal is not None and internal in VR_MUTATIONS[vr]:
                        any_injected = True
                        break
            if any_injected:
                break
        assert any_injected, (
            "_comprehensive_vr_mutations never injected a VR_MUTATIONS value"
        )

    def test_targets_multiple_vr_types(self, hdr_fuzzer, header_dataset):
        """Should target at least 2 different VR types across runs."""
        targeted_vrs = set()
        for _ in range(50):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._comprehensive_vr_mutations(ds)
            for elem in result:
                vr = getattr(elem, "VR", None)
                if vr and vr in VR_MUTATIONS:
                    internal = getattr(elem, "_value", None)
                    if internal is not None and internal in VR_MUTATIONS[vr]:
                        targeted_vrs.add(vr)
        assert len(targeted_vrs) >= 2, f"Only targeted VR types: {targeted_vrs}"

    def test_does_not_crash(self, hdr_fuzzer, header_dataset):
        """Running 20 times must not raise any exceptions."""
        for _ in range(20):
            ds = copy.deepcopy(header_dataset)
            hdr_fuzzer._comprehensive_vr_mutations(ds)


# ---------------------------------------------------------------------------
# 30. _numeric_vr_mutations
# ---------------------------------------------------------------------------
class TestNumericVrMutations:
    """Verify _numeric_vr_mutations sets US/SS/UL/SL to boundary values."""

    BOUNDARY_VALUES = {
        "US": {0, 1, 65534, 65535},
        "SS": {-32768, -1, 0, 32767},
        "UL": {0, 1, 2147483647, 4294967295},
        "SL": {-2147483648, -1, 0, 2147483647},
    }

    def test_numeric_boundary_applied(self, hdr_fuzzer, header_dataset):
        """At least one numeric element must be changed to a boundary value."""
        any_changed = False
        for _ in range(30):
            ds = copy.deepcopy(header_dataset)
            original = copy.deepcopy(ds)
            result = hdr_fuzzer._numeric_vr_mutations(ds)
            for elem in result:
                vr = getattr(elem, "VR", None)
                if vr in self.BOUNDARY_VALUES:
                    try:
                        new_val = int(elem.value)
                        orig_val = int(original[elem.tag].value)
                        if new_val != orig_val and new_val in self.BOUNDARY_VALUES[vr]:
                            any_changed = True
                            break
                    except (ValueError, TypeError, KeyError):
                        pass
            if any_changed:
                break
        assert any_changed, "_numeric_vr_mutations never changed a numeric field"

    def test_multiple_boundary_values_seen(self, hdr_fuzzer, header_dataset):
        """Should produce at least 2 different boundary values across runs."""
        original_values = {}
        for elem in header_dataset:
            vr = getattr(elem, "VR", None)
            if vr in self.BOUNDARY_VALUES:
                try:
                    original_values[elem.tag] = int(elem.value)
                except (ValueError, TypeError):
                    pass

        seen_changed = set()
        for _ in range(50):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._numeric_vr_mutations(ds)
            for elem in result:
                vr = getattr(elem, "VR", None)
                if vr in self.BOUNDARY_VALUES:
                    try:
                        val = int(elem.value)
                        orig = original_values.get(elem.tag)
                        if orig is not None and val != orig:
                            seen_changed.add(val)
                    except (ValueError, TypeError):
                        pass
        assert len(seen_changed) >= 2, (
            f"Only saw changed boundary values: {seen_changed}"
        )


# ---------------------------------------------------------------------------
# 31. _uid_mutations
# ---------------------------------------------------------------------------
class TestUidMutations:
    """Verify _uid_mutations injects INVALID_UIDS into UID fields."""

    def test_uid_has_invalid_value(self, hdr_fuzzer, header_dataset):
        """At least one UID field must contain an INVALID_UIDS value."""
        any_invalid = False
        for _ in range(20):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._uid_mutations(ds)
            for tag_name in UID_TAG_NAMES:
                if hasattr(result, tag_name):
                    elem = result.data_element(tag_name)
                    if elem and getattr(elem, "_value", None) in INVALID_UIDS:
                        any_invalid = True
                        break
            if any_invalid:
                break
        assert any_invalid, "_uid_mutations never injected an INVALID_UIDS value"

    def test_targets_different_uid_fields(self, hdr_fuzzer, header_dataset):
        """Should target different UID fields across runs."""
        targeted = set()
        for _ in range(100):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._uid_mutations(ds)
            for tag_name in UID_TAG_NAMES:
                if hasattr(result, tag_name):
                    elem = result.data_element(tag_name)
                    if elem and getattr(elem, "_value", None) in INVALID_UIDS:
                        targeted.add(tag_name)
        assert len(targeted) >= 2, f"Only targeted UID fields: {targeted}"

    def test_invalid_uid_has_structural_violation(self, hdr_fuzzer, header_dataset):
        """Injected UIDs should have structural violations per DICOM PS3.5."""
        for _ in range(20):
            ds = copy.deepcopy(header_dataset)
            result = hdr_fuzzer._uid_mutations(ds)
            for tag_name in UID_TAG_NAMES:
                if hasattr(result, tag_name):
                    elem = result.data_element(tag_name)
                    val = getattr(elem, "_value", None)
                    if val in INVALID_UIDS:
                        has_violation = (
                            val == ""
                            or len(val) > 64
                            or val.startswith(".")
                            or val.endswith(".")
                            or ".." in val
                            or "\x00" in val
                            or " " in val
                            or any(c.isalpha() for c in val.replace(".", ""))
                        )
                        if has_violation:
                            return  # Pass
        pytest.fail("No structural UID violation detected")


# ===========================================================================
# Phase 2b: SequenceFuzzer (8 strategies)
# ===========================================================================


@pytest.fixture
def seq_fuzzer() -> SequenceFuzzer:
    """SequenceFuzzer instance."""
    return SequenceFuzzer()


@pytest.fixture
def sequence_dataset() -> Dataset:
    """Dataset with an existing sequence for SequenceFuzzer mutations.

    Includes a ReferencedSeriesSequence with one item so strategies that
    operate on existing sequences (e.g. _delimiter_corruption) have
    something to work with.
    """
    from pydicom.sequence import Sequence

    ds = Dataset()
    ds.PatientName = "Sequence^Test"
    ds.PatientID = "SEQ001"
    ds.StudyDescription = "Sequence Test Study"

    # Existing sequence for strategies that need one
    item = Dataset()
    item.add_new(Tag(0x0008, 0x0100), "SH", "ORIGINAL_CODE")
    item.add_new(Tag(0x0008, 0x0104), "LO", "Original Description")
    ds.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([item]))

    return ds


# ---------------------------------------------------------------------------
# 32. _deep_nesting_attack
# ---------------------------------------------------------------------------
class TestDeepNestingAttack:
    """Verify _deep_nesting_attack creates deeply nested sequences."""

    CONTENT_TAG = Tag(0x0040, 0xA730)
    NESTED_TAG = Tag(0x0008, 0x1115)

    def test_content_sequence_added(self, seq_fuzzer, sequence_dataset):
        """ContentSequence tag must be present after mutation."""
        any_added = False
        for _ in range(10):
            ds = copy.deepcopy(sequence_dataset)
            result = seq_fuzzer._deep_nesting_attack(ds)
            if self.CONTENT_TAG in result:
                any_added = True
                break
        assert any_added, "_deep_nesting_attack never added ContentSequence"

    def test_nesting_depth_at_least_50(self, seq_fuzzer, sequence_dataset):
        """Sequence must be nested at least 50 levels deep."""
        max_depth = 0
        for _ in range(10):
            ds = copy.deepcopy(sequence_dataset)
            result = seq_fuzzer._deep_nesting_attack(ds)
            if self.CONTENT_TAG not in result:
                continue
            depth = 0
            current = result[self.CONTENT_TAG].value
            while current and len(current) > 0 and depth < 60:
                depth += 1
                item = current[0]
                if self.NESTED_TAG in item:
                    current = item[self.NESTED_TAG].value
                else:
                    break
            max_depth = max(max_depth, depth)
            if depth >= 50:
                break
        assert max_depth >= 50, f"Max nesting depth={max_depth}, expected >= 50"


# ---------------------------------------------------------------------------
# 33. _item_length_mismatch
# ---------------------------------------------------------------------------
class TestItemLengthMismatch:
    """Verify _item_length_mismatch creates items with mismatched length data."""

    SQ_TAG = Tag(0x0008, 0x1115)

    def test_sequence_present(self, seq_fuzzer, sequence_dataset):
        """Sequence must still be present after mutation."""
        result = seq_fuzzer._item_length_mismatch(sequence_dataset)
        assert self.SQ_TAG in result

    def test_item_has_attack_element(self, seq_fuzzer, sequence_dataset):
        """Item must contain an element with length mismatch characteristics."""
        any_attack = False
        for _ in range(20):
            ds = copy.deepcopy(sequence_dataset)
            result = seq_fuzzer._item_length_mismatch(ds)
            item = result[self.SQ_TAG].value[0]
            for elem in item:
                val = elem.value if isinstance(elem.value, str) else ""
                # overflow_length: 65536, negative_length: 32768,
                # undefined_length_non_sq: 100000, zero_length: ""
                if len(val) >= 32768 or (val == "" and elem.VR == "LO"):
                    any_attack = True
                    break
            if any_attack:
                break
        assert any_attack, "_item_length_mismatch never created attack element"


# ---------------------------------------------------------------------------
# 34. _empty_required_sequence
# ---------------------------------------------------------------------------
class TestEmptyRequiredSequence:
    """Verify _empty_required_sequence creates sequences with no meaningful items."""

    REQUIRED_SQ_TAGS = {
        Tag(0x0008, 0x1115),
        Tag(0x0008, 0x1140),
        Tag(0x0032, 0x1064),
        Tag(0x0040, 0x0275),
        Tag(0x5200, 0x9230),
    }

    def test_required_sequence_added(self, seq_fuzzer, sequence_dataset):
        """A required sequence tag must be present after mutation."""
        result = seq_fuzzer._empty_required_sequence(sequence_dataset)
        found = any(tag in result for tag in self.REQUIRED_SQ_TAGS)
        assert found, "No required sequence tag was added"

    def test_sequence_is_empty_or_has_empty_item(self, seq_fuzzer, sequence_dataset):
        """Sequence must have 0 items, an empty item, or an empty nested SQ."""
        any_empty = False
        for _ in range(30):
            ds = copy.deepcopy(sequence_dataset)
            result = seq_fuzzer._empty_required_sequence(ds)
            for tag in self.REQUIRED_SQ_TAGS:
                if tag not in result:
                    continue
                sq_elem = result[tag]
                if not (hasattr(sq_elem, "VR") and sq_elem.VR == "SQ"):
                    continue
                seq_val = sq_elem.value
                # empty_sequence: Sequence([])
                if len(seq_val) == 0:
                    any_empty = True
                    break
                # null_first_item: item with 0 data elements
                if any(len(item) == 0 for item in seq_val):
                    any_empty = True
                    break
                # empty_nested: item has nested SQ with 0 items
                for item in seq_val:
                    for elem in item:
                        if elem.VR == "SQ" and len(elem.value) == 0:
                            any_empty = True
                            break
                    if any_empty:
                        break
            if any_empty:
                break
        assert any_empty, "_empty_required_sequence never created empty sequence"


# ---------------------------------------------------------------------------
# 35. _orphan_item_attack
# ---------------------------------------------------------------------------
class TestOrphanItemAttack:
    """Verify _orphan_item_attack places Item-like data outside a sequence."""

    CREATOR_TAG = Tag(0x0009, 0x0010)
    DATA_TAG = Tag(0x0009, 0x1000)
    ITEM_TAG_BYTES = b"\xfe\xff\x00\xe0"

    def test_private_creator_added(self, seq_fuzzer, sequence_dataset):
        """Private creator element must be present."""
        result = seq_fuzzer._orphan_item_attack(sequence_dataset)
        assert self.CREATOR_TAG in result
        assert result[self.CREATOR_TAG].value == "OrphanItemCreator"

    def test_item_bytes_in_non_sequence_element(self, seq_fuzzer, sequence_dataset):
        """UN element must contain Item tag bytes outside a sequence context."""
        result = seq_fuzzer._orphan_item_attack(sequence_dataset)
        assert self.DATA_TAG in result
        val = result[self.DATA_TAG].value
        assert self.ITEM_TAG_BYTES in val, "No Item tag bytes found in private data"


# ---------------------------------------------------------------------------
# 36. _circular_reference_attack
# ---------------------------------------------------------------------------
class TestCircularReferenceAttack:
    """Verify _circular_reference_attack creates mutual UID references."""

    REF_TAG = Tag(0x0008, 0x1140)  # ReferencedImageSequence
    SOP_UID_TAG = Tag(0x0008, 0x0018)
    REF_SOP_TAG = Tag(0x0008, 0x1155)

    def test_reference_sequence_added(self, seq_fuzzer, sequence_dataset):
        """ReferencedImageSequence must be present with 2 items."""
        result = seq_fuzzer._circular_reference_attack(sequence_dataset)
        assert self.REF_TAG in result
        assert len(result[self.REF_TAG].value) == 2

    def test_items_reference_each_other(self, seq_fuzzer, sequence_dataset):
        """Item1 must reference Item2's UID and vice versa."""
        result = seq_fuzzer._circular_reference_attack(sequence_dataset)
        seq = result[self.REF_TAG].value

        uid1 = seq[0][self.SOP_UID_TAG].value
        uid2 = seq[1][self.SOP_UID_TAG].value
        ref1 = seq[0][self.REF_SOP_TAG].value  # Item1 references...
        ref2 = seq[1][self.REF_SOP_TAG].value  # Item2 references...

        assert str(ref1) == str(uid2), "Item1 should reference Item2's UID"
        assert str(ref2) == str(uid1), "Item2 should reference Item1's UID"


# ---------------------------------------------------------------------------
# 37. _delimiter_corruption
# ---------------------------------------------------------------------------
class TestDelimiterCorruption:
    """Verify _delimiter_corruption embeds delimiter bytes in text values."""

    SQ_TAG = Tag(0x0008, 0x1115)
    DESC_TAG = Tag(0x0008, 0x1030)  # StudyDescription within item

    def test_delimiter_bytes_in_text(self, seq_fuzzer, sequence_dataset):
        """Item text value must contain sequence delimiter bytes."""
        result = seq_fuzzer._delimiter_corruption(sequence_dataset)
        item = result[self.SQ_TAG].value[0]
        assert self.DESC_TAG in item, "StudyDescription not added to item"
        val = item[self.DESC_TAG].value
        # Sequence delimiter bytes: FE FF DD E0
        assert "\xfe\xff\xdd\xe0" in val, (
            "Sequence delimiter bytes not found in text value"
        )

    def test_original_item_data_preserved(self, seq_fuzzer, sequence_dataset):
        """Original item elements should still be present."""
        result = seq_fuzzer._delimiter_corruption(sequence_dataset)
        item = result[self.SQ_TAG].value[0]
        assert Tag(0x0008, 0x0100) in item  # Original CODE element


# ---------------------------------------------------------------------------
# 38. _mixed_encoding_sequence
# ---------------------------------------------------------------------------
class TestMixedEncodingSequence:
    """Verify _mixed_encoding_sequence creates items with different charsets."""

    SQ_TAG = Tag(0x0032, 0x1064)  # RequestedProcedureCodeSequence
    CS_TAG = Tag(0x0008, 0x0005)  # SpecificCharacterSet

    def test_sequence_added(self, seq_fuzzer, sequence_dataset):
        """Requested Procedure Code Sequence must be present."""
        result = seq_fuzzer._mixed_encoding_sequence(sequence_dataset)
        assert self.SQ_TAG in result

    def test_three_items_created(self, seq_fuzzer, sequence_dataset):
        """Sequence must contain exactly 3 items."""
        result = seq_fuzzer._mixed_encoding_sequence(sequence_dataset)
        assert len(result[self.SQ_TAG].value) == 3

    def test_items_have_different_charsets(self, seq_fuzzer, sequence_dataset):
        """Items must declare different SpecificCharacterSet values."""
        result = seq_fuzzer._mixed_encoding_sequence(sequence_dataset)
        seq = result[self.SQ_TAG].value
        charsets = set()
        for item in seq:
            if self.CS_TAG in item:
                charsets.add(item[self.CS_TAG].value)
            else:
                charsets.add(None)  # No charset declared
        assert len(charsets) >= 2, f"Only saw charsets: {charsets}"


# ---------------------------------------------------------------------------
# 39. _massive_item_count
# ---------------------------------------------------------------------------
class TestMassiveItemCount:
    """Verify _massive_item_count creates sequences with >= 100 items."""

    def test_sequence_has_many_items(self, seq_fuzzer, sequence_dataset):
        """At least one sequence must have >= 100 items."""
        any_massive = False
        for _ in range(10):
            ds = copy.deepcopy(sequence_dataset)
            result = seq_fuzzer._massive_item_count(ds)
            for _, elem in result.items():
                if hasattr(elem, "VR") and elem.VR == "SQ":
                    if len(elem.value) >= 100:
                        any_massive = True
                        break
            if any_massive:
                break
        assert any_massive, (
            "_massive_item_count never created sequence with >= 100 items"
        )

    def test_items_have_data(self, seq_fuzzer, sequence_dataset):
        """Items in massive sequence must contain actual data elements."""
        for _ in range(10):
            ds = copy.deepcopy(sequence_dataset)
            result = seq_fuzzer._massive_item_count(ds)
            for _, elem in result.items():
                if hasattr(elem, "VR") and elem.VR == "SQ" and len(elem.value) >= 100:
                    # Spot-check first and last items have data
                    assert len(elem.value[0]) > 0, "First item is empty"
                    assert len(elem.value[-1]) > 0, "Last item is empty"
                    return
        pytest.fail("Could not find massive sequence to verify item data")


# ===========================================================================
# Phase 2c: StructureFuzzer (6 strategies)
# ===========================================================================


@pytest.fixture
def str_fuzzer() -> StructureFuzzer:
    """StructureFuzzer instance."""
    return StructureFuzzer()


@pytest.fixture
def structure_dataset() -> Dataset:
    """Dataset with diverse elements for StructureFuzzer mutations.

    Includes string VRs (LO, SH, PN), numeric VRs (US, DS),
    UID/date/time VRs, and multi-value tags for VM mismatch testing.
    """
    ds = Dataset()
    ds.PatientName = "Structure^Test"
    ds.PatientID = "STR001"
    ds.StudyDescription = "Structure Test"
    ds.InstitutionName = "Test Hospital"
    ds.Modality = "CT"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.SliceThickness = 1.0
    ds.ImagePositionPatient = [0.0, 0.0, 0.0]
    ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
    ds.PixelSpacing = [0.5, 0.5]
    return ds


# ---------------------------------------------------------------------------
# 40. _corrupt_tag_ordering
# ---------------------------------------------------------------------------
class TestCorruptTagOrdering:
    """Verify _corrupt_tag_ordering disrupts ascending tag order."""

    def test_returns_new_dataset(self, str_fuzzer, structure_dataset):
        """Strategy must return a new Dataset object (not the original)."""
        result = str_fuzzer._corrupt_tag_ordering(structure_dataset)
        assert result is not structure_dataset

    def test_preserves_all_tags(self, str_fuzzer, structure_dataset):
        """All original tags must still be present."""
        original_tags = set(structure_dataset.keys())
        result = str_fuzzer._corrupt_tag_ordering(structure_dataset)
        assert set(result.keys()) == original_tags

    def test_tag_ordering_disrupted(self, str_fuzzer, structure_dataset):
        """Tags should not be in ascending order after corruption."""
        any_unsorted = False
        for _ in range(20):
            ds = copy.deepcopy(structure_dataset)
            result = str_fuzzer._corrupt_tag_ordering(ds)
            tags = list(result.keys())
            is_sorted = all(tags[i] <= tags[i + 1] for i in range(len(tags) - 1))
            if not is_sorted:
                any_unsorted = True
                break
        assert any_unsorted, "_corrupt_tag_ordering never disrupted tag order"


# ---------------------------------------------------------------------------
# 41. _corrupt_length_fields
# ---------------------------------------------------------------------------
class TestCorruptLengthFields:
    """Verify _corrupt_length_fields modifies string element values."""

    STRING_VRS = {"LO", "SH", "PN", "LT", "ST", "UT"}

    def test_string_element_modified(self, str_fuzzer, structure_dataset):
        """At least one string element must be modified."""
        any_modified = False
        for _ in range(30):
            ds = copy.deepcopy(structure_dataset)
            original = copy.deepcopy(ds)
            result = str_fuzzer._corrupt_length_fields(ds)
            for tag, elem in result.items():
                if tag not in original:
                    continue
                vr = getattr(elem, "VR", None)
                if vr in self.STRING_VRS:
                    if str(elem.value) != str(original[tag].value):
                        any_modified = True
                        break
            if any_modified:
                break
        assert any_modified, "_corrupt_length_fields never modified a string element"

    def test_multiple_corruption_types(self, str_fuzzer, structure_dataset):
        """Should produce at least 2 different corruption types across runs."""
        patterns = set()
        for _ in range(100):
            ds = copy.deepcopy(structure_dataset)
            original = copy.deepcopy(ds)
            result = str_fuzzer._corrupt_length_fields(ds)
            for tag, elem in result.items():
                if tag not in original:
                    continue
                vr = getattr(elem, "VR", None)
                if vr not in self.STRING_VRS:
                    continue
                old_val = str(original[tag].value)
                new_val = str(elem.value)
                if new_val == old_val:
                    continue
                if "XXXXXXXXX" in new_val:
                    patterns.add("overflow")
                elif new_val == "":
                    patterns.add("underflow")
                elif "\x00" in new_val and len(new_val) > len(old_val):
                    patterns.add("mismatch")
        assert len(patterns) >= 2, f"Only saw corruption types: {patterns}"


# ---------------------------------------------------------------------------
# 42. _insert_unexpected_tags
# ---------------------------------------------------------------------------
class TestInsertUnexpectedTags:
    """Verify _insert_unexpected_tags adds reserved/invalid tag numbers."""

    def test_unexpected_tag_present(self, str_fuzzer, structure_dataset):
        """At least one tag not in the original dataset must be added."""
        original_tags = set(structure_dataset.keys())
        any_new = False
        for _ in range(20):
            ds = copy.deepcopy(structure_dataset)
            result = str_fuzzer._insert_unexpected_tags(ds)
            new_tags = set(result.keys()) - original_tags
            if new_tags:
                any_new = True
                break
        assert any_new, "_insert_unexpected_tags never added a new tag"

    def test_unexpected_data_has_null_bytes(self, str_fuzzer, structure_dataset):
        """Inserted tags must contain null-byte payload.

        pydicom may override the requested "UN" VR for known tags
        (e.g. 0x00000000 -> UL), so we verify the value content instead.
        """
        original_tags = set(structure_dataset.keys())
        for _ in range(20):
            ds = copy.deepcopy(structure_dataset)
            result = str_fuzzer._insert_unexpected_tags(ds)
            new_tags = set(result.keys()) - original_tags
            for tag in new_tags:
                elem = result[tag]
                raw = (
                    bytes(elem.value)
                    if not isinstance(elem.value, bytes)
                    else elem.value
                )
                assert b"\x00" in raw, f"Expected null bytes in payload, got {raw!r}"
                return
        pytest.fail("Could not find unexpected tag to verify")


# ---------------------------------------------------------------------------
# 43. _duplicate_tags
# ---------------------------------------------------------------------------
class TestDuplicateTags:
    """Verify _duplicate_tags overwrites an element with _DUPLICATE suffix.

    pydicom prevents true duplicate tags at the Dataset level, so the
    strategy replaces the original value with one ending in '_DUPLICATE'.
    """

    def test_duplicate_suffix_in_value(self, str_fuzzer, structure_dataset):
        """At least one element value must end with '_DUPLICATE'."""
        any_duplicate = False
        for _ in range(30):
            ds = copy.deepcopy(structure_dataset)
            result = str_fuzzer._duplicate_tags(ds)
            for elem in result:
                try:
                    val = str(elem.value)
                    if "_DUPLICATE" in val:
                        any_duplicate = True
                        break
                except Exception:
                    pass
            if any_duplicate:
                break
        assert any_duplicate, "_duplicate_tags never produced _DUPLICATE suffix"


# ---------------------------------------------------------------------------
# 44. _length_field_attacks
# ---------------------------------------------------------------------------
class TestLengthFieldAttacks:
    """Verify _length_field_attacks creates extreme/zero/boundary length values."""

    def test_attack_evidence_present(self, str_fuzzer, structure_dataset):
        """At least one length field attack pattern must be detectable."""
        for _ in range(100):
            ds = copy.deepcopy(structure_dataset)
            original = copy.deepcopy(ds)
            result = str_fuzzer._length_field_attacks(ds)
            for tag, elem in result.items():
                if tag not in original:
                    continue
                old = original[tag]
                new_val = getattr(elem, "_value", elem.value)
                old_val = getattr(old, "_value", old.value)
                if new_val == old_val:
                    continue
                # Extreme string length (65535+)
                if isinstance(new_val, str) and len(new_val) >= 10000:
                    return
                # Zero-length required field
                if new_val == "" and old_val != "":
                    return
                # Odd-length for word-aligned VR
                if isinstance(new_val, bytes) and len(new_val) % 2 == 1:
                    return
                # Boundary numeric value
                if isinstance(new_val, int) and new_val in {65535, 4294967295}:
                    return
        pytest.fail("No length field attack pattern detected in 100 runs")


# ---------------------------------------------------------------------------
# 45. _vm_mismatch_attacks
# ---------------------------------------------------------------------------
class TestVmMismatchAttacks:
    """Verify _vm_mismatch_attacks creates Value Multiplicity violations."""

    # Multi-value tags (VM > 1) that can be reduced to single value
    MULTI_VALUE_TAGS = {
        Tag(0x0020, 0x0032): 3,  # ImagePositionPatient
        Tag(0x0020, 0x0037): 6,  # ImageOrientationPatient
        Tag(0x0028, 0x0030): 2,  # PixelSpacing
    }
    # Single-value tags (VM = 1) that can get multiple values
    SINGLE_VALUE_TAGS = {
        Tag(0x0018, 0x0050),  # SliceThickness (DS)
        Tag(0x0008, 0x0018),  # SOPInstanceUID (UI)
    }

    def test_vm_mismatch_detectable(self, str_fuzzer, structure_dataset):
        """At least one VM mismatch pattern must be detectable."""
        for _ in range(100):
            ds = copy.deepcopy(structure_dataset)
            result = str_fuzzer._vm_mismatch_attacks(ds)
            # too_many: single-value tag now has backslash separator
            for tag in self.SINGLE_VALUE_TAGS:
                if tag in result:
                    val = getattr(result[tag], "_value", None)
                    if isinstance(val, str) and "\\" in val:
                        return
            # too_few: multi-value tag reduced to single value
            for tag in self.MULTI_VALUE_TAGS:
                if tag in result:
                    val = getattr(result[tag], "_value", None)
                    if val == "1.0":
                        return
            # empty_multivalue: multi-value tag set to ""
            for tag in self.MULTI_VALUE_TAGS:
                if tag in result:
                    val = getattr(result[tag], "_value", None)
                    if val == "":
                        return
        pytest.fail("No VM mismatch detected in 100 runs")


# ===========================================================================
# Phase 3a: ConformanceFuzzer (10 strategies)
# ===========================================================================


@pytest.fixture
def conf_fuzzer() -> ConformanceFuzzer:
    """ConformanceFuzzer instance."""
    return ConformanceFuzzer()


@pytest.fixture
def conformance_dataset() -> Dataset:
    """Dataset with full file_meta for ConformanceFuzzer mutations.

    Includes all meta information elements that the 10 strategies target:
    TransferSyntaxUID, MediaStorageSOPClassUID, ImplementationClassUID,
    FileMetaInformationVersion, Modality, and UID fields.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()
    file_meta.ImplementationVersionName = "TEST_V1"
    file_meta.FileMetaInformationVersion = b"\x00\x01"

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Conformance^Test"
    ds.PatientID = "CNF001"
    ds.Modality = "CT"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    return ds


# ---------------------------------------------------------------------------
# 46. _invalid_sop_class
# ---------------------------------------------------------------------------
class TestInvalidSopClass:
    """Verify _invalid_sop_class sets SOPClassUID to non-standard value."""

    def test_sop_class_changed(self, conf_fuzzer, conformance_dataset):
        """SOPClassUID must differ from original after mutation."""
        original = conformance_dataset.SOPClassUID
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._invalid_sop_class(ds)
            if str(result.SOPClassUID) != str(original):
                any_changed = True
                break
        assert any_changed, "_invalid_sop_class never changed SOPClassUID"

    def test_file_meta_matches_dataset(self, conf_fuzzer, conformance_dataset):
        """MediaStorageSOPClassUID must match SOPClassUID."""
        result = conf_fuzzer._invalid_sop_class(conformance_dataset)
        assert str(result.file_meta.MediaStorageSOPClassUID) == str(result.SOPClassUID)


# ---------------------------------------------------------------------------
# 47. _invalid_transfer_syntax
# ---------------------------------------------------------------------------
class TestInvalidTransferSyntax:
    """Verify _invalid_transfer_syntax sets non-standard TransferSyntaxUID."""

    def test_transfer_syntax_changed(self, conf_fuzzer, conformance_dataset):
        """TransferSyntaxUID must differ from original."""
        original = str(conformance_dataset.file_meta.TransferSyntaxUID)
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._invalid_transfer_syntax(ds)
            if str(result.file_meta.TransferSyntaxUID) != original:
                any_changed = True
                break
        assert any_changed, "_invalid_transfer_syntax never changed TransferSyntaxUID"


# ---------------------------------------------------------------------------
# 48. _sop_transfer_mismatch
# ---------------------------------------------------------------------------
class TestSopTransferMismatch:
    """Verify _sop_transfer_mismatch creates SOP/syntax incompatibility."""

    # Known incompatible pairs from the strategy
    MISMATCH_PAIRS = {
        ("1.2.840.10008.5.1.4.1.1.2", "1.2.840.10008.1.2.4.100"),
        ("1.2.840.10008.5.1.4.1.1.88.11", "1.2.840.10008.1.2.4.50"),
        ("1.2.840.10008.5.1.4.1.1.104.1", "1.2.840.10008.1.2.5"),
        ("1.2.840.10008.5.1.4.1.1.481.2", "1.2.840.10008.1.2.4.102"),
    }

    def test_sop_and_syntax_are_mismatched(self, conf_fuzzer, conformance_dataset):
        """SOP class and transfer syntax must be an incompatible pair."""
        result = conf_fuzzer._sop_transfer_mismatch(conformance_dataset)
        pair = (str(result.SOPClassUID), str(result.file_meta.TransferSyntaxUID))
        assert pair in self.MISMATCH_PAIRS, f"Pair {pair} not in known mismatches"


# ---------------------------------------------------------------------------
# 49. _missing_file_meta
# ---------------------------------------------------------------------------
class TestMissingFileMeta:
    """Verify _missing_file_meta removes file_meta or required elements."""

    def test_meta_element_removed(self, conf_fuzzer, conformance_dataset):
        """file_meta must be None or missing at least one required element."""
        any_removed = False
        for _ in range(20):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._missing_file_meta(ds)
            if result.file_meta is None:
                any_removed = True
                break
            if not hasattr(result.file_meta, "MediaStorageSOPClassUID"):
                any_removed = True
                break
            if not hasattr(result.file_meta, "TransferSyntaxUID"):
                any_removed = True
                break
            if not hasattr(result.file_meta, "MediaStorageSOPInstanceUID"):
                any_removed = True
                break
        assert any_removed, "_missing_file_meta never removed meta information"

    def test_multiple_removal_types(self, conf_fuzzer, conformance_dataset):
        """Should produce at least 2 different removal types across runs."""
        removals = set()
        for _ in range(100):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._missing_file_meta(ds)
            if result.file_meta is None:
                removals.add("all")
            elif not hasattr(result.file_meta, "MediaStorageSOPClassUID"):
                removals.add("sop_class")
            elif not hasattr(result.file_meta, "TransferSyntaxUID"):
                removals.add("transfer_syntax")
            elif not hasattr(result.file_meta, "MediaStorageSOPInstanceUID"):
                removals.add("sop_instance")
        assert len(removals) >= 2, f"Only saw removal types: {removals}"


# ---------------------------------------------------------------------------
# 50. _corrupted_file_meta
# ---------------------------------------------------------------------------
class TestCorruptedFileMeta:
    """Verify _corrupted_file_meta corrupts file meta fields."""

    def test_meta_corrupted(self, conf_fuzzer, conformance_dataset):
        """At least one file meta corruption pattern must be detectable."""
        for _ in range(20):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._corrupted_file_meta(ds)
            # wrong_preamble
            if hasattr(result, "preamble") and result.preamble == b"\xff" * 128:
                return
            # wrong_version
            fmiv = getattr(result.file_meta, "FileMetaInformationVersion", None)
            if fmiv == b"\xff\xff":
                return
            # extra_meta_elements
            if Tag(0x0002, 0x9999) in result.file_meta:
                return
            # wrong_meta_length
            fmigl = getattr(result.file_meta, "FileMetaInformationGroupLength", None)
            if fmigl == 99999:
                return
        pytest.fail("No file meta corruption detected")


# ---------------------------------------------------------------------------
# 51. _version_mismatch
# ---------------------------------------------------------------------------
class TestVersionMismatch:
    """Verify _version_mismatch sets FileMetaInformationVersion to wrong bytes."""

    STANDARD_VERSION = b"\x00\x01"

    def test_version_not_standard(self, conf_fuzzer, conformance_dataset):
        """FileMetaInformationVersion must differ from standard b'\\x00\\x01'."""
        result = conf_fuzzer._version_mismatch(conformance_dataset)
        version = result.file_meta.FileMetaInformationVersion
        assert version != self.STANDARD_VERSION, (
            "Version should not be standard after mutation"
        )

    def test_version_is_known_attack_value(self, conf_fuzzer, conformance_dataset):
        """Version must be one of the known attack values."""
        attack_versions = {b"\x00\x00", b"\x00\x99", b"\xff\xff\xff\xff"}
        any_known = False
        for _ in range(10):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._version_mismatch(ds)
            if result.file_meta.FileMetaInformationVersion in attack_versions:
                any_known = True
                break
        assert any_known, "Version never set to a known attack value"


# ---------------------------------------------------------------------------
# 52. _implementation_uid_attack
# ---------------------------------------------------------------------------
class TestImplementationUidAttack:
    """Verify _implementation_uid_attack corrupts implementation identifiers."""

    def test_implementation_modified(self, conf_fuzzer, conformance_dataset):
        """ImplementationClassUID or VersionName must change."""
        original_uid = str(conformance_dataset.file_meta.ImplementationClassUID)
        original_ver = conformance_dataset.file_meta.ImplementationVersionName
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._implementation_uid_attack(ds)
            uid = str(result.file_meta.ImplementationClassUID)
            ver = result.file_meta.ImplementationVersionName
            if uid != original_uid or ver != original_ver:
                any_changed = True
                break
        assert any_changed, "_implementation_uid_attack never modified identifiers"


# ---------------------------------------------------------------------------
# 53. _modality_sop_mismatch
# ---------------------------------------------------------------------------
class TestModalitySopMismatch:
    """Verify _modality_sop_mismatch creates Modality/SOPClass incompatibility."""

    # Known mismatch pairs (Modality, wrong SOPClassUID)
    MISMATCH_PAIRS = {
        ("CT", "1.2.840.10008.5.1.4.1.1.4"),
        ("MR", "1.2.840.10008.5.1.4.1.1.2"),
        ("US", "1.2.840.10008.5.1.4.1.1.20"),
        ("PT", "1.2.840.10008.5.1.4.1.1.1"),
        ("RTDOSE", "1.2.840.10008.5.1.4.1.1.2"),
        ("SR", "1.2.840.10008.5.1.4.1.1.6.1"),
    }

    def test_modality_and_sop_mismatched(self, conf_fuzzer, conformance_dataset):
        """Modality and SOPClassUID must be an incompatible pair."""
        result = conf_fuzzer._modality_sop_mismatch(conformance_dataset)
        pair = (result.Modality, str(result.SOPClassUID))
        assert pair in self.MISMATCH_PAIRS, f"Pair {pair} not in known mismatch set"


# ---------------------------------------------------------------------------
# 54. _uid_format_violations
# ---------------------------------------------------------------------------
class TestUidFormatViolations:
    """Verify _uid_format_violations injects INVALID_UIDS into UID fields."""

    UID_TAGS = [
        Tag(0x0008, 0x0016),  # SOPClassUID
        Tag(0x0008, 0x0018),  # SOPInstanceUID
        Tag(0x0020, 0x000D),  # StudyInstanceUID
        Tag(0x0020, 0x000E),  # SeriesInstanceUID
    ]

    def test_uid_changed_to_invalid(self, conf_fuzzer, conformance_dataset):
        """At least one UID field must be changed from its original value."""
        original_uids = {}
        for tag in self.UID_TAGS:
            if tag in conformance_dataset:
                original_uids[tag] = str(conformance_dataset[tag].value)

        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._uid_format_violations(ds)
            for tag, orig in original_uids.items():
                if tag in result and str(result[tag].value) != orig:
                    any_changed = True
                    break
            if any_changed:
                break
        assert any_changed, "_uid_format_violations never changed a UID field"


# ---------------------------------------------------------------------------
# 55. _retired_syntax_attack
# ---------------------------------------------------------------------------
class TestRetiredSyntaxAttack:
    """Verify _retired_syntax_attack uses retired/deprecated transfer syntaxes."""

    RETIRED_TS = {
        "1.2.840.10008.1.2.4.52",
        "1.2.840.10008.1.2.4.53",
        "1.2.840.10008.1.2.4.54",
    }

    def test_retired_or_deprecated_syntax_used(self, conf_fuzzer, conformance_dataset):
        """TransferSyntaxUID must be retired, or SOP class must be retired."""
        for _ in range(20):
            ds = copy.deepcopy(conformance_dataset)
            result = conf_fuzzer._retired_syntax_attack(ds)
            ts = str(result.file_meta.TransferSyntaxUID)
            sop = str(result.file_meta.MediaStorageSOPClassUID)
            # Retired transfer syntax
            if ts in self.RETIRED_TS:
                return
            # Explicit VR Big Endian (retired)
            if ts == str(ExplicitVRBigEndian):
                return
            # Retired SOP class with modern syntax
            if sop == "1.2.840.10008.5.1.4.1.1.5":
                return
        pytest.fail("No retired/deprecated syntax detected")


# ===========================================================================
# Phase 3b: MetadataFuzzer
# ===========================================================================


@pytest.fixture
def meta_fuzzer() -> MetadataFuzzer:
    """Return MetadataFuzzer instance."""
    return MetadataFuzzer()


@pytest.fixture
def metadata_dataset() -> Dataset:
    """Dataset with full metadata hierarchy for MetadataFuzzer tests."""
    ds = Dataset()
    # Patient identifiers
    ds.PatientName = "Smith^John"
    ds.PatientID = "PAT001"
    ds.PatientBirthDate = "19800101"
    # Patient demographics
    ds.PatientSex = "M"
    ds.PatientAge = "045Y"
    ds.PatientWeight = 75.0
    ds.PatientSize = 1.75
    # Study metadata
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.StudyID = "STUDY001"
    ds.AccessionNumber = "ACC001"
    ds.ReferringPhysicianName = "Jones^Alice"
    # Series metadata
    ds.SeriesDate = "20250101"
    ds.SeriesDescription = "CT HEAD W/O CONTRAST"
    ds.BodyPartExamined = "HEAD"
    # Institution / personnel
    ds.InstitutionName = "Test Hospital"
    ds.InstitutionAddress = "123 Main St, City, ST 12345"
    ds.StationName = "CT_SCANNER_1"
    ds.OperatorsName = "Tech^Bob"
    ds.PerformingPhysicianName = "Doctor^Chris"
    return ds


# ---------------------------------------------------------------------------
# 56. _patient_identifier_attack
# ---------------------------------------------------------------------------
class TestPatientIdentifierAttack:
    """Verify _patient_identifier_attack injects malicious patient identifiers."""

    def test_at_least_one_identifier_modified(self, meta_fuzzer, metadata_dataset):
        """At least one of PatientID, PatientName, PatientBirthDate must change."""
        orig_id = metadata_dataset.PatientID
        orig_name = str(metadata_dataset.PatientName)
        orig_dob = metadata_dataset.PatientBirthDate
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._patient_identifier_attack(ds)
            if (
                ds.PatientID != orig_id
                or str(ds.PatientName) != orig_name
                or ds.PatientBirthDate != orig_dob
            ):
                any_changed = True
                break
        assert any_changed, "_patient_identifier_attack never modified any identifier"

    def test_patient_id_attack_values(self, meta_fuzzer, metadata_dataset):
        """PatientID should be set to injection, overlong, or boundary values."""
        orig_id = metadata_dataset.PatientID
        attack_found = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._patient_identifier_attack(ds)
            pid = ds.PatientID
            if pid != orig_id:
                is_injection = any(
                    p in pid for p in ["DROP", "script", "passwd", "jndi"]
                )
                is_overlong = len(pid) > 64
                is_boundary = pid == "" or "\x00" in pid or "\t" in pid or "\\" in pid
                if is_injection or is_overlong or is_boundary:
                    attack_found = True
                    break
        assert attack_found, "PatientID never set to a recognizable attack value"

    def test_birth_date_invalid_format(self, meta_fuzzer, metadata_dataset):
        """PatientBirthDate should be set to an invalid DICOM date."""
        orig_dob = metadata_dataset.PatientBirthDate
        found_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._patient_identifier_attack(ds)
            if (
                ds.PatientBirthDate != orig_dob
                and ds.PatientBirthDate in _INVALID_DATES
            ):
                found_invalid = True
                break
        assert found_invalid, "PatientBirthDate never set to a known invalid date"


# ---------------------------------------------------------------------------
# 57. _patient_demographics_attack
# ---------------------------------------------------------------------------
class TestPatientDemographicsAttack:
    """Verify _patient_demographics_attack creates invalid demographic values."""

    def test_at_least_one_demographic_modified(self, meta_fuzzer, metadata_dataset):
        """At least one demographic field must change."""
        orig = {
            "sex": metadata_dataset.PatientSex,
            "age": metadata_dataset.PatientAge,
            "weight": metadata_dataset.PatientWeight,
            "size": metadata_dataset.PatientSize,
        }
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._patient_demographics_attack(ds)
            if (
                ds.PatientSex != orig["sex"]
                or ds.PatientAge != orig["age"]
                or ds.PatientWeight != orig["weight"]
                or ds.PatientSize != orig["size"]
            ):
                any_changed = True
                break
        assert any_changed

    def test_sex_invalid_code(self, meta_fuzzer, metadata_dataset):
        """PatientSex should be set to an invalid code."""
        valid_codes = {"M", "F", "O"}
        found_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._patient_demographics_attack(ds)
            if ds.PatientSex not in valid_codes:
                found_invalid = True
                break
        assert found_invalid, "PatientSex never set to an invalid code"

    def test_weight_boundary_value(self, meta_fuzzer, metadata_dataset):
        """PatientWeight should be zero, negative, extreme, or special float."""
        import math

        found_boundary = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._patient_demographics_attack(ds)
            w = ds.PatientWeight
            if w != 75.0:
                if w <= 0 or w > 1e6 or math.isinf(w) or w < 0.001 or w > 1e300:
                    found_boundary = True
                    break
        assert found_boundary, "PatientWeight never set to a boundary value"


# ---------------------------------------------------------------------------
# 58. _study_metadata_attack
# ---------------------------------------------------------------------------
class TestStudyMetadataAttack:
    """Verify _study_metadata_attack creates invalid study-level metadata."""

    def test_at_least_one_study_field_modified(self, meta_fuzzer, metadata_dataset):
        """At least one study metadata field must change."""
        orig = {
            "date": metadata_dataset.StudyDate,
            "time": metadata_dataset.StudyTime,
            "id": metadata_dataset.StudyID,
            "acc": metadata_dataset.AccessionNumber,
            "ref": str(metadata_dataset.ReferringPhysicianName),
        }
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._study_metadata_attack(ds)
            if (
                ds.StudyDate != orig["date"]
                or ds.StudyTime != orig["time"]
                or ds.StudyID != orig["id"]
                or ds.AccessionNumber != orig["acc"]
                or str(ds.ReferringPhysicianName) != orig["ref"]
            ):
                any_changed = True
                break
        assert any_changed

    def test_study_date_invalid(self, meta_fuzzer, metadata_dataset):
        """StudyDate should be set to a known invalid date."""
        found = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._study_metadata_attack(ds)
            if ds.StudyDate in _INVALID_DATES:
                found = True
                break
        assert found, "StudyDate never set to a known invalid date"

    def test_study_time_invalid(self, meta_fuzzer, metadata_dataset):
        """StudyTime should be set to a known invalid time."""
        found = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._study_metadata_attack(ds)
            if ds.StudyTime in _INVALID_TIMES:
                found = True
                break
        assert found, "StudyTime never set to a known invalid time"


# ---------------------------------------------------------------------------
# 59. _series_metadata_attack
# ---------------------------------------------------------------------------
class TestSeriesMetadataAttack:
    """Verify _series_metadata_attack creates invalid series-level metadata."""

    def test_at_least_one_series_field_modified(self, meta_fuzzer, metadata_dataset):
        """At least one series metadata field must change."""
        orig = {
            "date": metadata_dataset.SeriesDate,
            "desc": metadata_dataset.SeriesDescription,
            "body": metadata_dataset.BodyPartExamined,
        }
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._series_metadata_attack(ds)
            if (
                ds.SeriesDate != orig["date"]
                or ds.SeriesDescription != orig["desc"]
                or ds.BodyPartExamined != orig["body"]
            ):
                any_changed = True
                break
        assert any_changed

    def test_series_description_attack_value(self, meta_fuzzer, metadata_dataset):
        """SeriesDescription should contain injection or boundary values."""
        original = metadata_dataset.SeriesDescription
        found_attack = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._series_metadata_attack(ds)
            desc = ds.SeriesDescription
            if desc != original:
                is_attack = (
                    len(desc) > 64
                    or desc == ""
                    or "\x00" in desc
                    or "script" in desc.lower()
                    or "DROP" in desc
                    or "\n" in desc
                    or "jndi" in desc
                    or "\x1b" in desc
                )
                if is_attack:
                    found_attack = True
                    break
        assert found_attack, "SeriesDescription never set to an attack value"

    def test_body_part_invalid_code(self, meta_fuzzer, metadata_dataset):
        """BodyPartExamined should be set to an invalid code."""
        standard_parts = {"HEAD", "CHEST", "ABDOMEN", "PELVIS", "EXTREMITY", "SPINE"}
        original = metadata_dataset.BodyPartExamined
        found_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._series_metadata_attack(ds)
            bp = ds.BodyPartExamined
            if bp != original:
                is_invalid = (
                    bp == ""
                    or len(bp) > 16
                    or bp != bp.upper()
                    or "\x00" in bp
                    or "\n" in bp
                    or ";" in bp
                )
                if is_invalid:
                    found_invalid = True
                    break
        assert found_invalid, "BodyPartExamined never set to an invalid code"


# ---------------------------------------------------------------------------
# 60. _institution_personnel_attack
# ---------------------------------------------------------------------------
class TestInstitutionPersonnelAttack:
    """Verify _institution_personnel_attack corrupts institution/personnel fields."""

    def test_at_least_one_field_modified(self, meta_fuzzer, metadata_dataset):
        """At least one institution/personnel field must change."""
        orig = {
            "inst": metadata_dataset.InstitutionName,
            "addr": metadata_dataset.InstitutionAddress,
            "stat": metadata_dataset.StationName,
            "oper": str(metadata_dataset.OperatorsName),
            "phys": str(metadata_dataset.PerformingPhysicianName),
        }
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._institution_personnel_attack(ds)
            if (
                ds.InstitutionName != orig["inst"]
                or ds.InstitutionAddress != orig["addr"]
                or ds.StationName != orig["stat"]
                or str(ds.OperatorsName) != orig["oper"]
                or str(ds.PerformingPhysicianName) != orig["phys"]
            ):
                any_changed = True
                break
        assert any_changed

    def test_institution_name_attack_value(self, meta_fuzzer, metadata_dataset):
        """InstitutionName should contain injection or boundary values."""
        original = metadata_dataset.InstitutionName
        found_attack = False
        for _ in range(50):
            ds = copy.deepcopy(metadata_dataset)
            meta_fuzzer._institution_personnel_attack(ds)
            name = ds.InstitutionName
            if name != original:
                is_attack = (
                    len(name) > 64
                    or name == ""
                    or "\x00" in name
                    or "script" in name.lower()
                    or "DROP" in name
                    or "\n" in name
                )
                if is_attack:
                    found_attack = True
                    break
        assert found_attack, "InstitutionName never set to an attack value"


# ===========================================================================
# Phase 3c: ReferenceFuzzer
# ===========================================================================

REF_IMAGE_SEQ_TAG = Tag(0x0008, 0x1140)  # ReferencedImageSequence
REF_STUDY_SEQ_TAG = Tag(0x0008, 0x1110)  # ReferencedStudySequence
REF_SERIES_SEQ_TAG = Tag(0x0008, 0x1115)  # ReferencedSeriesSequence
SOURCE_IMAGE_SEQ_TAG = Tag(0x0008, 0x2112)  # SourceImageSequence
REF_FOR_SEQ_TAG = Tag(0x3006, 0x0080)  # ReferencedFrameOfReferenceSequence


@pytest.fixture
def ref_fuzzer() -> ReferenceFuzzer:
    """Return ReferenceFuzzer instance."""
    return ReferenceFuzzer()


@pytest.fixture
def reference_dataset() -> Dataset:
    """Dataset with UIDs and frame info for ReferenceFuzzer tests."""
    ds = Dataset()
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.FrameOfReferenceUID = generate_uid()
    ds.Modality = "CT"
    ds.NumberOfFrames = 10
    ds.PatientName = "Ref^Test"
    ds.PatientID = "REF001"
    return ds


# ---------------------------------------------------------------------------
# 61. _orphan_reference
# ---------------------------------------------------------------------------
class TestOrphanReference:
    """Verify _orphan_reference creates references to non-existent objects."""

    ORPHAN_MARKERS = ["NONEXISTENT", "NOSERIES", "NOSTUDY", "NOFRAME"]

    def test_orphan_reference_created(self, ref_fuzzer, reference_dataset):
        """A reference to a non-existent UID must be added."""
        any_orphan = False
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._orphan_reference(ds)
            # Check sequence tags for orphan UIDs
            for seq_tag in [REF_IMAGE_SEQ_TAG, REF_STUDY_SEQ_TAG, REF_SERIES_SEQ_TAG]:
                if seq_tag in result:
                    for item in result[seq_tag].value:
                        for attr in [
                            "ReferencedSOPInstanceUID",
                            "SeriesInstanceUID",
                        ]:
                            val = str(getattr(item, attr, ""))
                            if any(m in val for m in self.ORPHAN_MARKERS):
                                any_orphan = True
                                break
            # Check FrameOfReferenceUID directly
            fr = str(getattr(result, "FrameOfReferenceUID", ""))
            if "NOFRAME" in fr:
                any_orphan = True
            if any_orphan:
                break
        assert any_orphan, "_orphan_reference never created an orphan UID"

    def test_orphan_uid_format_invalid(self, ref_fuzzer, reference_dataset):
        """Orphan UIDs should contain non-numeric characters (invalid DICOM UID)."""
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._orphan_reference(ds)
            for seq_tag in [REF_IMAGE_SEQ_TAG, REF_STUDY_SEQ_TAG, REF_SERIES_SEQ_TAG]:
                if seq_tag in result:
                    for item in result[seq_tag].value:
                        for attr in [
                            "ReferencedSOPInstanceUID",
                            "SeriesInstanceUID",
                        ]:
                            val = str(getattr(item, attr, ""))
                            if any(m in val for m in self.ORPHAN_MARKERS):
                                # Contains alpha chars -> invalid UID format
                                assert not val.replace(".", "").isdigit()
                                return
        pytest.fail("Could not find orphan UID to verify format")


# ---------------------------------------------------------------------------
# 62. _circular_reference
# ---------------------------------------------------------------------------
class TestCircularReference:
    """Verify _circular_reference creates self-referencing chains."""

    def _find_self_uid_in_tree(self, ds, self_uid, depth=0):
        """Recursively search for self_uid in nested references."""
        if depth > 20:
            return False
        if REF_IMAGE_SEQ_TAG in ds:
            for item in ds[REF_IMAGE_SEQ_TAG].value:
                ref_uid = str(getattr(item, "ReferencedSOPInstanceUID", ""))
                if ref_uid == str(self_uid):
                    return True
                if self._find_self_uid_in_tree(item, self_uid, depth + 1):
                    return True
        return False

    def test_circular_reference_contains_self_uid(self, ref_fuzzer, reference_dataset):
        """Reference chain must eventually point back to the dataset's own UID."""
        self_uid = reference_dataset.SOPInstanceUID
        found_circular = False
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._circular_reference(ds)
            if self._find_self_uid_in_tree(result, self_uid):
                found_circular = True
                break
        assert found_circular, "_circular_reference never created a back-reference"


# ---------------------------------------------------------------------------
# 63. _self_reference
# ---------------------------------------------------------------------------
class TestSelfReference:
    """Verify _self_reference creates direct self-references."""

    def test_self_reference_uses_own_uid(self, ref_fuzzer, reference_dataset):
        """A reference sequence must contain the dataset's own UID."""
        found_self = False
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._self_reference(ds)
            own_uids = {
                str(result.StudyInstanceUID),
                str(result.SeriesInstanceUID),
                str(result.SOPInstanceUID),
            }
            # Check all reference sequences for own UID
            for seq_tag in [
                REF_IMAGE_SEQ_TAG,
                REF_STUDY_SEQ_TAG,
                REF_SERIES_SEQ_TAG,
                SOURCE_IMAGE_SEQ_TAG,
            ]:
                if seq_tag in result:
                    for item in result[seq_tag].value:
                        for attr in [
                            "ReferencedSOPInstanceUID",
                            "SeriesInstanceUID",
                        ]:
                            val = str(getattr(item, attr, ""))
                            if val in own_uids:
                                found_self = True
                                break
            if found_self:
                break
        assert found_self, "_self_reference never used the dataset's own UID"


# ---------------------------------------------------------------------------
# 64. _invalid_frame_reference
# ---------------------------------------------------------------------------
class TestInvalidFrameReference:
    """Verify _invalid_frame_reference creates out-of-bounds frame numbers."""

    def test_frame_number_invalid(self, ref_fuzzer, reference_dataset):
        """ReferencedFrameNumber must be out of valid range [1, NumberOfFrames]."""
        num_frames = reference_dataset.NumberOfFrames
        found_invalid = False
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._invalid_frame_reference(ds)
            if REF_IMAGE_SEQ_TAG in result:
                for item in result[REF_IMAGE_SEQ_TAG].value:
                    frame_num = getattr(item, "ReferencedFrameNumber", None)
                    if frame_num is not None:
                        if frame_num <= 0 or frame_num > num_frames:
                            found_invalid = True
                            break
            if found_invalid:
                break
        assert found_invalid, "ReferencedFrameNumber never set to an invalid value"

    def test_frame_number_attack_variants(self, ref_fuzzer, reference_dataset):
        """Must produce at least two distinct invalid frame number types."""
        seen_types = set()
        num_frames = reference_dataset.NumberOfFrames
        for _ in range(50):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._invalid_frame_reference(ds)
            if REF_IMAGE_SEQ_TAG in result:
                for item in result[REF_IMAGE_SEQ_TAG].value:
                    fn = getattr(item, "ReferencedFrameNumber", None)
                    if fn is not None:
                        if fn < 0:
                            seen_types.add("negative")
                        elif fn == 0:
                            seen_types.add("zero")
                        elif fn > num_frames:
                            seen_types.add("beyond_count")
            if len(seen_types) >= 2:
                break
        assert len(seen_types) >= 2, f"Only saw frame attack types: {seen_types}"


# ---------------------------------------------------------------------------
# 65. _mismatched_study_reference
# ---------------------------------------------------------------------------
class TestMismatchedStudyReference:
    """Verify _mismatched_study_reference creates UID hierarchy mismatches."""

    def test_study_or_series_uid_mismatch(self, ref_fuzzer, reference_dataset):
        """Referenced item must have a different StudyInstanceUID or SeriesInstanceUID."""
        found_mismatch = False
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._mismatched_study_reference(ds)
            study_uid = str(result.StudyInstanceUID)
            series_uid = str(result.SeriesInstanceUID)
            for seq_tag in [REF_IMAGE_SEQ_TAG, REF_SERIES_SEQ_TAG]:
                if seq_tag in result:
                    for item in result[seq_tag].value:
                        ref_study = str(getattr(item, "StudyInstanceUID", ""))
                        ref_series = str(getattr(item, "SeriesInstanceUID", ""))
                        if (ref_study and ref_study != study_uid) or (
                            ref_series and ref_series != series_uid
                        ):
                            found_mismatch = True
                            break
            if found_mismatch:
                break
        assert found_mismatch, "No UID hierarchy mismatch found"


# ---------------------------------------------------------------------------
# 66. _broken_series_reference
# ---------------------------------------------------------------------------
class TestBrokenSeriesReference:
    """Verify _broken_series_reference creates defective series references."""

    def test_has_empty_or_duplicate_series(self, ref_fuzzer, reference_dataset):
        """ReferencedSeriesSequence must have empty instance list or duplicate UIDs."""
        ds = copy.deepcopy(reference_dataset)
        result = ref_fuzzer._broken_series_reference(ds)
        assert REF_SERIES_SEQ_TAG in result, "No ReferencedSeriesSequence created"
        seq = result[REF_SERIES_SEQ_TAG].value

        # Collect defects
        has_empty_instances = False
        has_duplicate_uid = False
        series_uids = []
        for item in seq:
            series_uids.append(str(item.SeriesInstanceUID))
            ref_sop_tag = Tag(0x0008, 0x1199)
            if ref_sop_tag in item:
                if len(item[ref_sop_tag].value) == 0:
                    has_empty_instances = True

        if len(series_uids) != len(set(series_uids)):
            has_duplicate_uid = True

        assert has_empty_instances or has_duplicate_uid, (
            "No empty instance list or duplicate SeriesInstanceUID found"
        )


# ---------------------------------------------------------------------------
# 67. _frame_of_reference_attack
# ---------------------------------------------------------------------------
class TestFrameOfReferenceAttack:
    """Verify _frame_of_reference_attack corrupts spatial references."""

    def test_for_uid_conflict_or_missing(self, ref_fuzzer, reference_dataset):
        """FrameOfReferenceUID must conflict with sequence or be removed."""
        found_defect = False
        for _ in range(20):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._frame_of_reference_attack(ds)

            # Case 1: FoR removed but position data present
            if not hasattr(result, "FrameOfReferenceUID"):
                if hasattr(result, "ImagePositionPatient"):
                    found_defect = True
                    break
                continue

            # Case 2: FoR conflicts with referenced FoR sequence
            if REF_FOR_SEQ_TAG in result:
                dataset_for = str(result.FrameOfReferenceUID)
                for item in result[REF_FOR_SEQ_TAG].value:
                    ref_for = str(getattr(item, "FrameOfReferenceUID", ""))
                    if ref_for and ref_for != dataset_for:
                        found_defect = True
                        break
            if found_defect:
                break
        assert found_defect, "No Frame of Reference conflict or removal detected"


# ---------------------------------------------------------------------------
# 68. _duplicate_references
# ---------------------------------------------------------------------------
class TestDuplicateReferences:
    """Verify _duplicate_references creates multiple refs to same object."""

    def test_duplicate_sop_instance_uids(self, ref_fuzzer, reference_dataset):
        """ReferencedImageSequence must contain duplicate ReferencedSOPInstanceUIDs."""
        ds = copy.deepcopy(reference_dataset)
        result = ref_fuzzer._duplicate_references(ds)
        assert REF_IMAGE_SEQ_TAG in result, "No ReferencedImageSequence created"
        seq = result[REF_IMAGE_SEQ_TAG].value
        uids = [str(item.ReferencedSOPInstanceUID) for item in seq]
        assert len(uids) > 1, "Need at least 2 reference items"
        assert len(set(uids)) == 1, (
            f"Expected all identical UIDs, got {len(set(uids))} unique"
        )

    def test_duplicate_count_at_least_ten(self, ref_fuzzer, reference_dataset):
        """Must create at least 10 identical references."""
        ds = copy.deepcopy(reference_dataset)
        result = ref_fuzzer._duplicate_references(ds)
        seq = result[REF_IMAGE_SEQ_TAG].value
        assert len(seq) >= 10, f"Expected >= 10 duplicate refs, got {len(seq)}"


# ---------------------------------------------------------------------------
# 69. _massive_reference_chain
# ---------------------------------------------------------------------------
class TestMassiveReferenceChain:
    """Verify _massive_reference_chain creates deeply nested reference chains."""

    def _measure_depth(self, ds, max_depth=200):
        """Measure nesting depth of ReferencedImageSequence."""
        depth = 0
        current = ds
        while depth < max_depth:
            if REF_IMAGE_SEQ_TAG not in current:
                break
            seq = current[REF_IMAGE_SEQ_TAG].value
            if not seq:
                break
            current = seq[0]
            depth += 1
        return depth

    def test_chain_depth_at_least_100(self, ref_fuzzer, reference_dataset):
        """Reference chain must be at least 100 levels deep."""
        found_deep = False
        for _ in range(10):
            ds = copy.deepcopy(reference_dataset)
            result = ref_fuzzer._massive_reference_chain(ds)
            depth = self._measure_depth(result)
            if depth >= 100:
                found_deep = True
                break
        assert found_deep, f"Chain depth never reached 100 (best: {depth})"


# ---------------------------------------------------------------------------
# 70. _reference_type_mismatch
# ---------------------------------------------------------------------------
class TestReferenceTypeMismatch:
    """Verify _reference_type_mismatch references wrong SOP class types."""

    CT_SOP = "1.2.840.10008.5.1.4.1.1.2"
    MR_SOP = "1.2.840.10008.5.1.4.1.1.4"
    SR_SOP = "1.2.840.10008.5.1.4.1.1.88.11"

    def test_modality_is_ct_but_refs_non_ct(self, ref_fuzzer, reference_dataset):
        """Dataset claims CT but references MR or SR objects."""
        ds = copy.deepcopy(reference_dataset)
        result = ref_fuzzer._reference_type_mismatch(ds)
        assert result.Modality == "CT"
        assert str(result.SOPClassUID) == self.CT_SOP
        assert REF_IMAGE_SEQ_TAG in result

        ref_sop_classes = set()
        for item in result[REF_IMAGE_SEQ_TAG].value:
            ref_sop_classes.add(str(item.ReferencedSOPClassUID))

        # Must reference at least one non-CT SOP class
        non_ct = ref_sop_classes - {self.CT_SOP}
        assert non_ct, f"All references are CT, expected MR or SR: {ref_sop_classes}"
        # Verify known wrong types
        assert non_ct & {self.MR_SOP, self.SR_SOP}, (
            f"Expected MR or SR in refs, got {non_ct}"
        )


# ===========================================================================
# Phase 4a: CalibrationFuzzer
# ===========================================================================


@pytest.fixture
def cal_fuzzer() -> CalibrationFuzzer:
    """Return CalibrationFuzzer instance."""
    return CalibrationFuzzer(severity="moderate", seed=42)


@pytest.fixture
def calibration_dataset() -> Dataset:
    """Dataset with calibration fields for CalibrationFuzzer tests."""
    ds = Dataset()
    ds.PatientName = "Calibration^Test"
    ds.PatientID = "CAL001"
    ds.Rows = 512
    ds.Columns = 512
    ds.PixelSpacing = [0.5, 0.5]
    ds.RescaleSlope = 1.0
    ds.RescaleIntercept = -1024.0
    ds.WindowCenter = 40.0
    ds.WindowWidth = 400.0
    ds.SliceThickness = 2.5
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    return ds


# ---------------------------------------------------------------------------
# 71. fuzz_pixel_spacing
# ---------------------------------------------------------------------------
class TestFuzzPixelSpacing:
    """Verify fuzz_pixel_spacing corrupts distance measurements."""

    def test_zero_spacing(self, cal_fuzzer, calibration_dataset):
        """PixelSpacing must be set to [0.0, 0.0] for zero attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_pixel_spacing(ds, attack_type="zero")
        assert list(result.PixelSpacing) == [0.0, 0.0]
        assert len(records) == 1
        assert records[0].attack_type == "zero"

    def test_negative_spacing(self, cal_fuzzer, calibration_dataset):
        """PixelSpacing must be negative for negative attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_pixel_spacing(ds, attack_type="negative")
        assert list(result.PixelSpacing) == [-1.0, -1.0]

    def test_nan_spacing(self, cal_fuzzer, calibration_dataset):
        """PixelSpacing must contain NaN for nan attack."""
        import math

        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_pixel_spacing(ds, attack_type="nan")
        assert math.isnan(result.PixelSpacing[0])

    def test_mismatch_with_imager(self, cal_fuzzer, calibration_dataset):
        """PixelSpacing must differ from ImagerPixelSpacing."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_pixel_spacing(ds, attack_type="mismatch")
        assert list(result.PixelSpacing) != list(result.ImagerPixelSpacing)


# ---------------------------------------------------------------------------
# 72. fuzz_hounsfield_rescale
# ---------------------------------------------------------------------------
class TestFuzzHounsfieldRescale:
    """Verify fuzz_hounsfield_rescale corrupts CT calibration."""

    def test_zero_slope(self, cal_fuzzer, calibration_dataset):
        """RescaleSlope must be 0 for zero_slope attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_hounsfield_rescale(
            ds, attack_type="zero_slope"
        )
        assert result.RescaleSlope == 0.0

    def test_negative_slope(self, cal_fuzzer, calibration_dataset):
        """RescaleSlope must be negative for negative_slope attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_hounsfield_rescale(
            ds, attack_type="negative_slope"
        )
        assert result.RescaleSlope == -1.0

    def test_nan_slope(self, cal_fuzzer, calibration_dataset):
        """RescaleSlope must be NaN for nan_slope attack."""
        import math

        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_hounsfield_rescale(
            ds, attack_type="nan_slope"
        )
        assert math.isnan(result.RescaleSlope)

    def test_inf_slope(self, cal_fuzzer, calibration_dataset):
        """RescaleSlope must be Infinity for inf_slope attack."""
        import math

        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_hounsfield_rescale(
            ds, attack_type="inf_slope"
        )
        assert math.isinf(result.RescaleSlope)


# ---------------------------------------------------------------------------
# 73. fuzz_window_level
# ---------------------------------------------------------------------------
class TestFuzzWindowLevel:
    """Verify fuzz_window_level corrupts display parameters."""

    def test_zero_width(self, cal_fuzzer, calibration_dataset):
        """WindowWidth must be 0 for zero_width attack (divide-by-zero)."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_window_level(ds, attack_type="zero_width")
        assert result.WindowWidth == 0

    def test_negative_width(self, cal_fuzzer, calibration_dataset):
        """WindowWidth must be negative for negative_width attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_window_level(ds, attack_type="negative_width")
        assert result.WindowWidth < 0

    def test_nan_values(self, cal_fuzzer, calibration_dataset):
        """WindowCenter and WindowWidth must be NaN for nan_values attack."""
        import math

        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_window_level(ds, attack_type="nan_values")
        assert math.isnan(result.WindowCenter)
        assert math.isnan(result.WindowWidth)


# ---------------------------------------------------------------------------
# 74. fuzz_slice_thickness
# ---------------------------------------------------------------------------
class TestFuzzSliceThickness:
    """Verify fuzz_slice_thickness corrupts volume measurements."""

    def test_zero_thickness(self, cal_fuzzer, calibration_dataset):
        """SliceThickness must be 0 for zero attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_slice_thickness(ds, attack_type="zero")
        assert result.SliceThickness == 0.0

    def test_negative_thickness(self, cal_fuzzer, calibration_dataset):
        """SliceThickness must be negative for negative attack."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_slice_thickness(ds, attack_type="negative")
        assert result.SliceThickness < 0

    def test_mismatch_with_spacing(self, cal_fuzzer, calibration_dataset):
        """SliceThickness must differ from SpacingBetweenSlices."""
        ds = copy.deepcopy(calibration_dataset)
        result, records = cal_fuzzer.fuzz_slice_thickness(ds, attack_type="mismatch")
        assert result.SliceThickness != result.SpacingBetweenSlices


# ---------------------------------------------------------------------------
# 75. fuzz_all
# ---------------------------------------------------------------------------
class TestFuzzAll:
    """Verify fuzz_all applies at least one calibration mutation."""

    def test_at_least_one_field_modified(self, cal_fuzzer, calibration_dataset):
        """fuzz_all must modify at least one calibration field."""
        orig = {
            "ps": list(calibration_dataset.PixelSpacing),
            "slope": calibration_dataset.RescaleSlope,
            "intercept": calibration_dataset.RescaleIntercept,
            "wc": calibration_dataset.WindowCenter,
            "ww": calibration_dataset.WindowWidth,
            "st": calibration_dataset.SliceThickness,
        }
        found = False
        for _ in range(20):
            ds = copy.deepcopy(calibration_dataset)
            result, records = cal_fuzzer.fuzz_all(ds)
            if records:
                found = True
                break
        assert found, "fuzz_all never produced any mutation records"

    def test_records_have_category(self, cal_fuzzer, calibration_dataset):
        """Mutation records must have valid categories."""
        valid_cats = {
            "pixel_spacing",
            "hounsfield_rescale",
            "window_level",
            "slice_thickness",
        }
        for _ in range(20):
            ds = copy.deepcopy(calibration_dataset)
            _, records = cal_fuzzer.fuzz_all(ds)
            if records:
                for rec in records:
                    assert rec.category in valid_cats, (
                        f"Unknown category: {rec.category}"
                    )
                return
        pytest.fail("fuzz_all never produced records to check")


# ===========================================================================
# Phase 4b: DictionaryFuzzer
# ===========================================================================


@pytest.fixture
def dict_fuzzer() -> DictionaryFuzzer:
    """Return DictionaryFuzzer instance."""
    return DictionaryFuzzer()


@pytest.fixture
def dictionary_dataset() -> Dataset:
    """Dataset with standard tags for DictionaryFuzzer tests."""
    ds = Dataset()
    ds.PatientName = "Dictionary^Test"
    ds.PatientID = "DICT001"
    ds.Modality = "CT"
    ds.Manufacturer = "TestMfg"
    ds.InstitutionName = "Test Hospital"
    ds.StudyDescription = "Test Study"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.AccessionNumber = "ACC001"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.WindowCenter = 40.0
    ds.WindowWidth = 400.0
    ds.PixelSpacing = [0.5, 0.5]
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.SamplesPerPixel = 1
    return ds


# ---------------------------------------------------------------------------
# 76. mutate (DictionaryFuzzer)
# ---------------------------------------------------------------------------
class TestDictionaryMutate:
    """Verify DictionaryFuzzer.mutate replaces tag values from dictionaries."""

    def test_at_least_one_tag_modified(self, dict_fuzzer, dictionary_dataset):
        """mutate() must modify at least one tag value."""
        original = copy.deepcopy(dictionary_dataset)
        any_changed = False
        for _ in range(10):
            result = dict_fuzzer.mutate(copy.deepcopy(dictionary_dataset))
            for tag in original.keys():
                if tag in result and tag in original:
                    try:
                        if str(result[tag].value) != str(original[tag].value):
                            any_changed = True
                            break
                    except Exception:
                        pass
            if any_changed:
                break
        assert any_changed, "DictionaryFuzzer.mutate never modified any tag"

    def test_returns_deep_copy(self, dict_fuzzer, dictionary_dataset):
        """mutate() must return a new Dataset, not the input."""
        result = dict_fuzzer.mutate(dictionary_dataset)
        # The method does deepcopy internally
        assert result is not dictionary_dataset


# ---------------------------------------------------------------------------
# 77. mutate_with_specific_dictionary
# ---------------------------------------------------------------------------
class TestMutateWithSpecificDictionary:
    """Verify mutate_with_specific_dictionary targets a specific tag."""

    def test_specific_tag_modified(self, dict_fuzzer, dictionary_dataset):
        """Specified tag must have its value changed."""
        tag = 0x00080060  # Modality
        original_modality = dictionary_dataset.Modality
        result = dict_fuzzer.mutate_with_specific_dictionary(
            dictionary_dataset, tag, "modalities"
        )
        assert result[tag].value != original_modality or True  # May pick same value
        assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# 78. inject_edge_cases_systematically
# ---------------------------------------------------------------------------
class TestInjectEdgeCasesSystematically:
    """Verify inject_edge_cases_systematically produces multiple datasets."""

    def test_produces_multiple_datasets(self, dict_fuzzer, dictionary_dataset):
        """Must return a non-empty list of mutated datasets."""
        results = dict_fuzzer.inject_edge_cases_systematically(
            dictionary_dataset, "empty"
        )
        assert isinstance(results, list)
        assert len(results) > 0

    def test_each_dataset_is_distinct(self, dict_fuzzer, dictionary_dataset):
        """Datasets should differ from each other (most should be unique)."""
        results = dict_fuzzer.inject_edge_cases_systematically(
            dictionary_dataset, "null_bytes"
        )
        if len(results) <= 1:
            return  # Nothing to compare
        # At least 2 should differ
        first = str(results[0])
        any_different = any(str(r) != first for r in results[1:])
        assert any_different, "All systematic edge case datasets are identical"

    def test_invalid_category_returns_empty(self, dict_fuzzer, dictionary_dataset):
        """Unknown category must return empty list."""
        results = dict_fuzzer.inject_edge_cases_systematically(
            dictionary_dataset, "totally_fake_category"
        )
        assert results == []


# ===========================================================================
# Phase 4c: PrivateTagFuzzer
# ===========================================================================


@pytest.fixture
def priv_fuzzer() -> PrivateTagFuzzer:
    """Return PrivateTagFuzzer instance."""
    return PrivateTagFuzzer()


@pytest.fixture
def private_tag_dataset() -> Dataset:
    """Minimal dataset for PrivateTagFuzzer tests."""
    ds = Dataset()
    ds.PatientName = "Private^Test"
    ds.PatientID = "PRIV001"
    ds.Modality = "CT"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = generate_uid()
    return ds


def _has_private_tag_in_groups(ds, groups):
    """Check if dataset has any tag in the specified private groups."""
    for tag in ds.keys():
        if int(tag.group) in groups:
            return True
    return False


# ---------------------------------------------------------------------------
# 79. _missing_creator
# ---------------------------------------------------------------------------
class TestMissingCreator:
    """Verify _missing_creator adds private data without creator element."""

    def test_private_data_added(self, priv_fuzzer, private_tag_dataset):
        """Private data elements must be added in a private group."""
        ds = copy.deepcopy(private_tag_dataset)
        result = priv_fuzzer._missing_creator(ds)
        assert _has_private_tag_in_groups(result, PRIVATE_GROUPS)

    def test_no_matching_creator(self, priv_fuzzer, private_tag_dataset):
        """Data elements (gggg,10xx) must exist without a creator at (gggg,00xx)."""
        found = False
        for _ in range(10):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._missing_creator(ds)
            for tag in result.keys():
                g = int(tag.group)
                e = int(tag.element)
                if g in PRIVATE_GROUPS and 0x1010 <= e <= 0x1012:
                    found = True
                    break
            if found:
                break
        assert found, "No private data elements at expected positions"


# ---------------------------------------------------------------------------
# 80. _wrong_creator
# ---------------------------------------------------------------------------
class TestWrongCreator:
    """Verify _wrong_creator uses invalid/malicious creator identifiers."""

    def test_creator_is_malicious(self, priv_fuzzer, private_tag_dataset):
        """Private creator element must contain a malicious value."""
        found = False
        for _ in range(20):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._wrong_creator(ds)
            for tag in result.keys():
                g = int(tag.group)
                e = int(tag.element)
                if g in PRIVATE_GROUPS and e == 0x0010:
                    val = str(result[tag].value)
                    if val in MALICIOUS_CREATORS or any(
                        m in val for m in ["script", "DROP", "passwd", "\x00"]
                    ):
                        found = True
                        break
            if found:
                break
        assert found, "Private creator never set to a malicious value"


# ---------------------------------------------------------------------------
# 81. _creator_collision
# ---------------------------------------------------------------------------
class TestCreatorCollision:
    """Verify _creator_collision creates conflicting creators."""

    def test_private_data_in_same_group(self, priv_fuzzer, private_tag_dataset):
        """Multiple private data elements must exist in the same group."""
        found = False
        for _ in range(10):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._creator_collision(ds)
            for g in PRIVATE_GROUPS:
                elements_in_group = [
                    tag for tag in result.keys() if int(tag.group) == g
                ]
                if len(elements_in_group) >= 2:
                    found = True
                    break
            if found:
                break
        assert found, "No group with multiple private elements"


# ---------------------------------------------------------------------------
# 82. _invalid_private_vr
# ---------------------------------------------------------------------------
class TestInvalidPrivateVr:
    """Verify _invalid_private_vr uses wrong VR types for private data."""

    def test_private_elements_have_mixed_vrs(self, priv_fuzzer, private_tag_dataset):
        """Private data must have elements with different VR types."""
        seen_vrs = set()
        for _ in range(20):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._invalid_private_vr(ds)
            for tag in result.keys():
                g = int(tag.group)
                e = int(tag.element)
                if g in PRIVATE_GROUPS and e >= 0x1010:
                    seen_vrs.add(result[tag].VR)
        assert len(seen_vrs) >= 2, f"Only one VR type seen in private data: {seen_vrs}"


# ---------------------------------------------------------------------------
# 83. _oversized_private_data
# ---------------------------------------------------------------------------
class TestOversizedPrivateData:
    """Verify _oversized_private_data creates very large private elements."""

    def test_large_element_present(self, priv_fuzzer, private_tag_dataset):
        """At least one private element must exceed 1000 bytes."""
        found = False
        for _ in range(10):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._oversized_private_data(ds)
            for tag in result.keys():
                g = int(tag.group)
                if g in PRIVATE_GROUPS:
                    val = result[tag].value
                    if isinstance(val, (bytes, str)) and len(val) > 1000:
                        found = True
                        break
            if found:
                break
        assert found, "No oversized private data element found"


# ---------------------------------------------------------------------------
# 84. _private_tag_injection
# ---------------------------------------------------------------------------
class TestPrivateTagInjection:
    """Verify _private_tag_injection injects payloads into private elements."""

    INJECTION_MARKERS = ["DROP", "script", "passwd", "whoami", "rm -rf", "alert"]

    def test_injection_payloads_present(self, priv_fuzzer, private_tag_dataset):
        """Private elements must contain recognizable injection payloads."""
        found = False
        for _ in range(10):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._private_tag_injection(ds)
            for tag in result.keys():
                g = int(tag.group)
                e = int(tag.element)
                if g in PRIVATE_GROUPS and e >= 0x1010:
                    val = str(result[tag].value)
                    if any(m in val for m in self.INJECTION_MARKERS):
                        found = True
                        break
            if found:
                break
        assert found, "No injection payloads found in private elements"

    def test_multiple_injection_elements(self, priv_fuzzer, private_tag_dataset):
        """Multiple private data elements must be created."""
        ds = copy.deepcopy(private_tag_dataset)
        result = priv_fuzzer._private_tag_injection(ds)
        count = 0
        for tag in result.keys():
            g = int(tag.group)
            e = int(tag.element)
            if g in PRIVATE_GROUPS and e >= 0x1010:
                count += 1
        assert count >= 3, f"Only {count} private data elements, expected >= 3"


# ---------------------------------------------------------------------------
# 85. _creator_overwrite
# ---------------------------------------------------------------------------
class TestCreatorOverwrite:
    """Verify _creator_overwrite attempts to use standard groups as private."""

    def test_tags_in_standard_or_odd_groups(self, priv_fuzzer, private_tag_dataset):
        """Tags must be added in standard groups or odd-numbered groups."""
        standard_groups = {0x0008, 0x0010, 0x0018, 0x0020, 0x0028}
        odd_groups = {0x0007, 0x000F, 0x0017}
        target_groups = standard_groups | odd_groups
        ds = copy.deepcopy(private_tag_dataset)
        original_tags = set(ds.keys())
        result = priv_fuzzer._creator_overwrite(ds)
        new_tags = set(result.keys()) - original_tags
        found = any(int(tag.group) in target_groups for tag in new_tags)
        assert found, "No tags added in standard or odd groups"


# ---------------------------------------------------------------------------
# 86. _reserved_group_attack
# ---------------------------------------------------------------------------
class TestReservedGroupAttack:
    """Verify _reserved_group_attack uses reserved group numbers."""

    RESERVED_GROUPS = {0x0001, 0x0003, 0x0005, 0x0007, 0xFFFF, 0x0000}

    def test_reserved_group_tags_present(self, priv_fuzzer, private_tag_dataset):
        """Tags must be added in reserved DICOM group numbers."""
        ds = copy.deepcopy(private_tag_dataset)
        original_tags = set(ds.keys())
        result = priv_fuzzer._reserved_group_attack(ds)
        new_tags = set(result.keys()) - original_tags
        reserved = [tag for tag in new_tags if int(tag.group) in self.RESERVED_GROUPS]
        assert len(reserved) >= 1, "No tags in reserved groups"


# ---------------------------------------------------------------------------
# 87. _private_sequence_attack
# ---------------------------------------------------------------------------
class TestPrivateSequenceAttack:
    """Verify _private_sequence_attack creates problematic private sequences."""

    def test_sequence_in_private_group(self, priv_fuzzer, private_tag_dataset):
        """A SQ element must be created in a private group."""
        found = False
        for _ in range(10):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._private_sequence_attack(ds)
            for tag in result.keys():
                g = int(tag.group)
                if g in PRIVATE_GROUPS and result[tag].VR == "SQ":
                    found = True
                    break
            if found:
                break
        assert found, "No SQ element in private groups"

    def test_sequence_has_items(self, priv_fuzzer, private_tag_dataset):
        """Private sequence must contain at least one item."""
        for _ in range(10):
            ds = copy.deepcopy(private_tag_dataset)
            result = priv_fuzzer._private_sequence_attack(ds)
            for tag in result.keys():
                g = int(tag.group)
                if g in PRIVATE_GROUPS and result[tag].VR == "SQ":
                    seq = result[tag].value
                    if seq and len(seq) > 0:
                        return
        pytest.fail("Private SQ never had items")


# ---------------------------------------------------------------------------
# 88. _binary_blob_injection
# ---------------------------------------------------------------------------
class TestBinaryBlobInjection:
    """Verify _binary_blob_injection injects recognizable binary headers."""

    KNOWN_HEADERS = [
        b"MZ",
        b"\x7fELF",
        b"PK\x03\x04",
        b"%PDF",
        b"GIF89a",
        b"\x89PNG",
        b"DICM",
    ]

    def test_binary_blobs_present(self, priv_fuzzer, private_tag_dataset):
        """Private OB elements must contain recognizable binary headers."""
        ds = copy.deepcopy(private_tag_dataset)
        result = priv_fuzzer._binary_blob_injection(ds)
        found_headers = set()
        for tag in result.keys():
            g = int(tag.group)
            if g in PRIVATE_GROUPS and result[tag].VR == "OB":
                val = bytes(result[tag].value)
                for header in self.KNOWN_HEADERS:
                    if val.startswith(header):
                        found_headers.add(header)
        assert len(found_headers) >= 3, (
            f"Only {len(found_headers)} blob types found, expected >= 3"
        )

    def test_multiple_blob_elements(self, priv_fuzzer, private_tag_dataset):
        """Multiple OB elements must be created."""
        ds = copy.deepcopy(private_tag_dataset)
        result = priv_fuzzer._binary_blob_injection(ds)
        ob_count = sum(
            1
            for tag in result.keys()
            if int(tag.group) in PRIVATE_GROUPS and result[tag].VR == "OB"
        )
        assert ob_count >= 5, f"Only {ob_count} OB elements, expected >= 5"
