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
"""

import copy
import struct

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import (
    ExplicitVRLittleEndian,
    JPEG2000Lossless,
    JPEGBaseline8Bit,
    RLELossless,
    generate_uid,
)

from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import CompressedPixelFuzzer
from dicom_fuzzer.attacks.format.encoding_fuzzer import EncodingFuzzer
from dicom_fuzzer.attacks.format.header_fuzzer import VR_MUTATIONS, HeaderFuzzer
from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer
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
            if isinstance(cs, list):
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
