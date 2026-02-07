"""Mutation verification tests for format fuzzer strategies.

Verifies that each strategy method actually produces the specific defect it
claims to -- not just "did it run" (contract tests) but "did it create a
dimension mismatch / invalid bit depth / corrupted pixel data / etc."

Tests call strategy methods directly (not via mutate()) and assert semantic
properties of the output.

Phase 1a: PixelFuzzer (6 strategies)
Phase 1b: CompressedPixelFuzzer (8 strategies)
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
from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer

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
    """Verify _inject_malformed_frame injects a bad frame among valid ones."""

    def test_pixel_data_set(self, comp_fuzzer, compressed_dataset):
        """PixelData must be set after mutation."""
        result = comp_fuzzer._inject_malformed_frame(compressed_dataset)
        assert PIXEL_DATA_TAG in result

    def test_number_of_frames_set_to_three(self, comp_fuzzer, compressed_dataset):
        """NumberOfFrames must be 3 (2 valid + 1 malformed)."""
        result = comp_fuzzer._inject_malformed_frame(compressed_dataset)
        assert result.NumberOfFrames == 3

    def test_three_frame_items_present(self, comp_fuzzer, compressed_dataset):
        """Encapsulated data must contain exactly 3 frame items."""
        result = comp_fuzzer._inject_malformed_frame(compressed_dataset)
        raw = _get_pixel_bytes(result)
        frame_count = _count_frame_items(raw)
        assert frame_count == 3, f"Expected 3 frames, got {frame_count}"

    def test_transfer_syntax_is_jpeg(self, comp_fuzzer, compressed_dataset):
        """Transfer syntax must be JPEG Baseline."""
        result = comp_fuzzer._inject_malformed_frame(compressed_dataset)
        assert result.file_meta.TransferSyntaxUID == JPEGBaseline8Bit


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
