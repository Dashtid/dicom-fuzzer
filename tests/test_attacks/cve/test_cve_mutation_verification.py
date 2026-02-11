# ruff: noqa: N801
"""CVE Mutation Verification Tests.

Verifies that each CVE mutation function produces output with the claimed defect.
Calls mutation functions directly and asserts byte-level properties.

Phase 1a: Memory Corruption CVEs (10 functions, 33 variants)
Phase 1b: Protocol/Parser CVEs (12 functions, 47 variants)
"""

from __future__ import annotations

import struct

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.cve.payloads.memory import (
    mutate_cve_2024_1453,
    mutate_cve_2024_22100,
    mutate_cve_2024_25578,
    mutate_cve_2024_28877,
    mutate_cve_2024_47796,
    mutate_cve_2024_52333,
    mutate_cve_2025_5307,
    mutate_cve_2025_5943,
    mutate_cve_2025_35975,
    mutate_cve_2025_36521,
)
from dicom_fuzzer.cve.payloads.protocol import (
    mutate_cve_2019_11687,
    mutate_cve_2020_29625,
    mutate_cve_2021_41946,
    mutate_cve_2022_24193,
    mutate_cve_2024_33606,
    mutate_cve_2025_1001,
    mutate_cve_2025_1002,
    mutate_cve_2025_11266,
    mutate_cve_2025_27578,
    mutate_cve_2025_31946,
    mutate_cve_2025_53618,
    mutate_cve_2025_53619,
)

# =============================================================================
# Tag byte patterns (little-endian group, element)
# =============================================================================
ROWS_TAG = b"\x28\x00\x10\x00"
COLS_TAG = b"\x28\x00\x11\x00"
BITS_ALLOC_TAG = b"\x28\x00\x00\x01"
BITS_STORED_TAG = b"\x28\x00\x01\x01"
HIGH_BIT_TAG = b"\x28\x00\x02\x01"
SAMPLES_TAG = b"\x28\x00\x02\x00"
PIXEL_DATA_TAG = b"\xe0\x7f\x10\x00"
PATIENT_NAME_TAG = b"\x10\x00\x10\x00"
PRIVATE_CREATOR_TAG = b"\x09\x00\x10\x00"
ITEM_START = b"\xfe\xff\x00\xe0"
SEQ_DELIM = b"\xfe\xff\xdd\xe0"


# =============================================================================
# Helpers
# =============================================================================
def _get_variant(variants: list[tuple[str, bytes]], name: str) -> bytes:
    """Extract variant data by name from mutation results."""
    for vname, vdata in variants:
        if vname == name:
            return vdata
    available = [v[0] for v in variants]
    raise ValueError(f"Variant '{name}' not found. Available: {available}")


def _read_tag_uint16(data: bytes, tag: bytes) -> int | None:
    """Find a DICOM tag and read the uint16 at offset+6 from tag start."""
    idx = data.find(tag)
    if idx == -1 or idx + 8 > len(data):
        return None
    return struct.unpack_from("<H", data, idx + 6)[0]


def _read_tag_uint32(data: bytes, tag: bytes, value_offset: int = 8) -> int | None:
    """Find a DICOM tag and read uint32 at given offset from tag start."""
    idx = data.find(tag)
    if idx == -1 or idx + value_offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, idx + value_offset)[0]


# =============================================================================
# Fixture
# =============================================================================
@pytest.fixture
def template_bytes(tmp_path) -> bytes:
    """Create a real DICOM template for CVE mutations."""
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "CVE^Template"
    ds.PatientID = "CVE001"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Manufacturer = "TestManufacturer"
    ds.InstitutionAddress = "http://example.com"
    ds.StationName = "STATION01"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    path = tmp_path / "template.dcm"
    ds.save_as(path, enforce_file_format=True)
    return path.read_bytes()


# =============================================================================
# Phase 1a: Memory Corruption CVEs
# =============================================================================
class TestCVE2025_5943:
    """CVE-2025-5943: MicroDicom heap buffer overflow via pixel dimensions."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_5943(template_bytes)) == 2

    @pytest.mark.parametrize(
        ("variant", "rows", "cols"),
        [
            ("heap_overflow", 0xFFFF, 0xFFFF),
            ("integer_overflow", 0x8000, 0x8000),
        ],
    )
    def test_dimensions(self, template_bytes, variant, rows, cols):
        data = _get_variant(mutate_cve_2025_5943(template_bytes), variant)
        assert _read_tag_uint16(data, ROWS_TAG) == rows
        assert _read_tag_uint16(data, COLS_TAG) == cols

    def test_heap_overflow_bits_allocated(self, template_bytes):
        data = _get_variant(mutate_cve_2025_5943(template_bytes), "heap_overflow")
        assert _read_tag_uint16(data, BITS_ALLOC_TAG) == 16


class TestCVE2025_35975:
    """CVE-2025-35975: MicroDicom OOB write via dimension mismatch."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_35975(template_bytes)) == 4

    @pytest.mark.parametrize(
        ("variant", "rows", "cols", "bits"),
        [
            ("near_max_cols", 1, 0xFFFE, 16),
            ("near_max_rows", 0xFFFE, 1, 16),
            ("large_32bit", 256, 256, 32),
            ("unusual_24bit", 512, 512, 24),
        ],
    )
    def test_dimensions(self, template_bytes, variant, rows, cols, bits):
        data = _get_variant(mutate_cve_2025_35975(template_bytes), variant)
        assert _read_tag_uint16(data, ROWS_TAG) == rows
        assert _read_tag_uint16(data, COLS_TAG) == cols
        assert _read_tag_uint16(data, BITS_ALLOC_TAG) == bits

    @pytest.mark.parametrize(
        "variant",
        ["near_max_cols", "near_max_rows", "large_32bit", "unusual_24bit"],
    )
    def test_pixel_data_length_64(self, template_bytes, variant):
        data = _get_variant(mutate_cve_2025_35975(template_bytes), variant)
        assert _read_tag_uint32(data, PIXEL_DATA_TAG) == 64


class TestCVE2025_36521:
    """CVE-2025-36521: MicroDicom OOB read via dimension/buffer mismatch."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_36521(template_bytes)) == 5

    @pytest.mark.parametrize(
        ("variant", "rows", "cols", "bits", "samples"),
        [
            ("max_rows_min_cols", 0xFFFF, 2, 16, 1),
            ("min_rows_max_cols", 2, 0xFFFF, 16, 1),
            ("large_rgb", 4096, 4096, 8, 3),
            ("very_large_mono", 8192, 8192, 16, 1),
            ("32bit_allocation", 1024, 1024, 32, 1),
        ],
    )
    def test_dimensions(self, template_bytes, variant, rows, cols, bits, samples):
        data = _get_variant(mutate_cve_2025_36521(template_bytes), variant)
        assert _read_tag_uint16(data, ROWS_TAG) == rows
        assert _read_tag_uint16(data, COLS_TAG) == cols
        assert _read_tag_uint16(data, BITS_ALLOC_TAG) == bits
        assert _read_tag_uint16(data, SAMPLES_TAG) == samples


class TestCVE2025_5307:
    """CVE-2025-5307: Sante DICOM Viewer Pro OOB read."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_5307(template_bytes)) == 4

    @pytest.mark.parametrize(
        ("variant", "rows", "cols", "samples", "bits"),
        [
            ("large_rgb_16bit", 4096, 4096, 3, 16),
            ("wide_single_row", 8192, 1, 1, 16),
            ("tall_single_col", 1, 8192, 1, 16),
            ("rgba_8bit", 2048, 2048, 4, 8),
        ],
    )
    def test_dimensions(self, template_bytes, variant, rows, cols, samples, bits):
        data = _get_variant(mutate_cve_2025_5307(template_bytes), variant)
        assert _read_tag_uint16(data, ROWS_TAG) == rows
        assert _read_tag_uint16(data, COLS_TAG) == cols
        assert _read_tag_uint16(data, SAMPLES_TAG) == samples
        assert _read_tag_uint16(data, BITS_ALLOC_TAG) == bits


class TestCVE2024_22100:
    """CVE-2024-22100: MicroDicom heap overflow via private creator."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_22100(template_bytes)) == 1

    def test_private_creator_injected(self, template_bytes):
        data = _get_variant(
            mutate_cve_2024_22100(template_bytes),
            "heap_overflow_private_elements",
        )
        idx = data.find(PRIVATE_CREATOR_TAG)
        assert idx != -1
        # Injected element: tag + "LO" + 0xFFFF length
        assert data[idx + 4 : idx + 6] == b"LO"
        length = struct.unpack_from("<H", data, idx + 6)[0]
        assert length == 0xFFFF


class TestCVE2024_25578:
    """CVE-2024-25578: MicroDicom OOB write via oversized VR lengths."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_25578(template_bytes)) == 1

    def test_contains_oversized_length(self, template_bytes):
        data = _get_variant(
            mutate_cve_2024_25578(template_bytes),
            "oob_write_oversized_length",
        )
        file_size = len(template_bytes)
        doubled = struct.pack("<I", file_size * 2)
        assert doubled in data

    def test_output_modified(self, template_bytes):
        data = _get_variant(
            mutate_cve_2024_25578(template_bytes),
            "oob_write_oversized_length",
        )
        assert data != template_bytes


class TestCVE2024_28877:
    """CVE-2024-28877: MicroDicom stack overflow via deep nesting."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_28877(template_bytes)) == 1

    def test_deep_nesting(self, template_bytes):
        data = _get_variant(
            mutate_cve_2024_28877(template_bytes),
            "stack_overflow_deep_nesting",
        )
        nesting_count = data.count(ITEM_START)
        assert nesting_count >= 500

    def test_patient_name_oversized(self, template_bytes):
        data = _get_variant(
            mutate_cve_2024_28877(template_bytes),
            "stack_overflow_deep_nesting",
        )
        idx = data.find(PATIENT_NAME_TAG)
        assert idx != -1
        length = struct.unpack_from("<H", data, idx + 6)[0]
        assert length == 4096


class TestCVE2024_1453:
    """CVE-2024-1453: Sante DICOM Viewer OOB read via oversized tag lengths."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_1453(template_bytes)) == 5

    @pytest.mark.parametrize(
        ("variant", "tag"),
        [
            ("oob_read_modality", b"\x08\x00\x60\x00"),
            ("oob_read_manufacturer", b"\x08\x00\x70\x00"),
            ("oob_read_patient_name", PATIENT_NAME_TAG),
            ("oob_read_patient_id", b"\x10\x00\x20\x00"),
            ("oob_read_study_uid", b"\x20\x00\x0d\x00"),
        ],
    )
    def test_oversized_length(self, template_bytes, variant, tag):
        """Tag length exceeds remaining bytes -- OOB read trigger."""
        data = _get_variant(mutate_cve_2024_1453(template_bytes), variant)
        idx = data.find(tag)
        assert idx != -1
        length = struct.unpack_from("<H", data, idx + 6)[0]
        remaining = len(data) - idx - 8
        assert length > remaining


class TestCVE2024_47796:
    """CVE-2024-47796: DCMTK LUT overflow."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_47796(template_bytes)) == 5

    @pytest.mark.parametrize(
        ("variant", "rows", "cols", "high_bit", "bits_stored"),
        [
            ("lut_overflow_max_rows", 0xFFFF, 1, 15, 16),
            ("lut_overflow_max_cols", 1, 0xFFFF, 15, 16),
            ("lut_overflow_many_frames", 256, 256, 15, 16),
            ("lut_overflow_32bit_large", 512, 512, 31, 32),
            ("lut_overflow_12bit_unusual", 1024, 1024, 11, 12),
        ],
    )
    def test_tag_values(
        self, template_bytes, variant, rows, cols, high_bit, bits_stored
    ):
        data = _get_variant(mutate_cve_2024_47796(template_bytes), variant)
        assert _read_tag_uint16(data, ROWS_TAG) == rows
        assert _read_tag_uint16(data, COLS_TAG) == cols
        assert _read_tag_uint16(data, HIGH_BIT_TAG) == high_bit
        assert _read_tag_uint16(data, BITS_STORED_TAG) == bits_stored


class TestCVE2024_52333:
    """CVE-2024-52333: DCMTK determineMinMax overflow."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_52333(template_bytes)) == 5

    @pytest.mark.parametrize(
        ("variant", "rows", "cols", "samples", "bits"),
        [
            ("minmax_overflow_near_max_rows", 0xFFFE, 2, 1, 16),
            ("minmax_overflow_near_max_cols", 2, 0xFFFE, 1, 16),
            ("minmax_overflow_rgb_planar_large", 1000, 1000, 3, 8),
            ("minmax_overflow_large_mono_8bit", 2048, 2048, 1, 8),
            ("minmax_overflow_rgba_16bit", 256, 256, 4, 16),
        ],
    )
    def test_tag_values(self, template_bytes, variant, rows, cols, samples, bits):
        data = _get_variant(mutate_cve_2024_52333(template_bytes), variant)
        assert _read_tag_uint16(data, ROWS_TAG) == rows
        assert _read_tag_uint16(data, COLS_TAG) == cols
        assert _read_tag_uint16(data, SAMPLES_TAG) == samples
        assert _read_tag_uint16(data, BITS_ALLOC_TAG) == bits


# =============================================================================
# Phase 1b: Protocol/Parser CVEs
# =============================================================================
class TestCVE2025_11266:
    """CVE-2025-11266: GDCM integer underflow in encapsulated PixelData."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_11266(template_bytes)) == 2

    def test_integer_underflow_trigger(self, template_bytes):
        data = _get_variant(mutate_cve_2025_11266(template_bytes), "integer_underflow")
        assert struct.pack("<I", 0xFFFFFFFF) in data

    def test_fragment_count_mismatch_bot(self, template_bytes):
        data = _get_variant(
            mutate_cve_2025_11266(template_bytes), "fragment_count_mismatch"
        )
        # BOT claims 10 fragments (40 bytes = 10 * 4-byte offsets)
        bot_length = struct.pack("<I", 40)
        assert bot_length in data


class TestCVE2025_53618:
    """CVE-2025-53618: GDCM JPEG Huffman table OOB read."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_53618(template_bytes)) == 1

    def test_jpeg_markers_present(self, template_bytes):
        data = _get_variant(
            mutate_cve_2025_53618(template_bytes), "jpeg_huffman_oob_read"
        )
        assert b"\xff\xd8" in data  # SOI
        assert b"\xff\xc4" in data  # DHT

    def test_dht_length_too_short(self, template_bytes):
        data = _get_variant(
            mutate_cve_2025_53618(template_bytes), "jpeg_huffman_oob_read"
        )
        dht_idx = data.find(b"\xff\xc4")
        assert dht_idx != -1
        length = struct.unpack_from(">H", data, dht_idx + 2)[0]
        assert length == 5


class TestCVE2025_53619:
    """CVE-2025-53619: GDCM JPEG stream truncation OOB read."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_53619(template_bytes)) == 1

    def test_jpeg_truncated_no_eoi(self, template_bytes):
        data = _get_variant(
            mutate_cve_2025_53619(template_bytes), "jpeg_truncated_stream"
        )
        # SOI and SOS present
        soi_idx = data.find(b"\xff\xd8")
        assert soi_idx != -1
        assert b"\xff\xda" in data  # SOS present
        # JPEG data within encapsulated frame has no EOI
        delim_idx = data.find(SEQ_DELIM, soi_idx)
        jpeg_data = data[soi_idx:delim_idx] if delim_idx != -1 else data[soi_idx:]
        assert b"\xff\xd9" not in jpeg_data


class TestCVE2025_1001:
    """CVE-2025-1001: RadiAnt certificate validation bypass.

    When InstitutionAddress tag exists, mutation corrupts its length field
    to match the URL payload size (OOB read trigger).
    """

    INSTITUTION_ADDR_TAG = b"\x08\x00\x81\x00"

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_1001(template_bytes)) == 5

    @pytest.mark.parametrize(
        ("variant", "payload_len"),
        [
            ("cert_bypass_attacker_domain", 43),
            ("cert_bypass_localhost_bypass", 42),
            ("cert_bypass_unc_path", 29),
            ("cert_bypass_subdomain_spoof", 56),
            ("cert_bypass_url_userinfo", 47),
        ],
    )
    def test_length_corrupted(self, template_bytes, variant, payload_len):
        data = _get_variant(mutate_cve_2025_1001(template_bytes), variant)
        length = _read_tag_uint16(data, self.INSTITUTION_ADDR_TAG)
        assert length == payload_len


class TestCVE2025_1002:
    """CVE-2025-1002: MicroDicom certificate verification bypass."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_1002(template_bytes)) == 7

    @pytest.mark.parametrize(
        ("variant", "payload"),
        [
            ("mitm_attacker_wado", b"attacker.example.com/wado"),
            ("mitm_self_signed", b"self-signed.badssl.com"),
            ("mitm_expired_cert", b"expired.badssl.com"),
            ("mitm_wrong_host", b"wrong.host.badssl.com"),
            ("mitm_untrusted_root", b"untrusted-root.badssl.com"),
            ("mitm_localhost_ipv4", b"127.0.0.1:8080"),
            ("mitm_localhost_ipv6", b"[::1]:8080"),
        ],
    )
    def test_payload_present(self, template_bytes, variant, payload):
        data = _get_variant(mutate_cve_2025_1002(template_bytes), variant)
        assert payload in data


class TestCVE2025_27578:
    """CVE-2025-27578: OsiriX use-after-free via DICOM upload."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_27578(template_bytes)) == 1

    def test_uaf_sequence_structure(self, template_bytes):
        data = _get_variant(
            mutate_cve_2025_27578(template_bytes), "use_after_free_remote"
        )
        sq_tag = b"\x08\x00\x15\x11"
        assert sq_tag in data
        assert SEQ_DELIM in data


class TestCVE2025_31946:
    """CVE-2025-31946: OsiriX local use-after-free via import.

    When PixelData exists, sets its length to 0xFFFFFFFF (undefined length).
    """

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2025_31946(template_bytes)) == 1

    def test_pixel_data_undefined_length(self, template_bytes):
        data = _get_variant(
            mutate_cve_2025_31946(template_bytes), "use_after_free_local"
        )
        # PixelData length field set to 0xFFFFFFFF (undefined)
        assert _read_tag_uint32(data, PIXEL_DATA_TAG) == 0xFFFFFFFF


class TestCVE2024_33606:
    """CVE-2024-33606: MicroDicom URL scheme security bypass."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2024_33606(template_bytes)) == 10

    @pytest.mark.parametrize(
        ("variant", "payload"),
        [
            ("url_scheme_file_windows", b"file:///C:/Windows/"),
            ("url_scheme_file_unix", b"file://localhost/etc/"),
            ("url_scheme_unc_path", b"\\\\attacker.com\\"),
            ("url_scheme_traversal", b"../../etc/passwd"),
            ("url_scheme_javascript", b"javascript:"),
            ("url_scheme_data_uri", b"data:text/html"),
            ("url_scheme_proc_environ", b"/proc/self/environ"),
            ("url_scheme_dict_scheme", b"dict://"),
            ("url_scheme_gopher_scheme", b"gopher://"),
            ("url_scheme_ldap_scheme", b"ldap://"),
        ],
    )
    def test_payload_present(self, template_bytes, variant, payload):
        data = _get_variant(mutate_cve_2024_33606(template_bytes), variant)
        assert payload in data


class TestCVE2022_24193:
    """CVE-2022-24193: OsiriX DoS via deep sequence nesting."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2022_24193(template_bytes)) == 3

    @pytest.mark.parametrize(
        ("variant", "min_depth"),
        [
            ("deep_nesting_depth_100", 100),
            ("deep_nesting_depth_250", 250),
            ("deep_nesting_depth_500", 500),
        ],
    )
    def test_nesting_depth(self, template_bytes, variant, min_depth):
        data = _get_variant(mutate_cve_2022_24193(template_bytes), variant)
        nesting_count = data.count(ITEM_START)
        assert nesting_count >= min_depth


class TestCVE2021_41946:
    """CVE-2021-41946: ClearCanvas path traversal."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2021_41946(template_bytes)) == 7

    @pytest.mark.parametrize(
        ("variant", "payload"),
        [
            ("path_traversal_unix_relative", b"../../../etc/passwd"),
            ("path_traversal_windows_relative", b"..\\..\\..\\windows\\"),
            ("path_traversal_unix_absolute", b"/etc/passwd"),
            ("path_traversal_unc_path", b"\\\\server\\share"),
            ("path_traversal_file_uri", b"file:///etc/passwd"),
            ("path_traversal_double_encoded", b"....//....//etc/passwd"),
            ("path_traversal_url_encoded", b"%2e%2e%2f"),
        ],
    )
    def test_payload_present(self, template_bytes, variant, payload):
        data = _get_variant(mutate_cve_2021_41946(template_bytes), variant)
        assert payload in data


class TestCVE2020_29625:
    """CVE-2020-29625: DCMTK DoS via undefined length fields."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2020_29625(template_bytes)) == 2

    def test_undefined_length(self, template_bytes):
        data = _get_variant(mutate_cve_2020_29625(template_bytes), "undefined_length")
        assert b"\xff\xff\xff\xff" in data

    def test_oversized_length(self, template_bytes):
        data = _get_variant(mutate_cve_2020_29625(template_bytes), "oversized_length")
        assert data != template_bytes


class TestCVE2019_11687:
    """CVE-2019-11687: DICOM preamble polyglot (PE/ELF)."""

    def test_variant_count(self, template_bytes):
        assert len(mutate_cve_2019_11687(template_bytes)) == 2

    def test_pe_polyglot(self, template_bytes):
        data = _get_variant(mutate_cve_2019_11687(template_bytes), "pe_polyglot")
        assert data[:2] == b"MZ"
        assert data[128:132] == b"DICM"

    def test_elf_polyglot(self, template_bytes):
        data = _get_variant(mutate_cve_2019_11687(template_bytes), "elf_polyglot")
        assert data[:4] == b"\x7fELF"
        assert data[128:132] == b"DICM"
