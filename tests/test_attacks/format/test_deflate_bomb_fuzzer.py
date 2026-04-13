"""Tests for deflate_bomb_fuzzer.py - Decompression Bomb Attacks."""

from __future__ import annotations

import io
import struct
import unittest.mock as mock
import zlib

import pydicom
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.deflate_bomb_fuzzer import (
    _BOMB_SIZES,
    _DEFLATED_TS,
    DeflateBombFuzzer,
    _build_fmi,
    _encode_ui,
    _find_fmi_end,
)

_PREAMBLE_LEN = 128
_DICM_OFFSET = 128
_DATA_OFFSET = 132
_DICM_MAGIC = b"DICM"

# Minimal CT SOP class and dummy TS for test DICOM bytes
_CT_SOP = "1.2.840.10008.5.1.4.1.1.2"
_EXPLICIT_TS = "1.2.840.10008.1.2.1"


def _make_dicom_bytes() -> bytes:
    """Return minimal serialised DICOM bytes (Part-10 format, CT SOP class)."""
    ds = Dataset()
    ds.file_meta = pydicom.Dataset()
    ds.file_meta.MediaStorageSOPClassUID = _CT_SOP
    ds.file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5"
    ds.file_meta.TransferSyntaxUID = _EXPLICIT_TS
    ds.is_implicit_VR = False
    ds.is_little_endian = True
    ds.PatientID = "TEST"
    ds.SOPClassUID = _CT_SOP
    ds.SOPInstanceUID = "1.2.3.4.5"
    buf = io.BytesIO()
    pydicom.dcmwrite(buf, ds, enforce_file_format=True)
    return buf.getvalue()


@pytest.fixture
def fuzzer() -> DeflateBombFuzzer:
    return DeflateBombFuzzer()


@pytest.fixture
def dicom_bytes() -> bytes:
    return _make_dicom_bytes()


# ---------------------------------------------------------------------------
# Init / protocol
# ---------------------------------------------------------------------------


class TestDeflateBombFuzzerInit:
    def test_strategy_name(self, fuzzer):
        assert fuzzer.strategy_name == "deflate_bomb"

    def test_can_mutate_always_true(self, fuzzer):
        assert fuzzer.can_mutate(Dataset()) is True

    def test_mutate_returns_dataset_unchanged(self, fuzzer):
        ds = Dataset()
        ds.PatientID = "X"
        result = fuzzer.mutate(ds)
        assert result.PatientID == "X"

    def test_mutate_sets_last_variant_none(self, fuzzer):
        fuzzer.mutate(Dataset())
        assert fuzzer.last_variant is None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestEncodingHelpers:
    def test_encode_ui_even_length(self):
        raw = _encode_ui(0x0002, 0x0100, _DEFLATED_TS)
        # tag(4) + "UI"(2) + length(2) + value(even)
        assert raw[:4] == b"\x02\x00\x00\x01"
        assert raw[4:6] == b"UI"
        length = struct.unpack_from("<H", raw, 6)[0]
        assert length % 2 == 0
        assert length == len(raw) - 8

    def test_encode_ui_odd_padded(self):
        # Craft a UID that encodes to odd ASCII length
        odd_uid = "1.2.3"  # 5 chars → padded to 6
        raw = _encode_ui(0x0002, 0x0002, odd_uid)
        length = struct.unpack_from("<H", raw, 6)[0]
        assert length == 6
        assert raw[-1] == 0x00  # null pad

    def test_build_fmi_starts_with_group_length(self):
        fmi = _build_fmi(_CT_SOP, "1.2.3.4.5")
        # (0002,0000) tag: group=0x0002, elem=0x0000
        assert struct.unpack_from("<H", fmi, 0)[0] == 0x0002
        assert struct.unpack_from("<H", fmi, 2)[0] == 0x0000

    def test_build_fmi_contains_deflated_ts(self):
        fmi = _build_fmi(_CT_SOP, "1.2.3.4.5")
        assert _DEFLATED_TS.encode("ascii") in fmi

    def test_build_fmi_group_length_consistent(self):
        """(0002,0000) value must equal length of remaining FMI bytes."""
        fmi = _build_fmi(_CT_SOP, "1.2.3.4.5")
        # (0002,0000) element: tag(4)+VR"UL"(2)+len(2)+value(4) = 12 bytes
        group_len = struct.unpack_from("<I", fmi, 8)[0]
        assert group_len == len(fmi) - 12


class TestFindFmiEnd:
    def test_finds_end_of_fmi(self, dicom_bytes):
        end = _find_fmi_end(dicom_bytes)
        # After FMI, next tag should NOT be group 0002
        group = struct.unpack_from("<H", dicom_bytes, end)[0]
        assert group != 0x0002

    def test_returns_132_for_short_data(self):
        assert _find_fmi_end(b"\x00" * 132) == 132

    def test_returns_132_when_no_fmi(self):
        # Build bytes where first element is group 0008 (not 0002)
        data = (
            b"\x00" * 128
            + b"DICM"
            + struct.pack("<HH", 0x0008, 0x0060)
            + b"CS\x02\x00CT"
        )
        assert _find_fmi_end(data) == 132


# ---------------------------------------------------------------------------
# Deflate bomb internals
# ---------------------------------------------------------------------------


class TestMakeBomb:
    def test_small_bomb_decompresses_correctly(self, fuzzer):
        compressed = fuzzer._make_bomb(1024)  # 1 KB for speed
        decompressed = zlib.decompress(compressed, wbits=-15)
        assert len(decompressed) == 1024
        assert decompressed == b"\x00" * 1024

    def test_bomb_is_raw_deflate(self, fuzzer):
        """Verify wbits=-15: no zlib header (0x78) or gzip magic."""
        compressed = fuzzer._make_bomb(256)
        assert not compressed.startswith(b"\x78")  # no zlib header
        assert not compressed.startswith(b"\x1f\x8b")  # no gzip magic

    def test_compression_ratio_exceeds_threshold(self, fuzzer):
        """256 KB of zeros should compress to < 512 bytes (ratio > 512:1)."""
        size = 256 * 1024
        compressed = fuzzer._make_bomb(size)
        assert len(compressed) < 512


class TestCorruptedStream:
    def test_corrupted_stream_length(self, fuzzer):
        data = fuzzer._corrupted_stream()
        assert len(data) > 0

    def test_corrupted_stream_raises_on_decompress(self, fuzzer):
        data = fuzzer._corrupted_stream()
        with pytest.raises(zlib.error):
            zlib.decompress(data, wbits=-15)


# ---------------------------------------------------------------------------
# mutate_bytes
# ---------------------------------------------------------------------------


class TestMutateBytes:
    def test_preserves_preamble_length(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="small"):
            result = fuzzer.mutate_bytes(dicom_bytes)
        assert result[:_PREAMBLE_LEN] == b"\x00" * _PREAMBLE_LEN

    def test_preserves_dicm_magic(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="small"):
            result = fuzzer.mutate_bytes(dicom_bytes)
        assert result[_DICM_OFFSET:_DATA_OFFSET] == _DICM_MAGIC

    def test_result_longer_than_input(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="small"):
            result = fuzzer.mutate_bytes(dicom_bytes)
        # Bomb + FMI overhead must exceed the tiny test input
        assert len(result) > len(dicom_bytes)

    def test_fmi_declares_deflated_ts(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="small"):
            result = fuzzer.mutate_bytes(dicom_bytes)
        assert _DEFLATED_TS.encode("ascii") in result

    def test_last_variant_set(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="medium"):
            fuzzer.mutate_bytes(dicom_bytes)
        assert fuzzer.last_variant == "deflate_bomb_medium"

    def test_applied_binary_mutations_populated(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="large"):
            fuzzer.mutate_bytes(dicom_bytes)
        assert "deflate_bomb_large" in fuzzer._applied_binary_mutations

    def test_corrupted_variant(self, fuzzer, dicom_bytes):
        with mock.patch("random.choice", return_value="corrupted"):
            result = fuzzer.mutate_bytes(dicom_bytes)
        assert fuzzer.last_variant == "deflate_bomb_corrupted"
        assert result[_DICM_OFFSET:_DATA_OFFSET] == _DICM_MAGIC

    def test_post_fmi_decompresses_for_small_variant(self, fuzzer, dicom_bytes):
        """small variant: post-FMI bytes should be a valid deflate bomb."""
        with mock.patch("random.choice", return_value="small"):
            result = fuzzer.mutate_bytes(dicom_bytes)
        fmi_end = _find_fmi_end(result)
        bomb_bytes = result[fmi_end:]
        decompressed = zlib.decompress(bomb_bytes, wbits=-15)
        assert len(decompressed) == _BOMB_SIZES["small"]

    def test_works_with_short_input(self, fuzzer):
        """Graceful handling when file_data is shorter than expected."""
        with mock.patch("random.choice", return_value="small"):
            result = fuzzer.mutate_bytes(b"\x00" * 50)
        assert result[_DICM_OFFSET:_DATA_OFFSET] == _DICM_MAGIC

    def test_all_variants_selectable(self, fuzzer, dicom_bytes):
        seen = set()
        for variant in ["small", "medium", "large", "corrupted"]:
            with mock.patch("random.choice", return_value=variant):
                fuzzer.mutate_bytes(dicom_bytes)
            seen.add(fuzzer.last_variant)
        assert seen == {
            "deflate_bomb_small",
            "deflate_bomb_medium",
            "deflate_bomb_large",
            "deflate_bomb_corrupted",
        }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_registered_in_dicom_mutator(self):
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator()
        names = [s.strategy_name for s in mutator.strategies]
        assert "deflate_bomb" in names
