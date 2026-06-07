"""Tests for tsuid_mismatch_fuzzer.py - Declared-vs-actual TSUID mismatch."""

import io

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.tsuid_mismatch_fuzzer import (
    _TSUID_EXPLICIT_VR_BE,
    _TSUID_EXPLICIT_VR_LE,
    _TSUID_IMPLICIT_VR_LE,
    TSUIDMismatchFuzzer,
)

_TSUID_JPEG2000_LOSSLESS = "1.2.840.10008.1.2.4.90"
_TSUID_JPEG_LS_LOSSLESS = "1.2.840.10008.1.2.4.80"
_TSUID_RLE = "1.2.840.10008.1.2.5"
_FAKE_ENCAPSULATED_PD = (
    b"\xfe\xff\x00\xe0\x00\x00\x00\x00\xfe\xff\x00\xe0\x36\x00\x00\x00"
)


@pytest.fixture
def fuzzer() -> TSUIDMismatchFuzzer:
    return TSUIDMismatchFuzzer()


def _make_dataset(tsuid: str, rows: int = 64, with_pixel_data: bool = True) -> Dataset:
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = tsuid
    ds.Rows = rows
    ds.Columns = 64
    if with_pixel_data:
        ds.PixelData = _FAKE_ENCAPSULATED_PD
    return ds


class TestStrategyContract:
    def test_strategy_name(self, fuzzer):
        assert fuzzer.strategy_name == "tsuid_mismatch"

    def test_can_mutate_encapsulated(self, fuzzer):
        ds = _make_dataset(_TSUID_JPEG2000_LOSSLESS)
        assert fuzzer.can_mutate(ds) is True

    def test_can_mutate_jpeg_baseline(self, fuzzer):
        ds = _make_dataset("1.2.840.10008.1.2.4.50")
        assert fuzzer.can_mutate(ds) is True

    def test_can_mutate_rle(self, fuzzer):
        ds = _make_dataset(_TSUID_RLE)
        assert fuzzer.can_mutate(ds) is True

    @pytest.mark.parametrize(
        "tsuid",
        ["1.2.840.10008.1.2", "1.2.840.10008.1.2.1", "1.2.840.10008.1.2.2"],
    )
    def test_cannot_mutate_uncompressed(self, fuzzer, tsuid):
        ds = _make_dataset(tsuid)
        assert fuzzer.can_mutate(ds) is False

    def test_cannot_mutate_without_file_meta(self, fuzzer):
        ds = Dataset()
        ds.Rows = 64
        assert fuzzer.can_mutate(ds) is False

    def test_cannot_mutate_without_tsuid(self, fuzzer):
        ds = Dataset()
        ds.file_meta = FileMetaDataset()
        assert fuzzer.can_mutate(ds) is False


class TestVariants:
    def test_swap_to_explicit_vr_le_changes_tsuid_only(self, fuzzer):
        ds = _make_dataset(_TSUID_JPEG2000_LOSSLESS, rows=64)
        original_pd = bytes(ds.PixelData)

        out = fuzzer._swap_to_explicit_vr_le(ds)

        assert str(out.file_meta.TransferSyntaxUID) == _TSUID_EXPLICIT_VR_LE
        assert out.Rows == 64
        assert bytes(out.PixelData) == original_pd

    def test_swap_to_implicit_vr_le_changes_tsuid_only(self, fuzzer):
        ds = _make_dataset(_TSUID_JPEG_LS_LOSSLESS, rows=64)
        original_pd = bytes(ds.PixelData)

        out = fuzzer._swap_to_implicit_vr_le(ds)

        assert str(out.file_meta.TransferSyntaxUID) == _TSUID_IMPLICIT_VR_LE
        assert out.Rows == 64
        assert bytes(out.PixelData) == original_pd

    def test_swap_with_rows_zero_produces_cwe770_pair(self, fuzzer):
        ds = _make_dataset(_TSUID_JPEG2000_LOSSLESS, rows=64)
        original_pd = bytes(ds.PixelData)

        out = fuzzer._swap_with_rows_zero(ds)

        assert str(out.file_meta.TransferSyntaxUID) == _TSUID_EXPLICIT_VR_LE
        assert out.Rows == 0
        assert bytes(out.PixelData) == original_pd

    def test_swap_with_rows_zero_skips_when_rows_absent(self, fuzzer):
        ds = _make_dataset(_TSUID_JPEG2000_LOSSLESS, rows=64)
        del ds.Rows

        out = fuzzer._swap_with_rows_zero(ds)

        # TSUID still swapped, but no Rows attribute to set
        assert str(out.file_meta.TransferSyntaxUID) == _TSUID_EXPLICIT_VR_LE
        assert "Rows" not in out


class TestMutateDispatch:
    def test_mutate_records_chosen_variant(self, fuzzer):
        ds = _make_dataset(_TSUID_JPEG2000_LOSSLESS)

        fuzzer.mutate(ds)

        assert fuzzer.last_variant in {
            "_swap_to_explicit_vr_le",
            "_swap_to_implicit_vr_le",
            "_swap_with_rows_zero",
        }

    def test_mutate_idempotent_on_repeat(self, fuzzer):
        # Two back-to-back mutations on the same dataset should not raise.
        ds = _make_dataset(_TSUID_JPEG2000_LOSSLESS)
        fuzzer.mutate(ds)
        fuzzer.mutate(ds)


# ---------------------------------------------------------------------------
# Gap #2: post-serialization swap to Explicit VR Big Endian
# ---------------------------------------------------------------------------


def _serialize_le_dicom(tsuid: str = ExplicitVRLittleEndian) -> bytes:
    """Build a real DICOM file serialised by pydicom in LE form."""
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = tsuid
    ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.is_implicit_VR = False
    ds.is_little_endian = True
    ds.PatientID = "TEST001"
    ds.PatientName = "Test^Patient"
    ds.Modality = "CT"
    ds.Rows = 0x0040  # 64; recognisable little-endian byte pattern 0x40 0x00
    ds.Columns = 0x0040
    buf = io.BytesIO()
    pydicom.dcmwrite(buf, ds, enforce_file_format=True)
    return buf.getvalue()


def _find_tsuid_value(file_data: bytes) -> tuple[int, int]:
    """Locate (0002,0010) UI value in an Explicit-VR-LE FMI region.

    Returns (value_offset, value_length). Helper for tests.
    """
    pos = 132
    while pos + 8 <= len(file_data):
        group = int.from_bytes(file_data[pos : pos + 2], "little")
        if group != 0x0002:
            raise AssertionError("Walked past FMI without finding (0002,0010)")
        element = int.from_bytes(file_data[pos + 2 : pos + 4], "little")
        vr = file_data[pos + 4 : pos + 6]
        if vr in (b"OB", b"OW", b"OF", b"SQ", b"UT", b"UN"):
            length = int.from_bytes(file_data[pos + 8 : pos + 12], "little")
            value_start = pos + 12
        else:
            length = int.from_bytes(file_data[pos + 6 : pos + 8], "little")
            value_start = pos + 8
        if element == 0x0010:
            return value_start, length
        pos = value_start + length
    raise AssertionError("TSUID not found")


class TestMutateBytesBigEndianSwap:
    """Gap #2: rewrite (0002,0010) to BE post-serialization."""

    def test_returns_bytes(self, fuzzer):
        result = fuzzer.mutate_bytes(_serialize_le_dicom())
        assert isinstance(result, bytes)

    def test_output_same_length_as_input(self, fuzzer):
        """The TSUID value field is patched in place; total length unchanged."""
        file_data = _serialize_le_dicom()
        result = fuzzer.mutate_bytes(file_data)
        assert len(result) == len(file_data)

    def test_preamble_and_dicm_preserved(self, fuzzer):
        file_data = _serialize_le_dicom()
        result = fuzzer.mutate_bytes(file_data)
        assert result[:132] == file_data[:132]

    def test_tsuid_value_overwritten_with_big_endian_uid(self, fuzzer):
        file_data = _serialize_le_dicom()
        value_offset, value_length = _find_tsuid_value(file_data)
        result = fuzzer.mutate_bytes(file_data)
        patched_value = bytes(result[value_offset : value_offset + value_length])
        # The new value should START with the BE UID. Trailing NULs are pad.
        assert patched_value.startswith(
            _TSUID_EXPLICIT_VR_BE.encode("ascii")[:value_length]
        )

    def test_dataset_bytes_remain_little_endian(self, fuzzer):
        """Rows = 0x0040 must still be encoded as `\\x40\\x00` (LE) after swap."""
        file_data = _serialize_le_dicom()
        result = fuzzer.mutate_bytes(file_data)
        # The LE byte pattern for 0x0040 is b"\x40\x00". It must appear in the
        # dataset region (after FMI). Search past the file meta.
        # The dataset starts somewhere after the FMI (>= ~200 bytes); search
        # the second half of the file to avoid matching FMI offsets.
        rows_le = b"\x40\x00"
        midpoint = len(file_data) // 2
        assert rows_le in result[midpoint:]

    def test_applied_binary_mutations_recorded(self, fuzzer):
        file_data = _serialize_le_dicom()
        fuzzer.mutate_bytes(file_data)
        assert "_swap_tsuid_to_big_endian" in fuzzer._applied_binary_mutations

    def test_non_dicom_passthrough(self, fuzzer):
        garbage = b"\x00" * 256
        assert fuzzer.mutate_bytes(garbage) is garbage

    def test_short_file_passthrough(self, fuzzer):
        too_short = b"\x00" * 128 + b"DICM" + b"\x00" * 4
        assert fuzzer.mutate_bytes(too_short) is too_short

    def test_swap_idempotent(self, fuzzer):
        """Swapping an already-BE-declared file produces the same BE value
        (no-op-like behaviour; the strategy does not check the current TSUID)."""
        file_data = _serialize_le_dicom()
        once = fuzzer.mutate_bytes(file_data)
        twice = fuzzer.mutate_bytes(once)
        assert once == twice
