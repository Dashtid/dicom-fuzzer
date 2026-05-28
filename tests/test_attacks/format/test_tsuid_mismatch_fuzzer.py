"""Tests for tsuid_mismatch_fuzzer.py - Declared-vs-actual TSUID mismatch."""

import pytest
from pydicom.dataset import Dataset, FileMetaDataset

from dicom_fuzzer.attacks.format.tsuid_mismatch_fuzzer import (
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
