"""Regression tests for MultiFrameFuzzerBase helpers.

Covers bugs surfaced by the campaign on 2026-04-18:
- _calculate_frame_size raised TypeError when a pydicom geometry tag
  (Rows/Columns/BitsAllocated/SamplesPerPixel) was a string after
  upstream mutation.
- _get_frame_count returned negative values, producing struct-pack
  format strings like "<-5I" that raise "bad char in struct format".
"""

from __future__ import annotations

from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.multiframe.format_base import MultiFrameFuzzerBase


class _Stub(MultiFrameFuzzerBase):
    """Concrete subclass so we can instantiate the abstract base for tests."""

    @property
    def strategy_name(self) -> str:
        return "stub"

    def can_mutate(self, dataset: Dataset) -> bool:
        return True

    def _mutate_impl(self, dataset, mutation_count):
        return dataset, []


class TestSafeInt:
    def test_int_passthrough(self) -> None:
        assert _Stub._safe_int(42, 0) == 42

    def test_numeric_string_parses(self) -> None:
        assert _Stub._safe_int("42", 0) == 42

    def test_garbage_string_returns_default(self) -> None:
        assert _Stub._safe_int("BAD", 7) == 7

    def test_none_returns_default(self) -> None:
        assert _Stub._safe_int(None, 7) == 7


class TestCalculateFrameSizeStringValues:
    def test_string_rows_does_not_raise(self) -> None:
        ds = Dataset()
        ds.Rows = "BAD"
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        stub = _Stub()
        assert stub._calculate_frame_size(ds) == 0

    def test_string_bits_allocated_does_not_raise(self) -> None:
        ds = Dataset()
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = "garbage"
        ds.SamplesPerPixel = 1
        stub = _Stub()
        size = stub._calculate_frame_size(ds)
        assert size == 256 * 256 * (8 // 8) * 1


class TestGetFrameCountNegative:
    def test_negative_clamped_to_one(self) -> None:
        # pydicom IS VR accepts negative ints; fuzzer must clamp since
        # downstream struct.pack uses the count in a format string like
        # f"<{count}I" and negatives raise "bad char in struct format".
        ds = Dataset()
        ds.NumberOfFrames = -5
        assert _Stub()._get_frame_count(ds) == 1

    def test_zero_clamped_to_one(self) -> None:
        ds = Dataset()
        ds.NumberOfFrames = 0
        assert _Stub()._get_frame_count(ds) == 1

    def test_valid_count_preserved(self) -> None:
        ds = Dataset()
        ds.NumberOfFrames = 10
        assert _Stub()._get_frame_count(ds) == 10
