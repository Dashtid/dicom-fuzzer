"""Tests for dicom_fuzzer.utils.binary_mutators.

The helper is the canonical implementation behind StructureFuzzer's
length-corruption attack and the new mutate_bytes paths on
HeaderFuzzer, MetadataFuzzer, and PrivateTagFuzzer. Regressions here
break four fuzzers at once, so the module deserves its own test set.
"""

from __future__ import annotations

import io
import random
import struct

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.utils.binary_mutators import (
    CORRUPT_LENGTHS_2B,
    CORRUPT_LENGTHS_4B,
    DATA_OFFSET,
    DICM_MAGIC,
    DICM_OFFSET,
    LONG_VRS,
    corrupt_random_length_field,
    is_valid_dicom,
    parse_dicom_elements,
)

# ---------------------------------------------------------------------------
# Fixtures: minimal valid DICOM byte streams in Explicit VR LE
# ---------------------------------------------------------------------------


def _build_dicom_bytes() -> bytes:
    """Produce a minimal valid Explicit VR LE DICOM byte string with
    a few short-VR elements suitable for length-field mutation tests.
    """
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST123"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = generate_uid()
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    buffer = io.BytesIO()
    pydicom.dcmwrite(buffer, ds, enforce_file_format=True)
    return buffer.getvalue()


@pytest.fixture
def dicom_bytes() -> bytes:
    return _build_dicom_bytes()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_magic_and_offsets(self) -> None:
        assert DICM_MAGIC == b"DICM"
        assert DICM_OFFSET == 128
        assert DATA_OFFSET == 132

    def test_long_vrs_membership(self) -> None:
        assert b"OB" in LONG_VRS
        assert b"SQ" in LONG_VRS
        assert b"UN" in LONG_VRS
        assert b"PN" not in LONG_VRS  # short VR

    def test_corrupt_lengths_4b_widths(self) -> None:
        for value in CORRUPT_LENGTHS_4B:
            assert len(value) == 4

    def test_corrupt_lengths_2b_widths(self) -> None:
        for value in CORRUPT_LENGTHS_2B:
            assert len(value) == 2

    def test_undefined_sentinel_present(self) -> None:
        assert struct.pack("<I", 0xFFFFFFFF) in CORRUPT_LENGTHS_4B
        assert struct.pack("<H", 0xFFFF) in CORRUPT_LENGTHS_2B


# ---------------------------------------------------------------------------
# is_valid_dicom
# ---------------------------------------------------------------------------


class TestIsValidDicom:
    def test_real_file(self, dicom_bytes: bytes) -> None:
        assert is_valid_dicom(dicom_bytes) is True

    def test_too_short(self) -> None:
        assert is_valid_dicom(b"") is False
        assert is_valid_dicom(b"\x00" * 100) is False

    def test_no_magic(self) -> None:
        # 132 bytes but DICM not at offset 128
        assert is_valid_dicom(b"\x00" * 200) is False

    def test_magic_at_wrong_offset(self) -> None:
        data = b"\x00" * 130 + b"DICM" + b"\x00" * 100
        assert is_valid_dicom(data) is False


# ---------------------------------------------------------------------------
# parse_dicom_elements
# ---------------------------------------------------------------------------


class TestParseDicomElements:
    def test_finds_dataset_elements(self, dicom_bytes: bytes) -> None:
        elements = parse_dicom_elements(dicom_bytes, DATA_OFFSET)
        assert len(elements) >= 1

    def test_offsets_are_in_range(self, dicom_bytes: bytes) -> None:
        for elem_start, elem_end, len_offset, len_size in parse_dicom_elements(
            dicom_bytes, DATA_OFFSET
        ):
            assert elem_start >= DATA_OFFSET
            assert elem_end <= len(dicom_bytes)
            assert len_offset < elem_end
            assert len_size in (2, 4)

    def test_elements_within_file_bounds(self, dicom_bytes: bytes) -> None:
        for _, elem_end, _, _ in parse_dicom_elements(dicom_bytes, DATA_OFFSET):
            assert elem_end <= len(dicom_bytes)

    def test_empty_input(self) -> None:
        assert parse_dicom_elements(b"", 0) == []

    def test_offset_past_end(self) -> None:
        assert parse_dicom_elements(b"\x00" * 10, 200) == []

    def test_truncated_file_returns_partial(self, dicom_bytes: bytes) -> None:
        # Truncate mid-element; parser should return whatever it managed
        # and not raise.
        truncated = dicom_bytes[: DATA_OFFSET + 10]
        result = parse_dicom_elements(truncated, DATA_OFFSET)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# corrupt_random_length_field
# ---------------------------------------------------------------------------


class TestCorruptRandomLengthField:
    def test_mutates_one_length_field(self, dicom_bytes: bytes) -> None:
        rng = random.Random(42)
        result = corrupt_random_length_field(dicom_bytes, rng=rng)

        assert result != dicom_bytes
        assert len(result) == len(dicom_bytes)  # length-preserving
        # Preamble + DICM intact
        assert result[:DATA_OFFSET] == dicom_bytes[:DATA_OFFSET]

    def test_invalid_input_unchanged(self) -> None:
        assert corrupt_random_length_field(b"") == b""
        assert corrupt_random_length_field(b"\x00" * 100) == b"\x00" * 100

    def test_no_parseable_elements_unchanged(self) -> None:
        # Valid magic but file ends mid-element header so no full element
        # can be parsed. (16 trailing zeros would parse as zero-length
        # group-0000 elements -- valid Explicit VR LE structure.)
        bogus = b"\x00" * DICM_OFFSET + DICM_MAGIC + b"\x00" * 7
        assert corrupt_random_length_field(bogus) == bogus

    def test_deterministic_with_seed(self, dicom_bytes: bytes) -> None:
        a = corrupt_random_length_field(dicom_bytes, rng=random.Random(1))
        b = corrupt_random_length_field(dicom_bytes, rng=random.Random(1))
        assert a == b

    def test_different_seeds_produce_different_outputs(
        self, dicom_bytes: bytes
    ) -> None:
        a = corrupt_random_length_field(dicom_bytes, rng=random.Random(1))
        b = corrupt_random_length_field(dicom_bytes, rng=random.Random(2))
        # Not strictly guaranteed, but with enough elements + patterns,
        # collision is improbable for these two seeds.
        assert a != b

    def test_output_is_bytes_type(self, dicom_bytes: bytes) -> None:
        result = corrupt_random_length_field(dicom_bytes)
        assert isinstance(result, bytes)

    def test_corruption_lands_in_a_known_pattern(self, dicom_bytes: bytes) -> None:
        """Verify the patched length matches one of the configured patterns."""
        rng = random.Random(99)
        result = corrupt_random_length_field(dicom_bytes, rng=rng)

        # Find the first byte that differs and confirm it's part of a
        # contiguous run that matches a known pattern.
        diff_offset = next(
            i for i in range(len(dicom_bytes)) if dicom_bytes[i] != result[i]
        )
        # The patched range must be 2 or 4 bytes; check both.
        candidate_2b = result[diff_offset : diff_offset + 2]
        candidate_4b = result[diff_offset : diff_offset + 4]
        assert candidate_2b in CORRUPT_LENGTHS_2B or candidate_4b in CORRUPT_LENGTHS_4B
