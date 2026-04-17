"""Tests for preamble_fuzzer.py - DICOM Preamble Polyglot Attacks."""

from __future__ import annotations

import io
import struct

import pydicom
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.preamble_fuzzer import (
    _DATA_OFFSET,
    _DICM_MAGIC,
    _DICM_OFFSET,
    _PREAMBLE_LEN,
    PreambleFuzzer,
)


def _make_dicom_bytes() -> bytes:
    """Return a minimal serialised DICOM file as bytes (Part 10 format)."""
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta.ImplementationClassUID = generate_uid()
    ds.is_implicit_VR = False
    ds.is_little_endian = True
    ds.PatientID = "TEST"

    buf = io.BytesIO()
    pydicom.dcmwrite(buf, ds, enforce_file_format=True)
    return buf.getvalue()


class TestPreambleFuzzerInit:
    def test_strategy_name(self):
        assert PreambleFuzzer().strategy_name == "preamble"

    def test_can_mutate_always_true(self):
        assert PreambleFuzzer().can_mutate(Dataset()) is True

    def test_last_variant_none_after_mutate(self):
        fuzzer = PreambleFuzzer()
        fuzzer.mutate(Dataset())
        assert fuzzer.last_variant is None

    def test_mutate_returns_dataset_unchanged(self):
        fuzzer = PreambleFuzzer()
        ds = Dataset()
        ds.PatientID = "X"
        result = fuzzer.mutate(ds)
        assert result is ds
        assert result.PatientID == "X"


class TestMutateBytes:
    def test_dicm_magic_preserved(self):
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        result = fuzzer.mutate_bytes(file_data)
        assert result[_DICM_OFFSET:_DATA_OFFSET] == _DICM_MAGIC

    def test_data_elements_unchanged(self):
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        result = fuzzer.mutate_bytes(file_data)
        assert result[_DATA_OFFSET:] == file_data[_DATA_OFFSET:]

    def test_preamble_length_preserved(self):
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        result = fuzzer.mutate_bytes(file_data)
        assert len(result) == len(file_data)

    def test_applied_binary_mutations_populated(self):
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        fuzzer.mutate_bytes(file_data)
        assert len(fuzzer._applied_binary_mutations) == 1

    def test_last_variant_set_after_mutate_bytes(self):
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        fuzzer.mutate_bytes(file_data)
        assert fuzzer.last_variant is not None

    def test_too_short_returns_unchanged(self):
        fuzzer = PreambleFuzzer()
        short = b"\x00" * 10
        assert fuzzer.mutate_bytes(short) == short

    def test_missing_dicm_magic_returns_unchanged(self):
        fuzzer = PreambleFuzzer()
        bad = b"\x00" * 128 + b"XXXX" + b"\x00" * 20
        assert fuzzer.mutate_bytes(bad) == bad

    def test_preamble_bytes_are_modified(self):
        """At least one preamble byte should differ from the original zeroes."""
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        # Default pydicom preamble is all zeros
        assert file_data[:_PREAMBLE_LEN] == b"\x00" * _PREAMBLE_LEN
        result = fuzzer.mutate_bytes(file_data)
        # Every attack we implement writes non-zero bytes somewhere
        assert result[:_PREAMBLE_LEN] != b"\x00" * _PREAMBLE_LEN


class TestPePolyglot:
    def test_mz_magic(self):
        fuzzer = PreambleFuzzer()
        preamble = fuzzer._pe_polyglot()
        assert preamble[:2] == b"MZ"

    def test_pe_signature_at_offset_64(self):
        fuzzer = PreambleFuzzer()
        preamble = fuzzer._pe_polyglot()
        assert preamble[64:68] == b"PE\x00\x00"

    def test_e_lfanew_points_to_64(self):
        fuzzer = PreambleFuzzer()
        preamble = fuzzer._pe_polyglot()
        e_lfanew = struct.unpack_from("<I", preamble, 0x3C)[0]
        assert e_lfanew == 64

    def test_length(self):
        assert len(PreambleFuzzer()._pe_polyglot()) == _PREAMBLE_LEN


class TestElfPolyglot:
    def test_elf_magic(self):
        fuzzer = PreambleFuzzer()
        preamble = fuzzer._elf_polyglot()
        assert preamble[:4] == b"\x7fELF"

    def test_elf_class_64bit(self):
        preamble = PreambleFuzzer()._elf_polyglot()
        assert preamble[4] == 2  # ELFCLASS64

    def test_elf_little_endian(self):
        preamble = PreambleFuzzer()._elf_polyglot()
        assert preamble[5] == 1  # ELFDATA2LSB

    def test_length(self):
        assert len(PreambleFuzzer()._elf_polyglot()) == _PREAMBLE_LEN


class TestJsonPreamble:
    def test_starts_with_brace(self):
        preamble = PreambleFuzzer()._json_preamble()
        assert preamble[0:1] == b"{"

    def test_length(self):
        assert len(PreambleFuzzer()._json_preamble()) == _PREAMBLE_LEN

    def test_null_padded(self):
        preamble = PreambleFuzzer()._json_preamble()
        assert preamble[-1] == 0


class TestFfPreamble:
    def test_all_ff(self):
        preamble = PreambleFuzzer()._ff_preamble()
        assert preamble == b"\xff" * _PREAMBLE_LEN

    def test_length(self):
        assert len(PreambleFuzzer()._ff_preamble()) == _PREAMBLE_LEN


class TestRandomPreamble:
    def test_length(self):
        assert len(PreambleFuzzer()._random_preamble()) == _PREAMBLE_LEN

    def test_different_each_call(self):
        f = PreambleFuzzer()
        # Two calls should almost certainly differ (p = 1/256^128 they're equal)
        assert f._random_preamble() != f._random_preamble()


class TestRegistration:
    def test_registered_in_dicom_mutator(self):
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator()
        names = [s.strategy_name for s in mutator.strategies]
        assert "preamble" in names

    def test_attack_selection_reaches_all_sub_attacks(self):
        """All 5 sub-attacks are reachable via repeated mutate_bytes calls."""
        fuzzer = PreambleFuzzer()
        file_data = _make_dicom_bytes()
        seen: set[str] = set()
        for _ in range(200):
            fuzzer.mutate_bytes(file_data)
            if fuzzer.last_variant:
                seen.add(fuzzer.last_variant)
        expected = {
            "_pe_polyglot",
            "_elf_polyglot",
            "_json_preamble",
            "_ff_preamble",
            "_random_preamble",
        }
        assert expected == seen
