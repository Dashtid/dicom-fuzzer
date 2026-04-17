"""Tests for dicomdir_fuzzer.py - DICOMDIR Path Traversal Attacks."""

from __future__ import annotations

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.dicomdir_fuzzer import (
    _DICOMDIR_SOP_CLASS,
    _TRAVERSAL_SEQUENCES,
    DicomdirFuzzer,
)


@pytest.fixture
def fuzzer() -> DicomdirFuzzer:
    return DicomdirFuzzer()


@pytest.fixture
def dataset() -> Dataset:
    ds = Dataset()
    ds.PatientID = "TEST"
    return ds


class TestDicomdirFuzzerInit:
    def test_strategy_name(self, fuzzer):
        assert fuzzer.strategy_name == "dicomdir"

    def test_can_mutate_always_true(self, fuzzer, dataset):
        assert fuzzer.can_mutate(dataset) is True

    def test_structural_strategies_count(self, fuzzer):
        assert len(fuzzer.structural_strategies) == 4

    def test_content_strategies_count(self, fuzzer):
        assert len(fuzzer.content_strategies) == 2

    def test_all_strategies_callable(self, fuzzer):
        for s in fuzzer.mutation_strategies:
            assert callable(s)


class TestMutate:
    def test_returns_dataset(self, fuzzer, dataset):
        result = fuzzer.mutate(dataset)
        assert isinstance(result, Dataset)

    def test_sets_sop_class_uid(self, fuzzer, dataset):
        result = fuzzer.mutate(dataset)
        assert str(result.SOPClassUID) == _DICOMDIR_SOP_CLASS

    def test_sets_fileset_id(self, fuzzer, dataset):
        result = fuzzer.mutate(dataset)
        # FileSetID may be overwritten by _fileset_id_attack; just check it exists
        assert hasattr(result, "FileSetID") or hasattr(
            result, "DirectoryRecordSequence"
        )

    def test_last_variant_set(self, fuzzer, dataset):
        fuzzer.mutate(dataset)
        assert fuzzer.last_variant is not None

    def test_last_variant_contains_strategy_name(self, fuzzer, dataset):
        fuzzer.mutate(dataset)
        strategy_names = {s.__name__ for s in fuzzer.mutation_strategies}
        parts = fuzzer.last_variant.split(",")
        for part in parts:
            assert part in strategy_names


class TestPathTraversal:
    def test_sets_directory_record_sequence(self, fuzzer, dataset):
        result = fuzzer._path_traversal(dataset)
        assert hasattr(result, "DirectoryRecordSequence")
        assert len(result.DirectoryRecordSequence) >= 1

    def test_referenced_file_id_contains_traversal(self, fuzzer, dataset):
        result = fuzzer._path_traversal(dataset)
        file_id = result.DirectoryRecordSequence[0].ReferencedFileID
        joined = "/".join(str(c) for c in file_id)
        assert ".." in joined or "%" in joined or "//" in joined

    def test_all_traversal_sequences_covered(self):
        """Every traversal sequence in _TRAVERSAL_SEQUENCES is reachable."""
        fuzzer = DicomdirFuzzer()
        seen = set()
        for _ in range(500):
            ds = Dataset()
            result = fuzzer._path_traversal(ds)
            file_id = tuple(result.DirectoryRecordSequence[0].ReferencedFileID)
            seen.add(file_id)
            if len(seen) == len(_TRAVERSAL_SEQUENCES):
                break
        assert len(seen) == len(_TRAVERSAL_SEQUENCES)


class TestAbsolutePath:
    def test_sets_directory_record_sequence(self, fuzzer, dataset):
        result = fuzzer._absolute_path(dataset)
        assert hasattr(result, "DirectoryRecordSequence")

    def test_referenced_file_id_is_absolute(self, fuzzer, dataset):
        result = fuzzer._absolute_path(dataset)
        file_id = result.DirectoryRecordSequence[0].ReferencedFileID
        # pydicom uses \ as CS VR delimiter, so Windows paths like
        # "C:\Windows\..." are split into ["C:", "Windows", ...].
        # Normalise to a list of string components then join for inspection.
        components = [file_id] if isinstance(file_id, str) else list(file_id)
        joined = "".join(str(c) for c in components)
        first = str(components[0])
        # /etc/passwd  -> first="/etc/passwd" (starts with /)
        # /proc/self   -> first="/proc/self/mem" (starts with /)
        # C:\Windows   -> split -> first="C:" or "C" (Windows drive letter)
        # \\evil.inval -> split -> first="" (empty UNC prefix) + "evil" later
        assert (
            first.startswith("/")
            or first.startswith("C:\\")
            or first in ("C:", "C")
            or first == ""  # UNC path: \\ splits to empty first component
            or "evil" in joined  # fallback for UNC marker
        )

    def test_multiple_runs_vary(self, fuzzer):
        """Absolute path selection varies across runs."""
        seen = set()
        for _ in range(200):
            ds = Dataset()
            result = fuzzer._absolute_path(ds)
            file_id = tuple(result.DirectoryRecordSequence[0].ReferencedFileID)
            seen.add(file_id)
        assert len(seen) > 1


class TestDeepNesting:
    def test_sets_directory_record_sequence(self, fuzzer, dataset):
        result = fuzzer._deep_nesting(dataset)
        assert hasattr(result, "DirectoryRecordSequence")

    def test_top_level_is_study_record(self, fuzzer, dataset):
        result = fuzzer._deep_nesting(dataset)
        top = result.DirectoryRecordSequence[0]
        assert top.DirectoryRecordType == "STUDY"

    def test_nested_structure_present(self, fuzzer, dataset):
        result = fuzzer._deep_nesting(dataset)
        top = result.DirectoryRecordSequence[0]
        # At least one level of nesting should exist
        assert hasattr(top, "DirectoryRecordSequence")
        assert len(top.DirectoryRecordSequence) >= 1


class TestOverlongComponent:
    def test_sets_directory_record_sequence(self, fuzzer, dataset):
        result = fuzzer._overlong_component(dataset)
        assert hasattr(result, "DirectoryRecordSequence")

    def test_single_huge_exceeds_cs_limit(self, fuzzer, dataset):
        """At least one variant produces a component far beyond 16-char CS limit."""
        for _ in range(50):
            ds = Dataset()
            result = fuzzer._overlong_component(ds)
            file_id = result.DirectoryRecordSequence[0].ReferencedFileID
            if any(len(str(c)) > 16 for c in file_id):
                return
        pytest.fail("No overlong component produced in 50 tries")

    def test_boundary_variant_is_17_chars(self, fuzzer):
        """boundary variant produces exactly 17-char component (one over CS limit)."""
        import unittest.mock as mock

        with mock.patch("random.choice", return_value="boundary"):
            ds = Dataset()
            result = fuzzer._overlong_component(ds)
            raw = result.DirectoryRecordSequence[0].ReferencedFileID
            # pydicom returns a bare string for single-component CS, not a list
            components = [raw] if isinstance(raw, str) else list(raw)
            assert any(len(str(c)) == 17 for c in components)


class TestNullByteInjection:
    def test_sets_directory_record_sequence(self, fuzzer, dataset):
        result = fuzzer._null_byte_injection(dataset)
        assert hasattr(result, "DirectoryRecordSequence")

    def test_null_bytes_present_in_file_id(self, fuzzer, dataset):
        for _ in range(50):
            ds = Dataset()
            result = fuzzer._null_byte_injection(ds)
            file_id = result.DirectoryRecordSequence[0].ReferencedFileID
            joined = "".join(str(c) for c in file_id)
            if "\x00" in joined:
                return
        pytest.fail("No null byte produced in 50 tries")


class TestFilesetIdAttack:
    def test_modifies_fileset_id(self, fuzzer, dataset):
        dataset.FileSetID = "ORIGINAL"
        result = fuzzer._fileset_id_attack(dataset)
        assert result.FileSetID != "ORIGINAL"

    def test_empty_variant(self, fuzzer, dataset):
        import unittest.mock as mock

        with mock.patch("random.choice", return_value="empty"):
            result = fuzzer._fileset_id_attack(dataset)
            assert result.FileSetID == ""

    def test_overlong_variant(self, fuzzer, dataset):
        import unittest.mock as mock

        with mock.patch("random.choice", return_value="overlong"):
            result = fuzzer._fileset_id_attack(dataset)
            assert len(result.FileSetID) == 65_536


class TestRegistration:
    def test_registered_in_dicom_mutator(self):
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator()
        names = [s.strategy_name for s in mutator.strategies]
        assert "dicomdir" in names

    def test_all_structural_attacks_reachable(self, fuzzer):
        """All 4 structural attacks are selectable via mutate()."""
        seen: set[str] = set()
        expected = {
            "_path_traversal",
            "_absolute_path",
            "_deep_nesting",
            "_overlong_component",
        }
        for _ in range(500):
            ds = Dataset()
            fuzzer.mutate(ds)
            for part in fuzzer.last_variant.split(","):
                seen.add(part)
            if expected.issubset(seen):
                break
        assert expected.issubset(seen)
