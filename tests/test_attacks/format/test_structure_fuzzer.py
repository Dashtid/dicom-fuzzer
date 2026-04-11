"""Tests for structure_fuzzer.py - DICOM Structure Attacks.

Tests cover structure mutations and tag corruption.
"""

import io
import random
import struct
from unittest.mock import patch

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.structure_fuzzer import (
    _DATA_OFFSET,
    StructureFuzzer,
    _parse_dicom_elements,
)


class TestStructureFuzzerInit:
    """Test StructureFuzzer initialization."""

    def test_init_corruption_strategies(self):
        """Test that fuzzer initializes with corruption strategies."""
        fuzzer = StructureFuzzer()
        assert len(fuzzer.corruption_strategies) == 6
        assert callable(fuzzer.corruption_strategies[0])

    def test_init_strategies_are_methods(self):
        """Test that all strategies are callable methods."""
        fuzzer = StructureFuzzer()
        for strategy in fuzzer.corruption_strategies:
            assert hasattr(strategy, "__call__")


class TestMutateStructure:
    """Test mutate method."""

    def test_mutate_returns_dataset(self):
        """Test that mutate returns a dataset."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test^Patient"

        result = fuzzer.mutate(dataset)
        assert isinstance(result, Dataset)
        assert result is not None

    def test_mutate_applies_strategies(self):
        """Test that mutate applies corruption strategies."""
        fuzzer = StructureFuzzer()

        # Track which strategies were called
        call_count = [0]
        original_strategies = fuzzer.corruption_strategies.copy()

        def mock_strategy(ds):
            call_count[0] += 1
            return ds

        fuzzer.corruption_strategies = [mock_strategy] * 4

        dataset = Dataset()
        dataset.PatientID = "12345"

        with patch.object(random, "randint", return_value=2):
            with patch.object(
                random, "sample", return_value=[mock_strategy, mock_strategy]
            ):
                fuzzer.mutate(dataset)

        assert call_count[0] == 2


class TestCorruptTagOrdering:
    """Test _corrupt_tag_ordering method."""

    def test_corrupt_tag_ordering_with_elements(self):
        """Test tag ordering corruption with multiple elements."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test^Patient"
        dataset.StudyDate = "20230101"
        dataset.Modality = "CT"

        # Force a specific swap
        with patch.object(random, "sample", return_value=[0, 2]):
            result = fuzzer._corrupt_tag_ordering(dataset)

        assert isinstance(result, Dataset)
        assert result is not None

    def test_corrupt_tag_ordering_few_elements(self):
        """Test tag ordering with insufficient elements."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        # Only 1 element - too few to swap

        result = fuzzer._corrupt_tag_ordering(dataset)
        assert result == dataset
        assert isinstance(result, Dataset)

    def test_corrupt_tag_ordering_preserves_file_meta(self):
        """Test that file_meta is preserved during corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test^Patient"
        dataset.StudyDate = "20230101"
        dataset.Modality = "CT"

        # Add file_meta
        file_meta = Dataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        dataset.file_meta = file_meta

        with patch.object(random, "sample", return_value=[0, 2]):
            result = fuzzer._corrupt_tag_ordering(dataset)

        assert hasattr(result, "file_meta")
        assert result.file_meta.TransferSyntaxUID == "1.2.840.10008.1.2"


class TestCorruptLengthFields:
    """Test _corrupt_length_fields method."""

    def test_corrupt_length_overflow(self):
        """Test length overflow corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = [
                Tag("PatientName"),  # Choose PatientName tag
                "overflow",  # Choose overflow corruption
            ]
            result = fuzzer._corrupt_length_fields(dataset)

        # Value should have been extended
        assert isinstance(result, Dataset)
        assert result is not None

    def test_corrupt_length_underflow(self):
        """Test length underflow corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = [
                Tag("PatientName"),
                "underflow",
            ]
            result = fuzzer._corrupt_length_fields(dataset)

        assert isinstance(result, Dataset)
        assert result is not None

    def test_corrupt_length_mismatch(self):
        """Test length mismatch corruption."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = [
                Tag("PatientName"),
                "mismatch",
            ]
            result = fuzzer._corrupt_length_fields(dataset)

        assert isinstance(result, Dataset)
        assert result is not None

    def test_corrupt_length_no_string_tags(self):
        """Test corruption when no string tags exist."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        # Only add a non-string type element
        dataset.Rows = 512
        dataset.Columns = 512

        result = fuzzer._corrupt_length_fields(dataset)
        assert result == dataset
        assert isinstance(result, Dataset)


class TestInsertUnexpectedTags:
    """Test _insert_unexpected_tags method."""

    def test_insert_unexpected_tags(self):
        """Test inserting unexpected tags."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"

        with patch.object(random, "randint", return_value=1):
            with patch.object(random, "choice", return_value=0xDEADBEEF):
                result = fuzzer._insert_unexpected_tags(dataset)

        assert isinstance(result, Dataset)
        assert result is not None

    def test_insert_unexpected_tags_handles_failure(self):
        """Test that failures during tag insertion are handled."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"

        # Mock add_new to always fail
        with patch.object(dataset, "add_new", side_effect=Exception("Cannot add tag")):
            with patch.object(random, "randint", return_value=1):
                with patch.object(random, "choice", return_value=0xFFFFFFFF):
                    # Should not raise, just log and continue
                    result = fuzzer._insert_unexpected_tags(dataset)

        assert isinstance(result, Dataset)
        assert result is not None


class TestDuplicateTags:
    """Test _duplicate_tags method."""

    def test_duplicate_tags(self):
        """Test tag duplication."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice", return_value=Tag("PatientName")):
            result = fuzzer._duplicate_tags(dataset)

        assert isinstance(result, Dataset)
        assert result is not None

    def test_duplicate_tags_empty_dataset(self):
        """Test duplication on empty dataset."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()

        result = fuzzer._duplicate_tags(dataset)
        assert result == dataset
        assert isinstance(result, Dataset)

    def test_duplicate_tags_handles_failure(self):
        """Test that failures during duplication are handled."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        # Mock add_new to fail
        with patch.object(
            dataset, "add_new", side_effect=Exception("Duplicate not allowed")
        ):
            with patch.object(random, "choice", return_value=Tag("PatientName")):
                result = fuzzer._duplicate_tags(dataset)

        assert isinstance(result, Dataset)
        assert result is not None


class TestCorruptLengthFieldsExtended:
    """Extended tests for _corrupt_length_fields covering all corruption types."""

    def test_corrupt_length_overflow_actual(self):
        """Test overflow corruption actually adds characters."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"
        original_len = len("Test^Patient")

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = lambda x: (
                Tag("PatientName")
                if isinstance(x, list) and Tag("PatientName") in x
                else "overflow"
            )
            result = fuzzer._corrupt_length_fields(dataset)

        # Value should have X characters appended
        assert len(str(result.PatientName)) > original_len

    def test_corrupt_length_underflow_actual(self):
        """Test underflow corruption actually empties the value."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = lambda x: (
                Tag("PatientName")
                if isinstance(x, list) and Tag("PatientName") in x
                else "underflow"
            )
            result = fuzzer._corrupt_length_fields(dataset)

        assert str(result.PatientName) == ""

    def test_corrupt_length_mismatch_actual(self):
        """Test mismatch corruption actually adds null bytes."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = lambda x: (
                Tag("PatientName")
                if isinstance(x, list) and Tag("PatientName") in x
                else "mismatch"
            )
            result = fuzzer._corrupt_length_fields(dataset)

        # Value should contain null bytes
        assert "\x00" in str(result.PatientName)

    def test_corrupt_length_mismatch_short_value(self):
        """Test mismatch corruption on short value."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "AB"  # Only 2 characters

        with patch.object(random, "choice") as mock_choice:
            mock_choice.side_effect = lambda x: (
                Tag("PatientName")
                if isinstance(x, list) and Tag("PatientName") in x
                else "mismatch"
            )
            result = fuzzer._corrupt_length_fields(dataset)

        # Short values shouldn't have mismatch applied (len <= 2)
        assert isinstance(result, Dataset)
        assert result is not None

    def test_corrupt_length_multiple_string_tags(self):
        """Test corruption when multiple string tags exist."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"
        dataset.PatientID = "12345"
        dataset.StudyDescription = "Test Study"

        # Run multiple times to potentially hit different tags
        for _ in range(5):
            result = fuzzer._corrupt_length_fields(dataset)
            assert isinstance(result, Dataset)


class TestMutateStructureIntegration:
    """Integration tests for mutate."""

    def test_mutate_comprehensive(self):
        """Test mutate with comprehensive dataset."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"
        dataset.PatientID = "12345"
        dataset.StudyDescription = "Test Study"
        dataset.Modality = "CT"
        dataset.Rows = 512
        dataset.Columns = 512

        # Run multiple times
        for _ in range(10):
            result = fuzzer.mutate(dataset)
            assert isinstance(result, Dataset)

    def test_mutate_single_strategy(self):
        """Test mutate with single strategy selection."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test"

        with patch.object(random, "randint", return_value=1):
            result = fuzzer.mutate(dataset)

        assert isinstance(result, Dataset)
        assert result is not None


class TestDuplicateTagsExtended:
    """Extended tests for _duplicate_tags."""

    def test_duplicate_tags_element_without_value(self):
        """Test duplication on element without .value attribute."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"

        # Mock to return a tag, but element might not have value
        result = fuzzer._duplicate_tags(dataset)
        assert isinstance(result, Dataset)
        assert result is not None

    def test_duplicate_tags_with_sequence(self):
        """Test duplication with sequence element."""
        from pydicom.sequence import Sequence

        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientName = "Test"

        # Add a sequence
        inner_ds = Dataset()
        inner_ds.CodeValue = "12345"
        dataset.ProcedureCodeSequence = Sequence([inner_ds])

        result = fuzzer._duplicate_tags(dataset)
        assert isinstance(result, Dataset)
        assert result is not None


class TestInsertUnexpectedTagsExtended:
    """Extended tests for _insert_unexpected_tags."""

    def test_insert_unexpected_tags_multiple(self):
        """Test inserting multiple unexpected tags."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"

        with patch.object(random, "randint", return_value=2):
            result = fuzzer._insert_unexpected_tags(dataset)

        assert isinstance(result, Dataset)
        assert result is not None

    def test_insert_unexpected_tags_all_types(self):
        """Test inserting all types of unusual tags."""
        fuzzer = StructureFuzzer()
        unusual_tags = [
            0xFFFFFFFF,
            0x00000000,
            0xDEADBEEF,
            0x7FE00010,
        ]

        for tag in unusual_tags:
            dataset = Dataset()
            dataset.PatientID = "12345"

            with patch.object(random, "randint", return_value=1):
                with patch.object(random, "choice", return_value=tag):
                    result = fuzzer._insert_unexpected_tags(dataset)

            assert isinstance(result, Dataset)


class TestCorruptTagOrderingExtended:
    """Extended tests for _corrupt_tag_ordering."""

    def test_corrupt_tag_ordering_exactly_two_elements(self):
        """Test tag ordering with exactly 2 elements."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        dataset.PatientID = "12345"
        dataset.PatientName = "Test"

        result = fuzzer._corrupt_tag_ordering(dataset)

        # Should return unchanged with only 2 elements
        assert result == dataset
        assert isinstance(result, Dataset)

    def test_corrupt_tag_ordering_many_elements(self):
        """Test tag ordering with many elements."""
        fuzzer = StructureFuzzer()
        dataset = Dataset()
        for i in range(20):
            setattr(dataset, "StudyDescription", f"Study{i}")

        result = fuzzer._corrupt_tag_ordering(dataset)
        assert isinstance(result, Dataset)
        assert result is not None


# ---------------------------------------------------------------------------
# Helpers shared by binary-attack test classes
# ---------------------------------------------------------------------------


def _make_minimal_dicom_bytes() -> bytes:
    """Build a minimal valid Explicit VR LE DICOM file in memory."""
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.is_implicit_VR = False
    ds.is_little_endian = True
    ds.PatientID = "TEST001"
    ds.PatientName = "Test^Patient"
    ds.StudyDate = "20230101"
    ds.Modality = "CT"
    ds.Rows = 64
    ds.Columns = 64

    buf = io.BytesIO()
    pydicom.dcmwrite(buf, ds, enforce_file_format=True)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _parse_dicom_elements helper
# ---------------------------------------------------------------------------


class TestParseDicomElements:
    """Tests for the _parse_dicom_elements module-level helper."""

    def test_returns_list_for_valid_dicom(self):
        """Should return at least one element for a valid DICOM file."""
        file_data = _make_minimal_dicom_bytes()
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        assert isinstance(elements, list)
        assert len(elements) > 0

    def test_tuples_have_four_fields(self):
        """Each result tuple must have (start, end, len_offset, len_size)."""
        file_data = _make_minimal_dicom_bytes()
        for elem in _parse_dicom_elements(file_data, _DATA_OFFSET):
            assert len(elem) == 4
            start, end, len_off, len_size = elem
            assert start < end
            assert len_off > start
            assert len_size in (2, 4)

    def test_skips_group_0002(self):
        """No element in group 0002 should appear in results."""
        file_data = _make_minimal_dicom_bytes()
        for start, end, _, _ in _parse_dicom_elements(file_data, _DATA_OFFSET):
            group = struct.unpack_from("<H", file_data, start)[0]
            assert group != 0x0002

    def test_empty_bytes_returns_empty(self):
        """Truly empty input returns empty list without raising."""
        assert _parse_dicom_elements(b"", 0) == []

    def test_offset_beyond_data_returns_empty(self):
        """Start offset beyond file length returns empty without raising."""
        assert _parse_dicom_elements(b"\x00" * 10, 200) == []

    def test_truncated_file_returns_partial(self):
        """Truncated file should return a partial list, not raise."""
        file_data = _make_minimal_dicom_bytes()
        truncated = file_data[: len(file_data) // 2]
        result = _parse_dicom_elements(truncated, _DATA_OFFSET)
        assert isinstance(result, list)  # may be empty or partial


# ---------------------------------------------------------------------------
# Binary attack: _binary_corrupt_tag_ordering
# ---------------------------------------------------------------------------


class TestBinaryCorruptTagOrdering:
    """Tests for StructureFuzzer._binary_corrupt_tag_ordering."""

    def test_returns_bytes(self):
        """Return type must be bytes."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_corrupt_tag_ordering(file_data)
        assert isinstance(result, bytes)

    def test_preserves_preamble_and_magic(self):
        """First 132 bytes must be unchanged."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_corrupt_tag_ordering(file_data)
        assert result[:_DATA_OFFSET] == file_data[:_DATA_OFFSET]

    def test_non_dicom_passthrough(self):
        """Non-DICOM bytes (no DICM magic) must be returned unchanged."""
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer._binary_corrupt_tag_ordering(garbage) is garbage

    def test_short_input_passthrough(self):
        """Input shorter than DATA_OFFSET + 4 returned unchanged."""
        fuzzer = StructureFuzzer()
        short = b"\x00" * 20
        assert fuzzer._binary_corrupt_tag_ordering(short) is short

    def test_produces_mutation_over_runs(self):
        """Over multiple runs at least one should produce different bytes."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        changed = any(
            fuzzer._binary_corrupt_tag_ordering(file_data) != file_data
            for _ in range(30)
        )
        assert changed, "No mutation produced in 30 runs"


# ---------------------------------------------------------------------------
# Binary attack: _binary_duplicate_tag
# ---------------------------------------------------------------------------


class TestBinaryDuplicateTag:
    """Tests for StructureFuzzer._binary_duplicate_tag."""

    def test_returns_bytes(self):
        """Return type must be bytes."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_duplicate_tag(file_data)
        assert isinstance(result, bytes)

    def test_output_longer_than_input(self):
        """Result must be longer (an element was duplicated)."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_duplicate_tag(file_data)
        assert len(result) > len(file_data)

    def test_preserves_preamble_and_magic(self):
        """First 132 bytes must be unchanged."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_duplicate_tag(file_data)
        assert result[:_DATA_OFFSET] == file_data[:_DATA_OFFSET]

    def test_non_dicom_passthrough(self):
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer._binary_duplicate_tag(garbage) is garbage

    def test_element_bytes_appear_twice(self):
        """The duplicated element bytes must appear at least twice in output."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        elements = _parse_dicom_elements(file_data, _DATA_OFFSET)
        assert len(elements) >= 2, "Need at least two elements for this test"

        src_start, src_end, _, _ = elements[0]
        elem_bytes = file_data[src_start:src_end]

        # Force src_idx=0, insert_after_idx=last element (integer index)
        with patch("random.randrange", return_value=0):
            with patch("random.choice", return_value=len(elements) - 1):
                result = fuzzer._binary_duplicate_tag(file_data)
        assert result.count(elem_bytes) >= 2


# ---------------------------------------------------------------------------
# Binary attack: _binary_corrupt_length_field
# ---------------------------------------------------------------------------


class TestBinaryCorruptLengthField:
    """Tests for StructureFuzzer._binary_corrupt_length_field."""

    def test_returns_bytes(self):
        """Return type must be bytes."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_corrupt_length_field(file_data)
        assert isinstance(result, bytes)

    def test_same_length_as_input(self):
        """Patching a length field does not change file size."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_corrupt_length_field(file_data)
        assert len(result) == len(file_data)

    def test_preamble_unchanged(self):
        """First 132 bytes must be unchanged."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_corrupt_length_field(file_data)
        assert result[:_DATA_OFFSET] == file_data[:_DATA_OFFSET]

    def test_bytes_differ_from_input(self):
        """At least one byte must differ (length field was patched)."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        changed = any(
            fuzzer._binary_corrupt_length_field(file_data) != file_data
            for _ in range(30)
        )
        assert changed, "No byte change produced in 30 runs"

    def test_non_dicom_passthrough(self):
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer._binary_corrupt_length_field(garbage) is garbage


# ---------------------------------------------------------------------------
# Binary attack: VR field corruption (4 variants)
# ---------------------------------------------------------------------------


VR_ATTACK_METHODS_AND_BYTES = [
    ("_binary_whitespace_vr", b"\x20\x0a"),
    ("_binary_null_vr", b"\x00\x00"),
    ("_binary_dash_vr", b"--"),
    ("_binary_vr_un_substitution", b"UN"),
]


class TestBinaryVrCorruption:
    """Shared tests for the 4 binary VR corruption attacks."""

    @pytest.mark.parametrize(
        ("method_name", "expected_vr"), VR_ATTACK_METHODS_AND_BYTES
    )
    def test_returns_bytes(self, method_name, expected_vr):
        """Each VR attack must return bytes."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        method = getattr(fuzzer, method_name)
        result = method(file_data)
        assert isinstance(result, bytes)

    @pytest.mark.parametrize(
        ("method_name", "expected_vr"), VR_ATTACK_METHODS_AND_BYTES
    )
    def test_length_preserved(self, method_name, expected_vr):
        """Output length must match input (VR rewrite is 1:1 byte substitution)."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        method = getattr(fuzzer, method_name)
        result = method(file_data)
        assert len(result) == len(file_data)

    @pytest.mark.parametrize(
        ("method_name", "expected_vr"), VR_ATTACK_METHODS_AND_BYTES
    )
    def test_preserves_preamble_and_magic(self, method_name, expected_vr):
        """First 132 bytes (preamble + DICM) must not be touched."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        method = getattr(fuzzer, method_name)
        result = method(file_data)
        assert result[:_DATA_OFFSET] == file_data[:_DATA_OFFSET]

    @pytest.mark.parametrize(
        ("method_name", "expected_vr"), VR_ATTACK_METHODS_AND_BYTES
    )
    def test_non_dicom_passthrough(self, method_name, expected_vr):
        """Non-DICOM bytes must be returned unchanged (identity)."""
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        method = getattr(fuzzer, method_name)
        assert method(garbage) is garbage

    @pytest.mark.parametrize(
        ("method_name", "expected_vr"), VR_ATTACK_METHODS_AND_BYTES
    )
    def test_short_input_passthrough(self, method_name, expected_vr):
        """Input shorter than DATA_OFFSET returned unchanged."""
        fuzzer = StructureFuzzer()
        short = b"\x00" * 20
        method = getattr(fuzzer, method_name)
        assert method(short) is short

    @pytest.mark.parametrize(
        ("method_name", "expected_vr"), VR_ATTACK_METHODS_AND_BYTES
    )
    def test_expected_vr_bytes_present(self, method_name, expected_vr):
        """After mutation the expected VR pattern must appear at a VR offset.

        Uses the ORIGINAL file's element offsets (because re-parsing the
        mutated file can misbehave -- e.g. UN substitution makes the parser
        treat the element as long-VR on the second pass). The mutations are
        length-preserving 2-byte rewrites, so VR offsets don't move.
        """
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        # Snapshot short-VR element offsets from the ORIGINAL bytes.
        vr_offsets = [
            elem_start + 4
            for elem_start, _, _, len_size in _parse_dicom_elements(
                file_data, _DATA_OFFSET
            )
            if len_size == 2
        ]
        assert vr_offsets, "fixture must contain short-VR elements"

        method = getattr(fuzzer, method_name)
        # Run up to 20 times to cover the random element selection
        found = False
        for _ in range(20):
            result = method(file_data)
            if result == file_data:
                continue
            if any(result[off : off + 2] == expected_vr for off in vr_offsets):
                found = True
                break
        assert found, (
            f"{method_name}: expected VR bytes {expected_vr!r} not found "
            f"at any original short-VR offset over 20 runs"
        )

    def test_un_substitution_never_targets_existing_un(self):
        """_binary_vr_un_substitution must not pick an element whose original VR is already UN.

        This guarantees every successful call produces a byte-level change.
        """
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        # Run many times -- the minimal fixture has no UN elements, so every
        # successful call must differ from the input.
        differs = any(
            fuzzer._binary_vr_un_substitution(file_data) != file_data for _ in range(10)
        )
        assert differs, "UN substitution produced no change in 10 runs"


# ---------------------------------------------------------------------------
# mutate_bytes integration
# ---------------------------------------------------------------------------


class TestMutateBytes:
    """Tests for StructureFuzzer.mutate_bytes."""

    def test_returns_bytes_type(self):
        """mutate_bytes must return bytes."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer.mutate_bytes(file_data)
        assert isinstance(result, bytes)

    def test_non_dicom_passthrough(self):
        """Non-DICOM input must be returned unchanged."""
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        result = fuzzer.mutate_bytes(garbage)
        assert result == garbage

    def test_short_input_passthrough(self):
        """Input shorter than minimum DICOM size returned unchanged."""
        fuzzer = StructureFuzzer()
        short = b"\x00" * 10
        assert fuzzer.mutate_bytes(short) == short

    def test_valid_input_produces_mutation(self):
        """Over many runs, at least one must differ from input."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        changed = any(fuzzer.mutate_bytes(file_data) != file_data for _ in range(50))
        assert changed, "mutate_bytes produced no changes in 50 runs"

    def test_base_class_returns_unchanged(self):
        """FormatFuzzerBase.mutate_bytes default must be a no-op."""
        from dicom_fuzzer.attacks.format.base import FormatFuzzerBase

        class _ConcreteNoOp(FormatFuzzerBase):
            def mutate(self, dataset):
                return dataset

            @property
            def strategy_name(self):
                return "noop"

        noop = _ConcreteNoOp()
        data = b"some data"
        assert noop.mutate_bytes(data) is data


class TestAppliedBinaryMutations:
    """Tests for _applied_binary_mutations side-channel on StructureFuzzer."""

    def test_populated_after_valid_dicom(self):
        """_applied_binary_mutations must be a non-empty list of strings after a successful call."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        populated = False
        for _ in range(50):
            fuzzer.mutate_bytes(file_data)
            if fuzzer._applied_binary_mutations:
                assert all(
                    isinstance(name, str) for name in fuzzer._applied_binary_mutations
                )
                populated = True
                break
        assert populated, "_applied_binary_mutations never populated in 50 runs"

    def test_cleared_on_each_call(self):
        """Each call to mutate_bytes() must reset _applied_binary_mutations (no accumulation)."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        # First call
        fuzzer.mutate_bytes(file_data)
        first_count = len(fuzzer._applied_binary_mutations)
        # Second call — list must reflect only the second call's attacks
        fuzzer.mutate_bytes(file_data)
        second_count = len(fuzzer._applied_binary_mutations)
        # Both counts must be in [0, 2]; if they accumulated the second would be > 2
        assert second_count <= 2, "accumulation detected: count exceeded maximum of 2"
        # The list is independent — not the sum of both calls
        assert first_count + second_count <= 4, (
            "sanity: each call selects at most 2 attacks"
        )


# ---------------------------------------------------------------------------
# Binary attack: G4 UL-as-US dimension type confusion
# ---------------------------------------------------------------------------


class TestBinaryDimensionVrUl:
    """Tests for _binary_dimension_vr_ul (Orthanc CVE-2026-5442)."""

    def test_returns_bytes(self):
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_dimension_vr_ul(file_data)
        assert isinstance(result, bytes)

    def test_length_preserved(self):
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_dimension_vr_ul(file_data)
        assert len(result) == len(file_data)

    def test_ul_present_at_dimension_tag(self):
        """VR 'UL' must appear at a Rows or Columns tag offset."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_dimension_vr_ul(file_data)
        rows_tag = b"\x28\x00\x10\x00"
        cols_tag = b"\x28\x00\x11\x00"
        found = False
        for tag_bytes in (rows_tag, cols_tag):
            idx = result.find(tag_bytes, _DATA_OFFSET)
            if idx >= 0 and result[idx + 4 : idx + 6] == b"UL":
                found = True
                break
        assert found, "UL not found at Rows or Columns VR offset"

    def test_non_dicom_passthrough(self):
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer._binary_dimension_vr_ul(garbage) is garbage


# ---------------------------------------------------------------------------
# Binary attack: G8 non-standard VR in file meta
# ---------------------------------------------------------------------------


class TestBinaryNonstandardVrMeta:
    """Tests for _binary_nonstandard_vr_meta (GDCM CVE-2026-3650)."""

    def test_returns_bytes(self):
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_nonstandard_vr_meta(file_data)
        assert isinstance(result, bytes)

    def test_length_preserved(self):
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_nonstandard_vr_meta(file_data)
        assert len(result) == len(file_data)

    def test_zz_present_in_meta_region(self):
        """'ZZ' must appear somewhere in the file meta region."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_nonstandard_vr_meta(file_data)
        # The file meta region starts at _DATA_OFFSET and extends until
        # the first non-0002 group. Since we just need to verify "ZZ"
        # was written, check it differs from the original and that "ZZ"
        # appears in the meta-plausible region (first ~200 bytes of data).
        assert result != file_data, "No mutation produced"
        meta_region = result[_DATA_OFFSET : _DATA_OFFSET + 300]
        assert b"ZZ" in meta_region, "ZZ not found in file meta region"

    def test_non_dicom_passthrough(self):
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer._binary_nonstandard_vr_meta(garbage) is garbage


# ---------------------------------------------------------------------------
# Binary attack: G10 duplicate tags in file meta
# ---------------------------------------------------------------------------


class TestBinaryDuplicateMetaTag:
    """Tests for _binary_duplicate_meta_tag (libdicom CVE-2024-24793/24794)."""

    def test_returns_bytes(self):
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_duplicate_meta_tag(file_data)
        assert isinstance(result, bytes)

    def test_output_longer_than_input(self):
        """Duplicating an element must grow the file."""
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_duplicate_meta_tag(file_data)
        assert len(result) > len(file_data)

    def test_preserves_preamble_and_magic(self):
        fuzzer = StructureFuzzer()
        file_data = _make_minimal_dicom_bytes()
        result = fuzzer._binary_duplicate_meta_tag(file_data)
        assert result[:_DATA_OFFSET] == file_data[:_DATA_OFFSET]

    def test_non_dicom_passthrough(self):
        fuzzer = StructureFuzzer()
        garbage = b"\x00" * 256
        assert fuzzer._binary_duplicate_meta_tag(garbage) is garbage
