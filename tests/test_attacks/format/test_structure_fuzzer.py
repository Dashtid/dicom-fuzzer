"""Tests for structure_fuzzer.py - DICOM Structure Attacks.

Tests cover structure mutations and tag corruption.
"""

import io
import random
import struct
from unittest.mock import patch

import pydicom
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
