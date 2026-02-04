"""Tests for sequence_fuzzer.py - DICOM Sequence and Item Structure Mutations."""

import random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag

from dicom_fuzzer.attacks.format.sequence_fuzzer import SequenceFuzzer


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> SequenceFuzzer:
    """Create a SequenceFuzzer instance."""
    return SequenceFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset with sequences."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7"

    # Add a simple sequence
    item = Dataset()
    item.add_new(Tag(0x0008, 0x0100), "SH", "TEST_CODE")
    item.add_new(Tag(0x0008, 0x0104), "LO", "Test Description")
    ds.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([item]))

    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset without sequences."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    return ds


# =============================================================================
# SequenceFuzzer Initialization Tests
# =============================================================================
class TestSequenceFuzzerInit:
    """Tests for SequenceFuzzer initialization."""

    def test_mutation_strategies_defined(self, fuzzer: SequenceFuzzer) -> None:
        """Test that mutation_strategies list is defined."""
        assert hasattr(fuzzer, "mutation_strategies")
        assert isinstance(fuzzer.mutation_strategies, list)
        assert len(fuzzer.mutation_strategies) == 8

    def test_all_strategies_callable(self, fuzzer: SequenceFuzzer) -> None:
        """Test that all strategies are callable methods."""
        for strategy in fuzzer.mutation_strategies:
            assert callable(strategy)


# =============================================================================
# mutate_sequences Tests
# =============================================================================
class TestMutateSequences:
    """Tests for mutate_sequences method."""

    def test_returns_dataset(
        self, fuzzer: SequenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate_sequences returns a Dataset."""
        result = fuzzer.mutate_sequences(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_applies_mutations(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test that mutations are applied to the dataset."""
        random.seed(42)
        result = fuzzer.mutate_sequences(minimal_dataset)
        # Should have added some sequences
        assert result is not None
        assert isinstance(result, Dataset)

    def test_handles_empty_dataset(self, fuzzer: SequenceFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate_sequences(ds)
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _deep_nesting_attack Tests
# =============================================================================
class TestDeepNestingAttack:
    """Tests for _deep_nesting_attack method."""

    def test_creates_nested_sequence(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test that deep nesting creates nested sequence."""
        with patch.object(random, "choice", return_value=10):  # Shallow for test
            result = fuzzer._deep_nesting_attack(minimal_dataset)

        assert isinstance(result, Dataset)
        # Should have ContentSequence
        content_seq_tag = Tag(0x0040, 0xA730)
        assert content_seq_tag in result

    def test_nesting_depth_varies(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test that nesting depth varies based on random choice."""
        depths = [50, 100, 500, 1000]
        for depth in depths:
            ds = Dataset()
            with patch.object(random, "choice", return_value=depth):
                result = fuzzer._deep_nesting_attack(ds)
            assert isinstance(result, Dataset)


# =============================================================================
# _item_length_mismatch Tests
# =============================================================================
class TestItemLengthMismatch:
    """Tests for _item_length_mismatch method."""

    def test_creates_sequence_if_none_exists(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test that method creates sequence if none exists."""
        result = fuzzer._item_length_mismatch(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have created ReferencedSeriesSequence
        ref_series_tag = Tag(0x0008, 0x1115)
        assert ref_series_tag in result

    def test_modifies_existing_sequence(
        self, fuzzer: SequenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test modification of existing sequence."""
        result = fuzzer._item_length_mismatch(sample_dataset)
        assert isinstance(result, Dataset)

    def test_attack_types(
        self, fuzzer: SequenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test different attack types."""
        attacks = ["overflow_length", "zero_length", "negative_length", "undefined_length_non_sq"]
        for attack in attacks:
            ds = Dataset()
            item = Dataset()
            item.add_new(Tag(0x0008, 0x0100), "SH", "CODE")
            ds.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([item]))

            with patch.object(random, "choice", side_effect=[
                (Tag(0x0008, 0x1115), ds[Tag(0x0008, 0x1115)]),
                attack
            ]):
                result = fuzzer._item_length_mismatch(ds)
            assert isinstance(result, Dataset)


# =============================================================================
# _empty_required_sequence Tests
# =============================================================================
class TestEmptyRequiredSequence:
    """Tests for _empty_required_sequence method."""

    def test_empty_sequence_attack(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test empty sequence attack."""
        with patch.object(random, "choice", side_effect=["empty_sequence", Tag(0x0008, 0x1115)]):
            result = fuzzer._empty_required_sequence(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_null_first_item_attack(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test null first item attack."""
        with patch.object(random, "choice", side_effect=["null_first_item", Tag(0x0008, 0x1115)]):
            result = fuzzer._empty_required_sequence(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_empty_nested_attack(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test empty nested sequence attack."""
        with patch.object(random, "choice", side_effect=["empty_nested", Tag(0x0008, 0x1115)]):
            result = fuzzer._empty_required_sequence(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _orphan_item_attack Tests
# =============================================================================
class TestOrphanItemAttack:
    """Tests for _orphan_item_attack method."""

    def test_creates_orphan_items(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of orphan items."""
        result = fuzzer._orphan_item_attack(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have private elements
        assert Tag(0x0009, 0x0010) in result or Tag(0x0009, 0x1000) in result


# =============================================================================
# _circular_reference_attack Tests
# =============================================================================
class TestCircularReferenceAttack:
    """Tests for _circular_reference_attack method."""

    def test_creates_circular_references(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of circular references."""
        result = fuzzer._circular_reference_attack(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have ReferencedImageSequence
        ref_image_tag = Tag(0x0008, 0x1140)
        assert ref_image_tag in result


# =============================================================================
# _delimiter_corruption Tests
# =============================================================================
class TestDelimiterCorruption:
    """Tests for _delimiter_corruption method."""

    def test_handles_no_sequences(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test handling when no sequences exist."""
        result = fuzzer._delimiter_corruption(minimal_dataset)
        assert result == minimal_dataset

    def test_corrupts_delimiters(
        self, fuzzer: SequenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test delimiter corruption in existing sequences."""
        result = fuzzer._delimiter_corruption(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _mixed_encoding_sequence Tests
# =============================================================================
class TestMixedEncodingSequence:
    """Tests for _mixed_encoding_sequence method."""

    def test_creates_mixed_encoding_items(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of items with mixed encodings."""
        result = fuzzer._mixed_encoding_sequence(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have RequestedProcedureCodeSequence
        proc_code_tag = Tag(0x0032, 0x1064)
        assert proc_code_tag in result


# =============================================================================
# _massive_item_count Tests
# =============================================================================
class TestMassiveItemCount:
    """Tests for _massive_item_count method."""

    def test_many_items_attack(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test many items attack."""
        with patch.object(random, "choice", side_effect=["many_items", 100]):
            result = fuzzer._massive_item_count(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_many_nested_items_attack(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test many nested items attack."""
        with patch.object(random, "choice", return_value="many_nested_items"):
            result = fuzzer._massive_item_count(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_items_with_large_data(
        self, fuzzer: SequenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test items with large data attack."""
        with patch.object(random, "choice", return_value="items_with_large_data"):
            result = fuzzer._massive_item_count(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# Integration Tests
# =============================================================================
class TestSequenceFuzzerIntegration:
    """Integration tests for SequenceFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: SequenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate_sequences(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_multiple_mutations_deterministic(
        self, fuzzer: SequenceFuzzer
    ) -> None:
        """Test that same seed produces same mutations."""
        random.seed(123)
        ds1 = Dataset()
        ds1.PatientName = "Test"
        result1 = fuzzer.mutate_sequences(ds1)

        random.seed(123)
        ds2 = Dataset()
        ds2.PatientName = "Test"
        result2 = fuzzer.mutate_sequences(ds2)

        # Both should have same structure
        assert set(result1.keys()) == set(result2.keys())

    def test_preserves_original_data(
        self, fuzzer: SequenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that original data is preserved."""
        original_name = sample_dataset.PatientName
        random.seed(42)
        result = fuzzer.mutate_sequences(sample_dataset)
        assert result.PatientName == original_name
