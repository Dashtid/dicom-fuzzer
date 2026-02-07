"""Tests for private_tag_fuzzer.py - Vendor-Specific Tag Mutations."""

import random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.attacks.format.private_tag_fuzzer import (
    KNOWN_CREATORS,
    MALICIOUS_CREATORS,
    PRIVATE_GROUPS,
    PrivateTagFuzzer,
)


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> PrivateTagFuzzer:
    """Create a PrivateTagFuzzer instance."""
    return PrivateTagFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Modality = "CT"
    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    return ds


# =============================================================================
# PrivateTagFuzzer Initialization Tests
# =============================================================================
class TestPrivateTagFuzzerInit:
    """Tests for PrivateTagFuzzer initialization."""

    def test_mutation_strategies_defined(self, fuzzer: PrivateTagFuzzer) -> None:
        """Test that mutation_strategies list is defined."""
        assert hasattr(fuzzer, "mutation_strategies")
        assert isinstance(fuzzer.mutation_strategies, list)
        assert len(fuzzer.mutation_strategies) == 10

    def test_all_strategies_callable(self, fuzzer: PrivateTagFuzzer) -> None:
        """Test that all strategies are callable methods."""
        for strategy in fuzzer.mutation_strategies:
            assert callable(strategy)


# =============================================================================
# mutate_private_tags Tests
# =============================================================================
class TestMutatePrivateTags:
    """Tests for mutate_private_tags method."""

    def test_returns_dataset(
        self, fuzzer: PrivateTagFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate_private_tags returns a Dataset."""
        result = fuzzer.mutate_private_tags(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_handles_empty_dataset(self, fuzzer: PrivateTagFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate_private_tags(ds)
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _missing_creator Tests
# =============================================================================
class TestMissingCreator:
    """Tests for _missing_creator method."""

    def test_adds_data_without_creator(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test adding private data without creator."""
        with patch.object(random, "choice", return_value=0x0009):
            result = fuzzer._missing_creator(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have private data tags
        assert Tag(0x0009, 0x1010) in result


# =============================================================================
# _wrong_creator Tests
# =============================================================================
class TestWrongCreator:
    """Tests for _wrong_creator method."""

    def test_adds_invalid_creator(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test adding private data with invalid creator."""
        with patch.object(random, "choice", side_effect=[0x0009, ""]):
            result = fuzzer._wrong_creator(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have creator and data
        assert Tag(0x0009, 0x0010) in result


# =============================================================================
# _creator_collision Tests
# =============================================================================
class TestCreatorCollision:
    """Tests for _creator_collision method."""

    def test_multiple_creators_same_block(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test multiple creators in same block."""
        with patch.object(
            random, "choice", side_effect=[0x0009, "multiple_creators_same_block"]
        ):
            result = fuzzer._creator_collision(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_creator_overwrites_data(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creator overwriting data."""
        with patch.object(
            random, "choice", side_effect=[0x0009, "creator_overwrites_data"]
        ):
            result = fuzzer._creator_collision(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_duplicate_creator_different_data(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test duplicate creator with different data."""
        with patch.object(
            random, "choice", side_effect=[0x0009, "duplicate_creator_different_data"]
        ):
            result = fuzzer._creator_collision(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _invalid_private_vr Tests
# =============================================================================
class TestInvalidPrivateVr:
    """Tests for _invalid_private_vr method."""

    def test_numeric_as_string(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test numeric data stored as string."""
        with patch.object(
            random, "choice", side_effect=[0x0009, "GEMS_GENIE_1", "numeric_as_string"]
        ):
            result = fuzzer._invalid_private_vr(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_string_as_binary(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test string data as binary."""
        with patch.object(
            random, "choice", side_effect=[0x0009, "GEMS_GENIE_1", "string_as_binary"]
        ):
            result = fuzzer._invalid_private_vr(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_sequence_where_primitive(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test sequence where primitive expected."""
        with patch.object(
            random,
            "choice",
            side_effect=[0x0009, "GEMS_GENIE_1", "sequence_where_primitive"],
        ):
            result = fuzzer._invalid_private_vr(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _oversized_private_data Tests
# =============================================================================
class TestOversizedPrivateData:
    """Tests for _oversized_private_data method."""

    def test_large_string(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test large string in private data."""
        with patch.object(random, "choice", side_effect=[0x0009, "large_string", 1000]):
            result = fuzzer._oversized_private_data(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_large_binary(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test large binary in private data."""
        with patch.object(random, "choice", side_effect=[0x0009, "large_binary", 1000]):
            result = fuzzer._oversized_private_data(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_many_elements(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test many private elements."""
        with patch.object(random, "choice", side_effect=[0x0009, "many_elements"]):
            result = fuzzer._oversized_private_data(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _private_tag_injection Tests
# =============================================================================
class TestPrivateTagInjection:
    """Tests for _private_tag_injection method."""

    def test_injects_payloads(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test injection of payloads."""
        with patch.object(random, "choice", return_value=0x0009):
            result = fuzzer._private_tag_injection(minimal_dataset)
        assert isinstance(result, Dataset)
        # Should have injection test creator
        assert Tag(0x0009, 0x0010) in result


# =============================================================================
# _creator_overwrite Tests
# =============================================================================
class TestCreatorOverwrite:
    """Tests for _creator_overwrite method."""

    def test_attempts_standard_group(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test attempting to use standard group as private."""
        result = fuzzer._creator_overwrite(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _reserved_group_attack Tests
# =============================================================================
class TestReservedGroupAttack:
    """Tests for _reserved_group_attack method."""

    def test_uses_reserved_groups(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test using reserved group numbers."""
        result = fuzzer._reserved_group_attack(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _private_sequence_attack Tests
# =============================================================================
class TestPrivateSequenceAttack:
    """Tests for _private_sequence_attack method."""

    def test_deeply_nested(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test deeply nested private sequence."""
        with patch.object(random, "choice", side_effect=[0x0009, "deeply_nested"]):
            result = fuzzer._private_sequence_attack(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_mixed_creators_in_items(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test mixed creators in items."""
        with patch.object(
            random, "choice", side_effect=[0x0009, "mixed_creators_in_items"]
        ):
            result = fuzzer._private_sequence_attack(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _binary_blob_injection Tests
# =============================================================================
class TestBinaryBlobInjection:
    """Tests for _binary_blob_injection method."""

    def test_injects_blobs(
        self, fuzzer: PrivateTagFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test injection of binary blobs."""
        with patch.object(random, "choice", return_value=0x0009):
            result = fuzzer._binary_blob_injection(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# Integration Tests
# =============================================================================
class TestPrivateTagFuzzerIntegration:
    """Integration tests for PrivateTagFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: PrivateTagFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate_private_tags(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_multiple_mutations(self, fuzzer: PrivateTagFuzzer) -> None:
        """Test multiple mutations in sequence."""
        for i in range(5):
            random.seed(i)
            ds = Dataset()
            ds.PatientName = "Test"
            result = fuzzer.mutate_private_tags(ds)
            assert isinstance(result, Dataset)

    def test_preserves_standard_tags(
        self, fuzzer: PrivateTagFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that standard tags are preserved."""
        original_name = sample_dataset.PatientName
        original_modality = sample_dataset.Modality
        random.seed(42)
        result = fuzzer.mutate_private_tags(sample_dataset)
        assert result.PatientName == original_name
        assert result.Modality == original_modality


# =============================================================================
# Module Constants Tests
# =============================================================================
class TestModuleConstants:
    """Tests for module-level constants."""

    def test_known_creators_not_empty(self) -> None:
        """Test KNOWN_CREATORS is not empty."""
        assert len(KNOWN_CREATORS) > 0
        assert all(isinstance(c, str) for c in KNOWN_CREATORS)

    def test_malicious_creators_not_empty(self) -> None:
        """Test MALICIOUS_CREATORS is not empty."""
        assert len(MALICIOUS_CREATORS) > 0

    def test_private_groups_are_odd(self) -> None:
        """Test PRIVATE_GROUPS are odd numbers."""
        for group in PRIVATE_GROUPS:
            assert group % 2 == 1, f"Group {group:04X} is not odd"
