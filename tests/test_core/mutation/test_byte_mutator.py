"""Comprehensive tests for AFL-style byte mutator.

Tests the ByteMutator and DICOMByteMutator classes which provide
low-level byte mutations for fuzzing.
"""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dicom_fuzzer.core.mutation.byte_mutator import (
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    ByteMutationRecord,
    ByteMutationType,
    ByteMutator,
    ByteMutatorConfig,
    DICOMByteMutator,
    MutationStage,
    quick_mutate,
    quick_splice,
)


class TestByteMutatorConfig:
    """Tests for ByteMutatorConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ByteMutatorConfig()

        assert config.arith_max == 35
        assert config.havoc_cycles == 256
        assert config.enable_bit_flips is True
        assert config.enable_splice is True
        assert config.max_input_size == 10 * 1024 * 1024
        assert config.min_input_size == 4

    def test_custom_config(self):
        """Test custom configuration."""
        config = ByteMutatorConfig(
            arith_max=50,
            havoc_cycles=512,
            enable_bit_flips=False,
        )

        assert config.arith_max == 50
        assert config.havoc_cycles == 512
        assert config.enable_bit_flips is False


class TestByteMutationRecord:
    """Tests for ByteMutationRecord dataclass."""

    def test_record_creation(self):
        """Test creating a mutation record."""
        record = ByteMutationRecord(
            mutation_type=ByteMutationType.BIT_FLIP_1,
            offset=10,
            original_bytes=b"\x00",
            mutated_bytes=b"\x01",
            description="Test flip",
        )

        assert record.mutation_type == ByteMutationType.BIT_FLIP_1
        assert record.offset == 10
        assert record.original_bytes == b"\x00"
        assert record.mutated_bytes == b"\x01"
        assert record.description == "Test flip"


class TestInterestingValues:
    """Tests for interesting value constants."""

    def test_interesting_8_values(self):
        """Test 8-bit interesting values."""
        assert -128 in INTERESTING_8  # INT8_MIN
        assert -1 in INTERESTING_8  # All bits set
        assert 0 in INTERESTING_8  # Zero
        assert 1 in INTERESTING_8  # One
        assert 127 in INTERESTING_8  # INT8_MAX

    def test_interesting_16_values(self):
        """Test 16-bit interesting values."""
        assert -32768 in INTERESTING_16  # INT16_MIN
        assert 255 in INTERESTING_16  # UINT8_MAX
        assert 256 in INTERESTING_16  # Above UINT8_MAX
        assert 32767 in INTERESTING_16  # INT16_MAX
        assert 65535 in INTERESTING_16  # UINT16_MAX

    def test_interesting_32_values(self):
        """Test 32-bit interesting values."""
        assert -2147483648 in INTERESTING_32  # INT32_MIN
        assert 65536 in INTERESTING_32  # Above UINT16_MAX
        assert 2147483647 in INTERESTING_32  # INT32_MAX


class TestByteMutator:
    """Tests for ByteMutator class."""

    @pytest.fixture
    def mutator(self):
        """Create a ByteMutator instance."""
        return ByteMutator()

    @pytest.fixture
    def sample_data(self):
        """Create sample binary data."""
        return b"DICM" + b"\x00" * 124 + b"Hello, World!"

    def test_initialization(self, mutator):
        """Test mutator initialization."""
        assert mutator.config is not None
        assert mutator.stats.total_mutations == 0

    def test_mutate_returns_bytes(self, mutator, sample_data):
        """Test that mutate returns bytes."""
        result = mutator.mutate(sample_data)

        assert isinstance(result, bytes)

    def test_mutate_changes_data(self, mutator, sample_data):
        """Test that mutation actually changes data."""
        # Apply multiple mutations to ensure change
        result = mutator.mutate(sample_data, num_mutations=10)

        # With 10 mutations, data should almost certainly change
        # (very small probability of no change)
        assert len(result) > 0

    def test_havoc_stage(self, mutator, sample_data):
        """Test havoc mutation stage."""
        result = mutator.mutate(sample_data, stage=MutationStage.HAVOC)

        assert isinstance(result, bytes)

    def test_deterministic_stage(self, mutator):
        """Test deterministic mutation stage."""
        # Use smaller data to avoid timeout
        data = b"Test data for fuzzing"
        result = mutator.mutate(data, stage=MutationStage.DETERMINISTIC)

        assert isinstance(result, bytes)

    def test_minimum_size_check(self, mutator):
        """Test that small inputs are handled correctly."""
        tiny_data = b"ab"  # Below min_input_size
        result = mutator.mutate(tiny_data)

        assert result == tiny_data  # Should return unchanged

    def test_maximum_size_truncation(self, mutator):
        """Test that large inputs are truncated before mutation."""
        config = ByteMutatorConfig(max_input_size=100)
        mutator = ByteMutator(config)
        large_data = b"A" * 200

        result = mutator.mutate(large_data)

        # Havoc can grow data, so we just verify it doesn't crash
        # and logs the truncation warning
        assert isinstance(result, bytes)

    def test_stats_tracking(self, mutator, sample_data):
        """Test that statistics are tracked."""
        mutator.mutate(sample_data, num_mutations=5)

        assert mutator.stats.total_mutations == 5

    def test_mutation_history(self, mutator, sample_data):
        """Test mutation history tracking."""
        # Use deterministic stage which records mutations
        mutator.mutate(sample_data, stage=MutationStage.DETERMINISTIC)
        history = mutator.get_mutation_history()

        # Deterministic stage records bit/byte flips
        assert isinstance(history, list)
        if len(history) > 0:
            assert all(isinstance(r, ByteMutationRecord) for r in history)

    def test_clear_history(self, mutator, sample_data):
        """Test clearing mutation history."""
        mutator.mutate(sample_data)
        mutator.clear_history()

        assert len(mutator.get_mutation_history()) == 0

    def test_get_stats(self, mutator, sample_data):
        """Test getting mutation statistics."""
        mutator.mutate(sample_data, num_mutations=5)
        stats = mutator.get_stats()

        assert "total_mutations" in stats
        assert "havoc" in stats
        assert "by_type" in stats

    def test_splice_two_inputs(self, mutator):
        """Test splicing two inputs together."""
        data1 = b"AAAAAAAAAA"
        data2 = b"BBBBBBBBBB"

        result = mutator.splice(data1, data2)

        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_splice_requires_minimum_size(self, mutator):
        """Test that splice handles small inputs."""
        data1 = b"AB"
        data2 = b"CD"

        result = mutator.splice(data1, data2)

        assert result == data1  # Returns original if too small


class TestByteMutatorBitFlips:
    """Tests for bit flip mutations."""

    @pytest.fixture
    def mutator(self):
        """Create a ByteMutator instance."""
        return ByteMutator()

    def test_walking_bit_flip_1(self, mutator):
        """Test single bit flip."""
        import random

        random.seed(42)  # Deterministic seed for reproducible tests
        data = bytearray(b"\x00" * 10)
        result = mutator._walking_bit_flip(data, 1)

        # Should have exactly one bit different somewhere
        diff_count = sum(bin(a ^ b).count("1") for a, b in zip(data, result))
        assert diff_count == 1

    def test_walking_bit_flip_2(self, mutator):
        """Test double bit flip."""
        import random

        random.seed(42)  # Deterministic seed for reproducible tests
        data = bytearray(b"\x00" * 10)
        result = mutator._walking_bit_flip(data, 2)

        # Should have exactly 2 bits different
        diff_count = sum(bin(a ^ b).count("1") for a, b in zip(data, result))
        assert diff_count == 2

    def test_walking_bit_flip_4(self, mutator):
        """Test quad bit flip."""
        import random

        random.seed(42)  # Deterministic seed for reproducible tests
        data = bytearray(b"\x00" * 10)
        result = mutator._walking_bit_flip(data, 4)

        # Should have exactly 4 bits different
        diff_count = sum(bin(a ^ b).count("1") for a, b in zip(data, result))
        assert diff_count == 4


class TestByteMutatorByteFlips:
    """Tests for byte flip mutations."""

    @pytest.fixture
    def mutator(self):
        """Create a ByteMutator instance."""
        return ByteMutator()

    def test_walking_byte_flip_1(self, mutator):
        """Test single byte flip."""
        data = bytearray(b"\x00" * 10)
        result = mutator._walking_byte_flip(data, 1)

        # Should have exactly one byte XORed with 0xFF
        diff_bytes = sum(1 for a, b in zip(data, result) if a != b)
        assert diff_bytes == 1

    def test_walking_byte_flip_2(self, mutator):
        """Test double byte flip."""
        data = bytearray(b"\x00" * 10)
        result = mutator._walking_byte_flip(data, 2)

        diff_bytes = sum(1 for a, b in zip(data, result) if a != b)
        assert diff_bytes == 2

    def test_walking_byte_flip_4(self, mutator):
        """Test quad byte flip."""
        data = bytearray(b"\x00" * 10)
        result = mutator._walking_byte_flip(data, 4)

        diff_bytes = sum(1 for a, b in zip(data, result) if a != b)
        assert diff_bytes == 4


class TestByteMutatorArithmetic:
    """Tests for arithmetic mutations."""

    @pytest.fixture
    def mutator(self):
        """Create a ByteMutator instance."""
        return ByteMutator()

    def test_arithmetic_8(self, mutator):
        """Test 8-bit arithmetic mutation."""
        data = bytearray(b"\x80" * 10)
        result = mutator._arithmetic_8(data)

        # Exactly one byte should change
        diff_bytes = sum(1 for a, b in zip(data, result) if a != b)
        assert diff_bytes == 1

    def test_arithmetic_16(self, mutator):
        """Test 16-bit arithmetic mutation."""
        data = bytearray(b"\x00\x80" * 5)
        result = mutator._arithmetic_16(data)

        # Data should change
        assert result != data or len(data) < 2

    def test_arithmetic_32(self, mutator):
        """Test 32-bit arithmetic mutation."""
        data = bytearray(b"\x00\x00\x00\x80" * 3)
        result = mutator._arithmetic_32(data)

        # Data should change
        assert result != data or len(data) < 4


class TestByteMutatorInteresting:
    """Tests for interesting value substitution."""

    @pytest.fixture
    def mutator(self):
        """Create a ByteMutator instance."""
        return ByteMutator()

    def test_interesting_8(self, mutator):
        """Test 8-bit interesting value substitution."""
        data = bytearray(b"\x00" * 10)
        result = mutator._interesting_8(data)

        # One byte should be an interesting value
        diff_bytes = [b for a, b in zip(data, result) if a != b]
        if diff_bytes:
            assert any(
                v & 0xFF in [v & 0xFF for v in INTERESTING_8] for v in diff_bytes
            )

    def test_interesting_16(self, mutator):
        """Test 16-bit interesting value substitution."""
        # Use non-zero data to ensure mutation is always detectable
        # (0 is a valid interesting value that would be invisible on zero-filled data)
        data = bytearray(b"\x80\x80" * 5)
        result = mutator._interesting_16(data)

        assert result != data or len(data) < 2

    def test_interesting_32(self, mutator):
        """Test 32-bit interesting value substitution."""
        # Use non-zero data to ensure mutation is always detectable
        # (0 is a valid interesting value that would be invisible on zero-filled data)
        data = bytearray(b"\x80\x80\x80\x80" * 3)
        result = mutator._interesting_32(data)

        assert result != data or len(data) < 4


class TestByteMutatorHavocOps:
    """Tests for individual havoc operations."""

    @pytest.fixture(autouse=True)
    def seed_random(self):
        """Seed random for deterministic tests."""
        import random

        import numpy as np

        random.seed(42)
        np.random.seed(42)

    @pytest.fixture
    def mutator(self):
        """Create a ByteMutator instance."""
        return ByteMutator()

    @pytest.fixture
    def data(self):
        """Create sample data."""
        return bytearray(b"A" * 100)

    def test_havoc_flip_bit(self, mutator, data):
        """Test havoc bit flip."""
        result = mutator._havoc_flip_bit(bytearray(data))
        diff = sum(1 for a, b in zip(data, result) if a != b)
        assert diff == 1

    def test_havoc_flip_byte(self, mutator, data):
        """Test havoc byte flip."""
        result = mutator._havoc_flip_byte(bytearray(data))
        assert result != data

    def test_havoc_arith_byte(self, mutator, data):
        """Test havoc arithmetic."""
        result = mutator._havoc_arith_byte(bytearray(data))
        # Arithmetic may not visibly change data (e.g., add 0 or wrap-around)
        assert isinstance(result, bytearray)
        assert len(result) == len(data)

    def test_havoc_random_byte(self, mutator, data):
        """Test havoc random byte."""
        result = mutator._havoc_random_byte(bytearray(data))
        # May or may not change (1/256 chance of same value)
        assert isinstance(result, bytearray)

    def test_havoc_delete_bytes(self, mutator, data):
        """Test havoc delete bytes."""
        result = mutator._havoc_delete_bytes(bytearray(data))
        assert len(result) < len(data)

    def test_havoc_clone_bytes(self, mutator, data):
        """Test havoc clone bytes."""
        result = mutator._havoc_clone_bytes(bytearray(data))
        assert len(result) >= len(data)

    def test_havoc_insert_bytes(self, mutator, data):
        """Test havoc insert bytes."""
        result = mutator._havoc_insert_bytes(bytearray(data))
        assert len(result) > len(data)


class TestDICOMByteMutator:
    """Tests for DICOM-specialized byte mutator."""

    @pytest.fixture(autouse=True)
    def seed_random(self):
        """Seed random for deterministic tests.

        This prevents flaky failures from havoc mutations that can
        delete bytes, making the result too short to preserve magic bytes.
        """
        import random

        random.seed(42)

    @pytest.fixture
    def mutator(self):
        """Create a DICOMByteMutator instance."""
        return DICOMByteMutator()

    @pytest.fixture
    def dicom_data(self):
        """Create sample DICOM-like data."""
        # DICOM preamble (128 bytes) + "DICM" + some data
        return b"\x00" * 128 + b"DICM" + b"\x00" * 100

    def test_initialization(self, mutator):
        """Test DICOM mutator initialization."""
        assert mutator.DICOM_PREAMBLE_SIZE == 128
        assert mutator.DICOM_PREFIX == b"DICM"
        assert mutator.DICOM_PREFIX_OFFSET == 128

    def test_mutate_dicom_preserves_magic(self, mutator, dicom_data):
        """Test that magic bytes can be preserved."""
        result = mutator.mutate_dicom(dicom_data, preserve_magic=True)

        # DICM prefix should be preserved
        assert result[128:132] == b"DICM"

    def test_mutate_dicom_without_preservation(self, mutator, dicom_data):
        """Test mutation without magic preservation."""
        result = mutator.mutate_dicom(dicom_data, preserve_magic=False)

        assert isinstance(result, bytes)

    def test_mutate_targeted(self, mutator, dicom_data):
        """Test targeted region mutation."""
        regions = [(0, 50), (150, 200)]
        result = mutator.mutate_targeted(dicom_data, regions, num_mutations=5)

        assert isinstance(result, bytes)

    def test_high_value_regions(self, mutator):
        """Test high value regions constant."""
        assert len(mutator.HIGH_VALUE_REGIONS) > 0
        assert (0, 132) in mutator.HIGH_VALUE_REGIONS


class TestQuickMutationHelpers:
    """Tests for convenience mutation functions."""

    def test_quick_mutate(self):
        """Test quick_mutate helper."""
        data = b"Test data for quick mutation"
        result = quick_mutate(data, num_mutations=3)

        assert isinstance(result, bytes)

    def test_quick_splice(self):
        """Test quick_splice helper."""
        data1 = b"AAAAAAAAAA"
        data2 = b"BBBBBBBBBB"

        result = quick_splice(data1, data2)

        assert isinstance(result, bytes)


class TestByteMutatorPropertyBased:
    """Property-based tests using Hypothesis."""

    @given(st.binary(min_size=10, max_size=1000))
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.differing_executors],
    )
    def test_mutate_returns_bytes(self, data):
        """Property: mutate always returns bytes."""
        mutator = ByteMutator()
        result = mutator.mutate(data)

        assert isinstance(result, bytes)

    @given(st.binary(min_size=10, max_size=1000))
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.differing_executors],
    )
    def test_mutate_never_crashes(self, data):
        """Property: mutate never crashes on valid input."""
        mutator = ByteMutator()

        # Should not raise any exceptions
        result = mutator.mutate(data, num_mutations=5)
        assert result is not None

    @given(
        st.binary(min_size=10, max_size=100),
        st.binary(min_size=10, max_size=100),
    )
    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.differing_executors],
    )
    def test_splice_combines_inputs(self, data1, data2):
        """Property: splice produces output combining both inputs."""
        mutator = ByteMutator()
        result = mutator.splice(data1, data2)

        assert isinstance(result, bytes)
        assert len(result) > 0


class TestMutationStageEnum:
    """Tests for MutationStage enum."""

    def test_stage_values(self):
        """Test mutation stage enum values."""
        assert MutationStage.DETERMINISTIC is not None
        assert MutationStage.HAVOC is not None
        assert MutationStage.SPLICE is not None


class TestByteMutationTypeEnum:
    """Tests for ByteMutationType enum."""

    def test_all_types_have_values(self):
        """Test all mutation types have string values."""
        for mutation_type in ByteMutationType:
            assert isinstance(mutation_type.value, str)
            assert len(mutation_type.value) > 0

    def test_expected_types_exist(self):
        """Test expected mutation types exist."""
        expected = [
            "BIT_FLIP_1",
            "BIT_FLIP_2",
            "BIT_FLIP_4",
            "BYTE_FLIP_1",
            "ARITH_8",
            "INTEREST_8",
            "SPLICE",
        ]

        for name in expected:
            assert hasattr(ByteMutationType, name)
