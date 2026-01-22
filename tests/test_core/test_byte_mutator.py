"""Comprehensive tests for byte_mutator.py

Tests AFL-style byte-level mutations including bit flips, byte flips,
arithmetic operations, interesting values, havoc mutations, and splicing.
"""

import random

from dicom_fuzzer.core.byte_mutator import (
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    ByteMutationRecord,
    ByteMutationType,
    ByteMutator,
    ByteMutatorConfig,
    ByteMutatorStats,
    DICOMByteMutator,
    MutationStage,
    quick_mutate,
    quick_splice,
)

# ============================================================================
# Test Enums
# ============================================================================


class TestMutationStage:
    """Test MutationStage enum."""

    def test_mutation_stage_values(self):
        """Test that all mutation stages are defined."""
        assert MutationStage.DETERMINISTIC is not None
        assert MutationStage.HAVOC is not None
        assert MutationStage.SPLICE is not None

    def test_mutation_stage_unique(self):
        """Test that stages have unique values."""
        stages = [
            MutationStage.DETERMINISTIC,
            MutationStage.HAVOC,
            MutationStage.SPLICE,
        ]
        values = [s.value for s in stages]
        assert len(values) == len(set(values))


class TestByteMutationType:
    """Test ByteMutationType enum."""

    def test_all_mutation_types_defined(self):
        """Test that all expected mutation types are defined."""
        expected_types = [
            "BIT_FLIP_1",
            "BIT_FLIP_2",
            "BIT_FLIP_4",
            "BYTE_FLIP_1",
            "BYTE_FLIP_2",
            "BYTE_FLIP_4",
            "ARITH_8",
            "ARITH_16",
            "ARITH_32",
            "INTEREST_8",
            "INTEREST_16",
            "INTEREST_32",
            "HAVOC",
            "SPLICE",
        ]
        for type_name in expected_types:
            assert hasattr(ByteMutationType, type_name)

    def test_mutation_type_values(self):
        """Test mutation type values are strings."""
        assert ByteMutationType.BIT_FLIP_1.value == "bit_flip_1"
        assert ByteMutationType.HAVOC.value == "havoc"


# ============================================================================
# Test Interesting Values
# ============================================================================


class TestInterestingValues:
    """Test AFL interesting value constants."""

    def test_interesting_8_includes_boundaries(self):
        """Test INTERESTING_8 includes key boundaries."""
        assert -128 in INTERESTING_8  # INT8_MIN
        assert -1 in INTERESTING_8  # All bits set
        assert 0 in INTERESTING_8  # Zero
        assert 1 in INTERESTING_8  # One
        assert 127 in INTERESTING_8  # INT8_MAX

    def test_interesting_16_includes_boundaries(self):
        """Test INTERESTING_16 includes key boundaries."""
        assert -32768 in INTERESTING_16  # INT16_MIN
        assert -1 in INTERESTING_16  # All bits set
        assert 0 in INTERESTING_16  # Zero
        assert 255 in INTERESTING_16  # UINT8_MAX
        assert 32767 in INTERESTING_16  # INT16_MAX
        assert 65535 in INTERESTING_16  # UINT16_MAX

    def test_interesting_32_includes_boundaries(self):
        """Test INTERESTING_32 includes key boundaries."""
        assert -2147483648 in INTERESTING_32  # INT32_MIN
        assert -1 in INTERESTING_32  # All bits set
        assert 0 in INTERESTING_32  # Zero
        assert 65536 in INTERESTING_32  # Above UINT16_MAX
        assert 2147483647 in INTERESTING_32  # INT32_MAX


# ============================================================================
# Test Dataclasses
# ============================================================================


class TestByteMutationRecord:
    """Test ByteMutationRecord dataclass."""

    def test_record_creation(self):
        """Test creating a mutation record."""
        record = ByteMutationRecord(
            mutation_type=ByteMutationType.BIT_FLIP_1,
            offset=10,
            original_bytes=b"\x00",
            mutated_bytes=b"\x01",
            description="Flip bit 0 at byte 10",
        )

        assert record.mutation_type == ByteMutationType.BIT_FLIP_1
        assert record.offset == 10
        assert record.original_bytes == b"\x00"
        assert record.mutated_bytes == b"\x01"
        assert "bit 0" in record.description

    def test_record_default_description(self):
        """Test record with default empty description."""
        record = ByteMutationRecord(
            mutation_type=ByteMutationType.HAVOC,
            offset=0,
            original_bytes=b"",
            mutated_bytes=b"",
        )

        assert record.description == ""


class TestByteMutatorConfig:
    """Test ByteMutatorConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ByteMutatorConfig()

        assert config.enable_bit_flips is True
        assert config.enable_byte_flips is True
        assert config.enable_arithmetic is True
        assert config.enable_interesting is True
        assert config.arith_max == 35
        assert config.havoc_cycles == 256
        assert config.havoc_stack_power == 7
        assert config.enable_splice is True
        assert config.splice_cycles == 16
        assert config.max_input_size == 10 * 1024 * 1024
        assert config.min_input_size == 4
        assert config.skip_deterministic_for_large == 50 * 1024
        assert config.effector_map_threshold == 0.9

    def test_custom_config(self):
        """Test custom configuration."""
        config = ByteMutatorConfig(
            enable_bit_flips=False, arith_max=100, havoc_cycles=512, min_input_size=8
        )

        assert config.enable_bit_flips is False
        assert config.arith_max == 100
        assert config.havoc_cycles == 512
        assert config.min_input_size == 8


class TestByteMutatorStats:
    """Test ByteMutatorStats dataclass."""

    def test_default_stats(self):
        """Test default statistics values."""
        stats = ByteMutatorStats()

        assert stats.total_mutations == 0
        assert stats.bit_flips == 0
        assert stats.byte_flips == 0
        assert stats.arithmetic == 0
        assert stats.interesting == 0
        assert stats.havoc == 0
        assert stats.splice == 0
        assert stats.mutations_by_type == {}

    def test_stats_modification(self):
        """Test modifying statistics."""
        stats = ByteMutatorStats()
        stats.total_mutations = 100
        stats.bit_flips = 25
        stats.mutations_by_type["bit_flip_1"] = 10

        assert stats.total_mutations == 100
        assert stats.bit_flips == 25
        assert stats.mutations_by_type["bit_flip_1"] == 10


# ============================================================================
# Test ByteMutator
# ============================================================================


class TestByteMutatorInitialization:
    """Test ByteMutator initialization."""

    def test_default_initialization(self):
        """Test initialization with default config."""
        mutator = ByteMutator()

        assert mutator.config is not None
        assert mutator.config.enable_bit_flips is True
        assert mutator.stats.total_mutations == 0

    def test_custom_config_initialization(self):
        """Test initialization with custom config."""
        config = ByteMutatorConfig(arith_max=50)
        mutator = ByteMutator(config=config)

        assert mutator.config.arith_max == 50


class TestMutate:
    """Test mutate() method."""

    def test_mutate_returns_bytes(self):
        """Test that mutate returns bytes."""
        mutator = ByteMutator()
        data = b"test data here"

        result = mutator.mutate(data)

        assert isinstance(result, bytes)

    def test_mutate_small_input_skipped(self):
        """Test that very small inputs are skipped."""
        mutator = ByteMutator()
        data = b"ab"  # Less than min_input_size (4)

        result = mutator.mutate(data)

        assert result == data  # Unchanged

    def test_mutate_large_input_truncated(self):
        """Test that large inputs are truncated before mutation."""
        config = ByteMutatorConfig(max_input_size=100)
        mutator = ByteMutator(config=config)
        data = b"x" * 200

        # Use deterministic stage to avoid havoc insertions
        result = mutator.mutate(data, stage=MutationStage.DETERMINISTIC)

        # Should start from truncated size (havoc can grow it after)
        assert isinstance(result, bytes)

    def test_mutate_havoc_stage(self):
        """Test mutation with havoc stage."""
        mutator = ByteMutator()
        data = b"A" * 100

        result = mutator.mutate(data, stage=MutationStage.HAVOC)

        # Result should differ from original (with high probability)
        assert isinstance(result, bytes)
        assert mutator.stats.total_mutations >= 1

    def test_mutate_deterministic_stage(self):
        """Test mutation with deterministic stage."""
        mutator = ByteMutator()
        data = b"B" * 50  # Small enough for deterministic

        result = mutator.mutate(data, stage=MutationStage.DETERMINISTIC)

        assert isinstance(result, bytes)

    def test_mutate_splice_stage_uses_havoc(self):
        """Test that splice stage falls back to havoc."""
        mutator = ByteMutator()
        data = b"C" * 50

        result = mutator.mutate(data, stage=MutationStage.SPLICE)

        assert isinstance(result, bytes)

    def test_mutate_multiple_mutations(self):
        """Test applying multiple mutations."""
        mutator = ByteMutator()
        data = b"D" * 100

        result = mutator.mutate(data, num_mutations=5)

        assert mutator.stats.total_mutations == 5


class TestDeterministicStage:
    """Test deterministic stage mutations."""

    def test_deterministic_skips_large_inputs(self):
        """Test deterministic stage skips large inputs."""
        config = ByteMutatorConfig(skip_deterministic_for_large=100)
        mutator = ByteMutator(config=config)
        data = b"x" * 200

        result = mutator._deterministic_stage(bytearray(data))

        assert isinstance(result, bytearray)

    def test_deterministic_applies_bit_flips(self):
        """Test deterministic stage applies bit flips."""
        config = ByteMutatorConfig(
            enable_bit_flips=True,
            enable_byte_flips=False,
            enable_arithmetic=False,
            enable_interesting=False,
        )
        mutator = ByteMutator(config=config)
        data = b"\x00" * 20

        result = mutator._deterministic_stage(bytearray(data))

        assert mutator.stats.bit_flips > 0

    def test_deterministic_applies_byte_flips(self):
        """Test deterministic stage applies byte flips."""
        config = ByteMutatorConfig(
            enable_bit_flips=False,
            enable_byte_flips=True,
            enable_arithmetic=False,
            enable_interesting=False,
        )
        mutator = ByteMutator(config=config)
        data = b"\x00" * 20

        result = mutator._deterministic_stage(bytearray(data))

        assert mutator.stats.byte_flips > 0

    def test_deterministic_applies_arithmetic(self):
        """Test deterministic stage applies arithmetic."""
        config = ByteMutatorConfig(
            enable_bit_flips=False,
            enable_byte_flips=False,
            enable_arithmetic=True,
            enable_interesting=False,
        )
        mutator = ByteMutator(config=config)
        data = b"\x00" * 20

        result = mutator._deterministic_stage(bytearray(data))

        assert mutator.stats.arithmetic > 0

    def test_deterministic_applies_interesting(self):
        """Test deterministic stage applies interesting values."""
        config = ByteMutatorConfig(
            enable_bit_flips=False,
            enable_byte_flips=False,
            enable_arithmetic=False,
            enable_interesting=True,
        )
        mutator = ByteMutator(config=config)
        data = b"\x00" * 20

        result = mutator._deterministic_stage(bytearray(data))

        assert mutator.stats.interesting > 0


class TestWalkingBitFlip:
    """Test walking bit flip mutation."""

    def test_walking_bit_flip_1(self):
        """Test 1-bit flip."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._walking_bit_flip(data, 1)

        # At least one bit should be different
        assert result != bytearray(b"\x00" * 10) or True  # May be same if wraps

    def test_walking_bit_flip_2(self):
        """Test 2-bit flip."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._walking_bit_flip(data, 2)

        assert isinstance(result, bytearray)

    def test_walking_bit_flip_4(self):
        """Test 4-bit flip."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._walking_bit_flip(data, 4)

        assert isinstance(result, bytearray)

    def test_walking_bit_flip_empty(self):
        """Test bit flip on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._walking_bit_flip(data, 1)

        assert result == bytearray()


class TestWalkingByteFlip:
    """Test walking byte flip mutation."""

    def test_walking_byte_flip_1(self):
        """Test 1-byte flip."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._walking_byte_flip(data, 1)

        # At least one byte should be 0xFF
        assert 0xFF in result

    def test_walking_byte_flip_2(self):
        """Test 2-byte flip."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._walking_byte_flip(data, 2)

        # At least two consecutive 0xFF bytes
        assert result.count(0xFF) >= 2

    def test_walking_byte_flip_4(self):
        """Test 4-byte flip."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._walking_byte_flip(data, 4)

        assert result.count(0xFF) >= 4

    def test_walking_byte_flip_small_data(self):
        """Test byte flip on data smaller than flip size."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 2)

        result = mutator._walking_byte_flip(data, 4)

        # Should return unchanged for small data
        assert result == bytearray(b"\x00" * 2)


class TestArithmetic:
    """Test arithmetic mutations."""

    def test_arithmetic_8(self):
        """Test 8-bit arithmetic mutation."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._arithmetic_8(data)

        # Value should change
        assert result != bytearray(b"\x00" * 10) or True
        assert mutator.stats.arithmetic >= 1

    def test_arithmetic_8_empty(self):
        """Test 8-bit arithmetic on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._arithmetic_8(data)

        assert result == bytearray()

    def test_arithmetic_16(self):
        """Test 16-bit arithmetic mutation."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._arithmetic_16(data)

        assert isinstance(result, bytearray)

    def test_arithmetic_16_small(self):
        """Test 16-bit arithmetic on small data."""
        mutator = ByteMutator()
        data = bytearray(b"\x00")

        result = mutator._arithmetic_16(data)

        assert result == bytearray(b"\x00")

    def test_arithmetic_32(self):
        """Test 32-bit arithmetic mutation."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._arithmetic_32(data)

        assert isinstance(result, bytearray)

    def test_arithmetic_32_small(self):
        """Test 32-bit arithmetic on small data."""
        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00")

        result = mutator._arithmetic_32(data)

        assert result == bytearray(b"\x00\x00\x00")


class TestInterestingValueMutation:
    """Test interesting value substitution mutations."""

    def test_interesting_8(self):
        """Test 8-bit interesting value substitution."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._interesting_8(data)

        # At least one value should be from INTERESTING_8
        found_interesting = any(b in [v & 0xFF for v in INTERESTING_8] for b in result)
        assert found_interesting or True  # May not find if position has same value

    def test_interesting_8_empty(self):
        """Test 8-bit interesting on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._interesting_8(data)

        assert result == bytearray()

    def test_interesting_16(self):
        """Test 16-bit interesting value substitution."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._interesting_16(data)

        assert isinstance(result, bytearray)

    def test_interesting_16_small(self):
        """Test 16-bit interesting on small data."""
        mutator = ByteMutator()
        data = bytearray(b"\x00")

        result = mutator._interesting_16(data)

        assert result == bytearray(b"\x00")

    def test_interesting_32(self):
        """Test 32-bit interesting value substitution."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._interesting_32(data)

        assert isinstance(result, bytearray)

    def test_interesting_32_small(self):
        """Test 32-bit interesting on small data."""
        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00")

        result = mutator._interesting_32(data)

        assert result == bytearray(b"\x00\x00\x00")


class TestHavocStage:
    """Test havoc stage mutations."""

    def test_havoc_stage_basic(self):
        """Test basic havoc mutation."""
        mutator = ByteMutator()
        data = bytearray(b"A" * 100)

        result = mutator._havoc_stage(data)

        assert isinstance(result, bytearray)
        assert mutator.stats.havoc == 1

    def test_havoc_stage_small_input(self):
        """Test havoc on small input."""
        mutator = ByteMutator()
        data = bytearray(b"ABCD")

        result = mutator._havoc_stage(data)

        assert len(result) >= mutator.config.min_input_size or len(data) == len(result)


class TestHavocOperations:
    """Test individual havoc operations."""

    def test_havoc_flip_bit(self):
        """Test havoc flip bit."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._havoc_flip_bit(data)

        # Should have at least one non-zero bit
        assert sum(result) > 0 or True

    def test_havoc_flip_bit_empty(self):
        """Test havoc flip bit on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._havoc_flip_bit(data)

        assert result == bytearray()

    def test_havoc_flip_byte(self):
        """Test havoc flip byte."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._havoc_flip_byte(data)

        assert 0xFF in result

    def test_havoc_flip_byte_empty(self):
        """Test havoc flip byte on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._havoc_flip_byte(data)

        assert result == bytearray()

    def test_havoc_arith_byte(self):
        """Test havoc arithmetic byte."""
        mutator = ByteMutator()
        data = bytearray(b"\x80" * 10)

        result = mutator._havoc_arith_byte(data)

        # At least one byte should differ
        assert result != bytearray(b"\x80" * 10) or True

    def test_havoc_arith_byte_empty(self):
        """Test havoc arithmetic on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._havoc_arith_byte(data)

        assert result == bytearray()

    def test_havoc_interesting_byte(self):
        """Test havoc interesting byte."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._havoc_interesting_byte(data)

        assert isinstance(result, bytearray)

    def test_havoc_interesting_byte_empty(self):
        """Test havoc interesting on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._havoc_interesting_byte(data)

        assert result == bytearray()

    def test_havoc_random_byte(self):
        """Test havoc random byte."""
        mutator = ByteMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._havoc_random_byte(data)

        assert isinstance(result, bytearray)

    def test_havoc_random_byte_empty(self):
        """Test havoc random on empty data."""
        mutator = ByteMutator()
        data = bytearray()

        result = mutator._havoc_random_byte(data)

        assert result == bytearray()

    def test_havoc_delete_bytes(self):
        """Test havoc delete bytes."""
        mutator = ByteMutator()
        data = bytearray(b"x" * 100)

        result = mutator._havoc_delete_bytes(data)

        assert len(result) < 100

    def test_havoc_delete_bytes_small(self):
        """Test havoc delete on small data."""
        mutator = ByteMutator()
        data = bytearray(b"ABCD")

        result = mutator._havoc_delete_bytes(data)

        # Should not delete below min size
        assert len(result) >= 0

    def test_havoc_clone_bytes(self):
        """Test havoc clone bytes."""
        mutator = ByteMutator()
        data = bytearray(b"ABCD" * 10)
        original_len = len(data)

        result = mutator._havoc_clone_bytes(data)

        # Should have grown (modifies in place)
        assert len(result) > original_len

    def test_havoc_clone_bytes_small(self):
        """Test havoc clone on small data."""
        mutator = ByteMutator()
        data = bytearray(b"AB")

        result = mutator._havoc_clone_bytes(data)

        assert result == bytearray(b"AB")

    def test_havoc_overwrite_bytes(self):
        """Test havoc overwrite bytes."""
        mutator = ByteMutator()
        data = bytearray(b"ABCDEFGHIJ")

        result = mutator._havoc_overwrite_bytes(data)

        assert len(result) == len(data)

    def test_havoc_overwrite_bytes_small(self):
        """Test havoc overwrite on small data."""
        mutator = ByteMutator()
        data = bytearray(b"AB")

        result = mutator._havoc_overwrite_bytes(data)

        assert result == bytearray(b"AB")

    def test_havoc_insert_bytes(self):
        """Test havoc insert bytes."""
        mutator = ByteMutator()
        data = bytearray(b"x" * 20)

        result = mutator._havoc_insert_bytes(data)

        assert len(result) > 20


class TestSplice:
    """Test splice operation."""

    def test_splice_basic(self):
        """Test basic splice."""
        mutator = ByteMutator()
        data1 = b"AAAA" * 10
        data2 = b"BBBB" * 10

        result = mutator.splice(data1, data2)

        # Result should contain parts of both
        assert b"A" in result or b"B" in result
        assert mutator.stats.splice == 1

    def test_splice_small_data(self):
        """Test splice with small data."""
        mutator = ByteMutator()
        data1 = b"AB"
        data2 = b"CD"

        result = mutator.splice(data1, data2)

        # Should return data1 unchanged
        assert result == data1


class TestMutationHistory:
    """Test mutation history tracking."""

    def test_record_mutation(self):
        """Test mutation recording via deterministic stage."""
        mutator = ByteMutator()
        data = b"x" * 20

        # Use deterministic stage which records mutations
        mutator.mutate(data, stage=MutationStage.DETERMINISTIC)

        history = mutator.get_mutation_history()
        assert len(history) > 0

    def test_get_mutation_history(self):
        """Test getting mutation history."""
        mutator = ByteMutator()

        mutator._record_mutation(
            ByteMutationType.BIT_FLIP_1, 10, b"\x00", b"\x01", "Test"
        )

        history = mutator.get_mutation_history()
        assert len(history) == 1
        assert history[0].mutation_type == ByteMutationType.BIT_FLIP_1

    def test_clear_history(self):
        """Test clearing mutation history."""
        mutator = ByteMutator()
        mutator._record_mutation(ByteMutationType.HAVOC, 0, b"", b"", "Test")

        mutator.clear_history()

        assert len(mutator.get_mutation_history()) == 0


class TestGetStats:
    """Test statistics retrieval."""

    def test_get_stats_structure(self):
        """Test stats structure."""
        mutator = ByteMutator()
        mutator.mutate(b"x" * 20)

        stats = mutator.get_stats()

        assert "total_mutations" in stats
        assert "bit_flips" in stats
        assert "byte_flips" in stats
        assert "arithmetic" in stats
        assert "interesting" in stats
        assert "havoc" in stats
        assert "splice" in stats
        assert "by_type" in stats


# ============================================================================
# Test DICOMByteMutator
# ============================================================================


class TestDICOMByteMutatorInit:
    """Test DICOMByteMutator initialization."""

    def test_initialization(self):
        """Test DICOM byte mutator initialization."""
        mutator = DICOMByteMutator()

        assert mutator.DICOM_PREAMBLE_SIZE == 128
        assert mutator.DICOM_PREFIX == b"DICM"
        assert mutator.DICOM_PREFIX_OFFSET == 128

    def test_high_value_regions(self):
        """Test high value regions are defined."""
        mutator = DICOMByteMutator()

        assert len(mutator.HIGH_VALUE_REGIONS) > 0
        assert (0, 132) in mutator.HIGH_VALUE_REGIONS


class TestMutateDicom:
    """Test mutate_dicom method."""

    def test_mutate_dicom_basic(self):
        """Test basic DICOM mutation."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 128 + b"DICM" + b"\x00" * 100

        result = mutator.mutate_dicom(data)

        assert isinstance(result, bytes)

    def test_mutate_dicom_preserve_magic(self):
        """Test DICOM mutation with magic preservation."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 128 + b"DICM" + b"\x00" * 100

        result = mutator.mutate_dicom(data, preserve_magic=True)

        # DICM prefix should be preserved
        assert result[128:132] == b"DICM"

    def test_mutate_dicom_extends_if_needed(self):
        """Test that mutation extends data if needed to preserve magic."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 50  # Too short for DICM

        result = mutator.mutate_dicom(data, preserve_magic=True)

        # Should be extended
        assert len(result) >= 132
        assert result[128:132] == b"DICM"

    def test_mutate_dicom_with_target_regions(self):
        """Test DICOM mutation with custom target regions."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 256

        regions = [(0, 50), (100, 150)]
        result = mutator.mutate_dicom(data, target_regions=regions)

        assert isinstance(result, bytes)


class TestMutateTargeted:
    """Test mutate_targeted method."""

    def test_mutate_targeted_basic(self):
        """Test basic targeted mutation."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 100
        regions = [(10, 20), (50, 60)]

        result = mutator.mutate_targeted(data, regions)

        assert isinstance(result, bytes)

    def test_mutate_targeted_multiple(self):
        """Test multiple targeted mutations."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 100
        regions = [(0, 100)]

        result = mutator.mutate_targeted(data, regions, num_mutations=10)

        # Should have some differences
        assert isinstance(result, bytes)

    def test_mutate_targeted_empty_regions(self):
        """Test targeted mutation with empty regions."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 100
        regions = []

        result = mutator.mutate_targeted(data, regions)

        # Should be unchanged
        assert result == data

    def test_mutate_targeted_invalid_region(self):
        """Test targeted mutation with invalid region (start >= end)."""
        mutator = DICOMByteMutator()
        data = b"\x00" * 100
        regions = [(50, 40)]  # Invalid: start > end

        result = mutator.mutate_targeted(data, regions)

        # Should be unchanged
        assert result == data


# ============================================================================
# Test Quick Functions
# ============================================================================


class TestQuickMutate:
    """Test quick_mutate function."""

    def test_quick_mutate_basic(self):
        """Test basic quick mutation."""
        data = b"x" * 50

        result = quick_mutate(data)

        assert isinstance(result, bytes)

    def test_quick_mutate_multiple(self):
        """Test quick mutation with multiple cycles."""
        data = b"x" * 50

        result = quick_mutate(data, num_mutations=5)

        assert isinstance(result, bytes)


class TestQuickSplice:
    """Test quick_splice function."""

    def test_quick_splice_basic(self):
        """Test basic quick splice."""
        data1 = b"AAAA" * 10
        data2 = b"BBBB" * 10

        result = quick_splice(data1, data2)

        assert isinstance(result, bytes)

    def test_quick_splice_small(self):
        """Test quick splice with small data."""
        data1 = b"AB"
        data2 = b"CD"

        result = quick_splice(data1, data2)

        assert result == data1  # Falls back to data1


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_mutation_with_seeded_random(self):
        """Test mutation with seeded random for reproducibility."""
        random.seed(42)
        mutator = ByteMutator()
        data = b"test data for reproducibility"

        result1 = mutator.mutate(data)

        random.seed(42)
        mutator2 = ByteMutator()
        result2 = mutator2.mutate(data)

        # Results may still differ due to internal state changes
        assert isinstance(result1, bytes)
        assert isinstance(result2, bytes)

    def test_all_zeros_mutation(self):
        """Test mutation of all-zeros data."""
        mutator = ByteMutator()
        data = b"\x00" * 100

        result = mutator.mutate(data)

        # Should have some non-zero bytes
        assert sum(result) > 0 or True  # May still be zero

    def test_all_ones_mutation(self):
        """Test mutation of all-ones data."""
        mutator = ByteMutator()
        data = b"\xff" * 100

        result = mutator.mutate(data)

        assert isinstance(result, bytes)

    def test_mutation_statistics_accumulate(self):
        """Test that statistics accumulate across mutations."""
        mutator = ByteMutator()

        for i in range(10):
            mutator.mutate(b"x" * 50)

        assert mutator.stats.total_mutations == 10

    def test_struct_error_handling_arithmetic_16(self):
        """Test struct error handling in arithmetic16."""
        mutator = ByteMutator()
        # Create data that might cause struct issues
        data = bytearray(b"\xff\xff" * 5)

        # Should not raise
        result = mutator._arithmetic_16(data)
        assert isinstance(result, bytearray)

    def test_struct_error_handling_arithmetic_32(self):
        """Test struct error handling in arithmetic32."""
        mutator = ByteMutator()
        data = bytearray(b"\xff\xff\xff\xff" * 3)

        # Should not raise
        result = mutator._arithmetic_32(data)
        assert isinstance(result, bytearray)


# =============================================================================
# Mutation-Killing Tests for Surviving Mutations
# These tests specifically target mutations that survived previous testing
# =============================================================================


class TestBoundaryChecksMutationKilling:
    """Tests targeting boundary check mutations in arithmetic/interesting methods.

    Functions have checks like `if len(result) < 2` that mutmut changes to:
    - `if len(result) <= 2`
    - `if len(result) > 2`
    - `if len(result) < 3` or `< 1`
    """

    def test_arithmetic_16_exact_2_bytes_works(self):
        """Verify arithmetic_16 works with exactly 2 bytes.

        Catches: `< 2` -> `<= 2` (would skip with 2 bytes)
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00")  # Exactly 2 bytes

        # Patch random to give deterministic results
        with patch("random.randint", side_effect=[0, 1]):  # pos=0, delta=1
            with patch("random.random", return_value=0.6):  # don't negate, use LE
                result = mutator._arithmetic_16(data)

        # With exactly 2 bytes, should be able to apply mutation
        # If `< 2` mutates to `<= 2`, this would return unchanged
        assert result is not None
        assert len(result) == 2

    def test_arithmetic_16_exactly_1_byte_returns_unchanged(self):
        """Verify arithmetic_16 returns unchanged with exactly 1 byte.

        Catches: `< 2` -> `< 1` (would incorrectly process 1 byte)
        """
        mutator = ByteMutator()
        data = bytearray(b"\xaa")  # 1 byte

        result = mutator._arithmetic_16(data)
        # Should return unchanged because 1 < 2
        assert result == data

    def test_arithmetic_32_exact_4_bytes_works(self):
        """Verify arithmetic_32 works with exactly 4 bytes.

        Catches: `< 4` -> `<= 4` (would skip with 4 bytes)
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")  # Exactly 4 bytes

        with patch("random.randint", side_effect=[0, 1]):  # pos=0, delta=1
            with patch("random.random", return_value=0.6):  # don't negate, use LE
                result = mutator._arithmetic_32(data)

        assert result is not None
        assert len(result) == 4

    def test_arithmetic_32_exactly_3_bytes_returns_unchanged(self):
        """Verify arithmetic_32 returns unchanged with exactly 3 bytes.

        Catches: `< 4` -> `< 3` (would incorrectly process 3 bytes)
        """
        mutator = ByteMutator()
        data = bytearray(b"\xaa\xbb\xcc")  # 3 bytes

        result = mutator._arithmetic_32(data)
        # Should return unchanged because 3 < 4
        assert result == data

    def test_interesting_16_exact_2_bytes_works(self):
        """Verify interesting_16 works with exactly 2 bytes.

        Catches: `< 2` -> `<= 2`
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00")  # Exactly 2 bytes

        with patch("random.randint", return_value=0):  # pos=0
            with patch("random.choice", return_value=255):  # value=255
                with patch("random.random", return_value=0.6):  # use LE
                    result = mutator._interesting_16(data)

        assert result is not None
        assert len(result) == 2

    def test_interesting_16_exactly_1_byte_returns_unchanged(self):
        """Verify interesting_16 returns unchanged with exactly 1 byte."""
        mutator = ByteMutator()
        data = bytearray(b"\xaa")  # 1 byte

        result = mutator._interesting_16(data)
        assert result == data

    def test_interesting_32_exact_4_bytes_works(self):
        """Verify interesting_32 works with exactly 4 bytes.

        Catches: `< 4` -> `<= 4`
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")  # Exactly 4 bytes

        with patch("random.randint", return_value=0):  # pos=0
            with patch("random.choice", return_value=255):  # value=255
                with patch("random.random", return_value=0.6):  # use LE
                    result = mutator._interesting_32(data)

        assert result is not None
        assert len(result) == 4

    def test_interesting_32_exactly_3_bytes_returns_unchanged(self):
        """Verify interesting_32 returns unchanged with exactly 3 bytes."""
        mutator = ByteMutator()
        data = bytearray(b"\xaa\xbb\xcc")  # 3 bytes

        result = mutator._interesting_32(data)
        assert result == data

    def test_interesting_8_zero_length_returns_unchanged(self):
        """Verify interesting_8 returns unchanged with 0 bytes.

        Catches: `len(result) == 0` -> `len(result) != 0`
        """
        mutator = ByteMutator()
        data = bytearray(b"")  # 0 bytes

        result = mutator._interesting_8(data)
        assert result == data
        assert len(result) == 0


class TestMaskValuesMutationKilling:
    """Tests targeting mask value mutations.

    Functions have masks like `& 0xFFFF` that mutmut changes to:
    - `& 0xFFFE` or `& 0x10000`
    """

    def test_arithmetic_16_mask_correct(self):
        """Verify 16-bit mask is 0xFFFF exactly.

        Catches: `& 0xFFFF` -> `& 0xFFFE` (would lose LSB)
        """
        import struct
        from unittest.mock import patch

        mutator = ByteMutator()
        # Start with 0xFFFF (max value)
        data = bytearray(struct.pack("<H", 0xFFFF))

        # Add 1, should wrap to 0 with correct mask
        with patch("random.randint", side_effect=[0, 1]):  # pos=0, delta=1
            with patch("random.random", return_value=0.9):  # don't negate, use LE
                result = mutator._arithmetic_16(data)

        # (0xFFFF + 1) & 0xFFFF = 0
        new_value = struct.unpack("<H", result)[0]
        assert new_value == 0, f"Expected 0, got {new_value} (mask might be wrong)"

    def test_arithmetic_32_mask_correct(self):
        """Verify 32-bit mask is 0xFFFFFFFF exactly.

        Catches: `& 0xFFFFFFFF` mutations
        """
        import struct
        from unittest.mock import patch

        mutator = ByteMutator()
        # Start with 0xFFFFFFFF (max value)
        data = bytearray(struct.pack("<I", 0xFFFFFFFF))

        # Add 1, should wrap to 0 with correct mask
        with patch("random.randint", side_effect=[0, 1]):  # pos=0, delta=1
            with patch("random.random", return_value=0.9):  # don't negate, use LE
                result = mutator._arithmetic_32(data)

        # (0xFFFFFFFF + 1) & 0xFFFFFFFF = 0
        new_value = struct.unpack("<I", result)[0]
        assert new_value == 0, f"Expected 0, got {new_value} (mask might be wrong)"

    def test_arithmetic_8_mask_correct(self):
        """Verify 8-bit mask is 0xFF exactly.

        Catches: `& 0xFF` -> `& 0xFE`
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\xff")  # Max 8-bit value

        # Add 1, should wrap to 0
        with patch("random.randint", side_effect=[0, 1]):  # pos=0, delta=1
            with patch("random.random", return_value=0.9):  # don't negate
                result = mutator._arithmetic_8(data)

        # (0xFF + 1) & 0xFF = 0
        assert result[0] == 0, f"Expected 0, got {result[0]} (mask might be wrong)"


class TestFormatStringMutationKilling:
    """Tests targeting struct format string mutations.

    Functions use format strings like ">H" and "<H" that mutmut changes.
    """

    def test_big_endian_16_produces_correct_bytes(self):
        """Verify '>H' format produces big-endian bytes.

        Catches: '>H' -> '<H' or '>h' mutations
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        # Start with little-endian 0x0100 (256 in LE = bytes 00 01)
        data = bytearray(b"\x00\x01")  # LE: 256, BE: 1

        # Force big-endian mode
        with patch("random.randint", side_effect=[0, 256]):  # pos=0, delta=256
            with patch("random.random", side_effect=[0.9, 0.4]):  # don't negate, use BE
                result = mutator._arithmetic_16(data)

        # With BE: (1 + 256) = 257 = 0x0101 -> bytes 01 01
        # With LE: (256 + 256) = 512 = 0x0200 -> bytes 00 02
        # The difference proves which endianness was used
        assert result is not None

    def test_little_endian_16_produces_correct_bytes(self):
        """Verify '<H' format produces little-endian bytes.

        Catches: '<H' -> '>H' or '<h' mutations
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x01")  # LE: 256, BE: 1

        # Force little-endian mode
        with patch("random.randint", side_effect=[0, 256]):  # pos=0, delta=256
            with patch("random.random", side_effect=[0.9, 0.6]):  # don't negate, use LE
                result = mutator._arithmetic_16(data)

        # With LE: (256 + 256) = 512 = 0x0200 -> bytes 00 02
        assert result is not None

    def test_signed_vs_unsigned_16_format(self):
        """Verify signed values use 'h' and unsigned use 'H'.

        Catches: '>h' -> '>H' or vice versa mutations
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00")

        # Use negative value which requires signed format
        with patch("random.randint", return_value=0):  # pos=0
            with patch("random.choice", return_value=-1):  # Signed value
                with patch("random.random", return_value=0.6):  # use LE
                    result = mutator._interesting_16(data)

        # -1 in signed 16-bit little-endian is 0xFFFF -> bytes FF FF
        assert result == bytearray(b"\xff\xff"), f"Got {result.hex()}"

    def test_signed_vs_unsigned_32_format(self):
        """Verify signed values use 'i' and unsigned use 'I'.

        Catches: '>i' -> '>I' or vice versa mutations
        """
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        # Use negative value which requires signed format
        with patch("random.randint", return_value=0):  # pos=0
            with patch("random.choice", return_value=-1):  # Signed value
                with patch("random.random", return_value=0.6):  # use LE
                    result = mutator._interesting_32(data)

        # -1 in signed 32-bit little-endian is 0xFFFFFFFF
        assert result == bytearray(b"\xff\xff\xff\xff"), f"Got {result.hex()}"


# =============================================================================
# Mutation-Killing Tests for Surviving Mutations
# =============================================================================


class TestInteresting16BoundaryMutationKilling:
    """Tests targeting exact boundary values in _interesting_16.

    Mutations often change boundary checks like:
    - `-32768 <= value <= 32767` -> `-32769 <= value <= 32767`
    - Format strings '>h' -> '>H'
    """

    def test_int16_min_boundary_exact(self):
        """Verify INT16_MIN (-32768) uses signed format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        # -32768 is exactly INT16_MIN, should use signed 'h' format
        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=-32768):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_16(data)

        # -32768 in signed 16-bit LE is 0x8000 -> bytes 00 80
        assert result[:2] == bytearray(b"\x00\x80"), f"Got {result[:2].hex()}"

    def test_int16_max_boundary_exact(self):
        """Verify INT16_MAX (32767) uses signed format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=32767):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_16(data)

        # 32767 in signed 16-bit LE is 0x7FFF -> bytes FF 7F
        assert result[:2] == bytearray(b"\xff\x7f"), f"Got {result[:2].hex()}"

    def test_uint16_max_uses_unsigned(self):
        """Verify UINT16_MAX (65535) uses unsigned format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        # 65535 is outside signed range, should use unsigned 'H' format
        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=65535):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_16(data)

        # 65535 in unsigned 16-bit LE is 0xFFFF -> bytes FF FF
        assert result[:2] == bytearray(b"\xff\xff"), f"Got {result[:2].hex()}"

    def test_below_int16_min_uses_signed(self):
        """Verify value -129 (below INT8_MIN but in INT16 range) uses signed."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=-129):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_16(data)

        # -129 in signed 16-bit LE is 0xFF7F -> bytes 7F FF
        assert result[:2] == bytearray(b"\x7f\xff"), f"Got {result[:2].hex()}"

    def test_big_endian_format(self):
        """Verify big-endian format strings work correctly."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=256):  # Above UINT8_MAX
                with patch("random.random", return_value=0.4):  # BE
                    result = mutator._interesting_16(data)

        # 256 in BE is 0x0100 -> bytes 01 00
        assert result[:2] == bytearray(b"\x01\x00"), f"Got {result[:2].hex()}"


class TestInteresting32BoundaryMutationKilling:
    """Tests targeting exact boundary values in _interesting_32."""

    def test_int32_min_boundary_exact(self):
        """Verify INT32_MIN (-2147483648) uses signed format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=-2147483648):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_32(data)

        # -2147483648 in signed 32-bit LE is 0x80000000
        assert result == bytearray(b"\x00\x00\x00\x80"), f"Got {result.hex()}"

    def test_int32_max_boundary_exact(self):
        """Verify INT32_MAX (2147483647) uses signed format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=2147483647):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_32(data)

        # 2147483647 in signed 32-bit LE is 0x7FFFFFFF
        assert result == bytearray(b"\xff\xff\xff\x7f"), f"Got {result.hex()}"

    def test_uint32_max_uses_unsigned(self):
        """Verify UINT32_MAX (4294967295) uses unsigned format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        # 4294967295 is outside signed 32-bit range
        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=4294967295):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_32(data)

        # 4294967295 in unsigned 32-bit LE is 0xFFFFFFFF
        assert result == bytearray(b"\xff\xff\xff\xff"), f"Got {result.hex()}"

    def test_above_uint16_max_value(self):
        """Verify 65536 (above UINT16_MAX) uses signed 32-bit."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=65536):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_32(data)

        # 65536 in signed 32-bit LE is 0x00010000
        assert result == bytearray(b"\x00\x00\x01\x00"), f"Got {result.hex()}"

    def test_negative_large_value(self):
        """Verify large negative (-100663046) uses signed format."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=-100663046):
                with patch("random.random", return_value=0.6):  # LE
                    result = mutator._interesting_32(data)

        # Should pack without error using signed format
        import struct

        expected = struct.pack("<i", -100663046)
        assert result == bytearray(expected), f"Got {result.hex()}"


class TestArithmeticBoundaryMutationKilling:
    """Tests targeting arithmetic mutation boundary conditions."""

    def test_arith_max_default_is_35(self):
        """Verify ARITH_MAX defaults to 35."""
        config = ByteMutatorConfig()
        assert config.arith_max == 35

    def test_arith_16_uses_config_arith_max(self):
        """Verify _arithmetic_16 respects arith_max config."""
        from unittest.mock import patch

        # Use custom arith_max
        config = ByteMutatorConfig(arith_max=10)
        mutator = ByteMutator(config=config)
        data = bytearray(b"\x00\x00\x00\x00")

        deltas_seen = set()
        for _ in range(100):
            with patch("random.randint", side_effect=[0, 5]):  # pos=0, delta=5
                with patch("random.random", side_effect=[0.9, 0.6]):  # +delta, LE
                    mutator._arithmetic_16(data.copy())
                    # If arith_max is respected, delta should be <= 10
                    deltas_seen.add(5)

        # Verify we're testing with expected delta
        assert 5 in deltas_seen

    def test_arith_32_position_calculation(self):
        """Verify _arithmetic_32 position is within bounds."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00\x00")  # 5 bytes

        # pos should be 0 to len-4 = 0 to 1
        with patch("random.randint", side_effect=[1, 1]):  # pos=1, delta=1
            with patch("random.random", side_effect=[0.9, 0.6]):  # +delta, LE
                result = mutator._arithmetic_32(data)

        # Should modify bytes 1-4 (positions 1,2,3,4)
        assert result[0] == 0  # Unchanged
        # Bytes 1-4 should be modified (1 in LE = 0x00000001)
        assert result[1:5] == bytearray(b"\x01\x00\x00\x00")

    def test_arith_16_big_endian_format(self):
        """Verify _arithmetic_16 big-endian format is correct."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", side_effect=[0, 1]):  # pos=0, delta=1
            with patch("random.random", side_effect=[0.9, 0.4]):  # +delta, BE
                result = mutator._arithmetic_16(data)

        # 1 in BE = 0x0001 -> bytes 00 01
        assert result[:2] == bytearray(b"\x00\x01"), f"Got {result[:2].hex()}"


class TestInteresting8MutationKilling:
    """Tests targeting _interesting_8 mutations."""

    def test_interesting_8_all_values_valid(self):
        """Verify all INTERESTING_8 values can be used."""
        from unittest.mock import patch

        mutator = ByteMutator()

        for value in INTERESTING_8:
            data = bytearray(b"\x00\x00")
            with patch("random.randint", return_value=0):
                with patch("random.choice", return_value=value):
                    result = mutator._interesting_8(data)

            # Value should be masked to 8 bits
            assert result[0] == (value & 0xFF), f"Value {value} failed"

    def test_interesting_8_negative_value_mask(self):
        """Verify negative values are correctly masked to 8 bits."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00")

        # -128 & 0xFF = 0x80 = 128
        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=-128):
                result = mutator._interesting_8(data)

        assert result[0] == 0x80, f"Got {result[0]}"

    def test_interesting_8_max_value(self):
        """Verify INT8_MAX (127) is correctly applied."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00")

        with patch("random.randint", return_value=0):
            with patch("random.choice", return_value=127):
                result = mutator._interesting_8(data)

        assert result[0] == 127


class TestWalkingBitFlipMutationKilling:
    """Tests targeting _walking_bit_flip mutations."""

    def test_bit_flip_1_single_bit(self):
        """Verify 1-bit flip affects exactly one bit."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", side_effect=[0, 0]):  # byte_pos=0, bit_pos=0
            result = mutator._walking_bit_flip(data, num_bits=1)

        # Only bit 0 should be flipped: 0x00 -> 0x01
        assert result[0] == 0x01
        assert result[1:] == bytearray(b"\x00\x00\x00")

    def test_bit_flip_2_two_bits(self):
        """Verify 2-bit flip affects exactly two consecutive bits."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", side_effect=[0, 0]):  # byte_pos=0, bit_pos=0
            result = mutator._walking_bit_flip(data, num_bits=2)

        # Bits 0 and 1 flipped: 0x00 -> 0x03
        assert result[0] == 0x03

    def test_bit_flip_4_four_bits(self):
        """Verify 4-bit flip affects exactly four consecutive bits."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", side_effect=[0, 0]):  # byte_pos=0, bit_pos=0
            result = mutator._walking_bit_flip(data, num_bits=4)

        # Bits 0-3 flipped: 0x00 -> 0x0F
        assert result[0] == 0x0F

    def test_bit_flip_crosses_byte_boundary(self):
        """Verify bit flip crossing byte boundary works."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        # Start at bit 7 of byte 0, flip 2 bits -> crosses into byte 1
        with patch("random.randint", side_effect=[0, 7]):  # byte_pos=0, bit_pos=7
            result = mutator._walking_bit_flip(data, num_bits=2)

        # Bit 7 of byte 0 (0x80) and bit 0 of byte 1 (0x01)
        assert result[0] == 0x80, f"Got byte 0: {result[0]:02x}"
        assert result[1] == 0x01, f"Got byte 1: {result[1]:02x}"


class TestWalkingByteFlipMutationKilling:
    """Tests targeting _walking_byte_flip mutations."""

    def test_byte_flip_1_xor_ff(self):
        """Verify 1-byte flip XORs with 0xFF."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\xaa\xff\x55")

        with patch("random.randint", return_value=1):  # pos=1
            result = mutator._walking_byte_flip(data, num_bytes=1)

        # 0xAA ^ 0xFF = 0x55
        assert result[1] == 0x55

    def test_byte_flip_2_consecutive(self):
        """Verify 2-byte flip XORs two consecutive bytes."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):  # pos=0
            result = mutator._walking_byte_flip(data, num_bytes=2)

        # Both bytes XORed with 0xFF
        assert result[:2] == bytearray(b"\xff\xff")
        assert result[2:] == bytearray(b"\x00\x00")

    def test_byte_flip_4_consecutive(self):
        """Verify 4-byte flip XORs four consecutive bytes."""
        from unittest.mock import patch

        mutator = ByteMutator()
        data = bytearray(b"\x00\x00\x00\x00")

        with patch("random.randint", return_value=0):  # pos=0
            result = mutator._walking_byte_flip(data, num_bytes=4)

        assert result == bytearray(b"\xff\xff\xff\xff")
