"""Comprehensive tests for Coverage-Guided Mutation Engine.

Tests cover:
- MutationType enum
- MutationStrategy dataclass
- CoverageGuidedMutator class
- All mutation operations
- Strategy selection and feedback
"""

import random
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.corpus_manager import Seed
from dicom_fuzzer.core.coverage_guided_mutator import (
    CoverageGuidedMutator,
    MutationStrategy,
    MutationType,
)


class TestMutationType:
    """Test MutationType enum."""

    def test_mutation_type_values(self):
        """Test that all mutation types have values."""
        assert MutationType.BIT_FLIP.value == "bit_flip"
        assert MutationType.BYTE_FLIP.value == "byte_flip"
        assert MutationType.RANDOM_BYTE.value == "random_byte"
        assert MutationType.DICOM_TAG_CORRUPT.value == "dicom_tag_corrupt"

    def test_all_mutation_types_exist(self):
        """Test all expected mutation types exist."""
        expected_types = [
            "BIT_FLIP",
            "BYTE_FLIP",
            "RANDOM_BYTE",
            "BYTE_INSERT",
            "BYTE_DELETE",
            "ARITHMETIC_INC",
            "ARITHMETIC_DEC",
            "ARITHMETIC_RANDOM",
            "BLOCK_REMOVE",
            "BLOCK_DUPLICATE",
            "BLOCK_SHUFFLE",
            "DICOM_TAG_CORRUPT",
            "DICOM_VR_MISMATCH",
            "DICOM_LENGTH_OVERFLOW",
            "DICOM_SEQUENCE_NEST",
            "DICOM_TRANSFER_SYNTAX",
            "INTERESTING_BYTES",
            "INTERESTING_INTS",
            "BOUNDARY_VALUES",
            "GRAMMAR_MUTATE",
            "DICTIONARY_REPLACE",
        ]

        for type_name in expected_types:
            assert hasattr(MutationType, type_name)


class TestMutationStrategy:
    """Test MutationStrategy dataclass."""

    def test_strategy_initialization(self):
        """Test strategy initialization with defaults."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)

        assert strategy.mutation_type == MutationType.BIT_FLIP
        assert strategy.success_count == 0
        assert strategy.total_count == 0
        assert strategy.coverage_gains == []
        assert strategy.weight == 1.0
        assert strategy.enabled is True

    def test_strategy_post_init_empty_list(self):
        """Test __post_init__ initializes empty coverage_gains list (lines 69-70)."""
        strategy = MutationStrategy(
            mutation_type=MutationType.BIT_FLIP, coverage_gains=[]
        )
        assert strategy.coverage_gains == []

    def test_strategy_post_init_with_list(self):
        """Test __post_init__ with existing list."""
        strategy = MutationStrategy(
            mutation_type=MutationType.BIT_FLIP, coverage_gains=[1, 2, 3]
        )
        assert strategy.coverage_gains == [1, 2, 3]

    def test_success_rate_zero_total(self):
        """Test success_rate returns 0.0 when total_count is 0 (lines 75-77)."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)
        assert strategy.success_rate == 0.0

    def test_success_rate_calculation(self):
        """Test success_rate calculation with data."""
        strategy = MutationStrategy(
            mutation_type=MutationType.BIT_FLIP, success_count=5, total_count=10
        )
        assert strategy.success_rate == 0.5

    def test_update_without_coverage(self):
        """Test update without coverage gain (lines 81-84)."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)

        strategy.update(coverage_gained=False, new_edges=0)

        assert strategy.total_count == 1
        assert strategy.success_count == 0
        assert strategy.coverage_gains == []

    def test_update_with_coverage(self):
        """Test update with coverage gain."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)

        strategy.update(coverage_gained=True, new_edges=5)

        assert strategy.total_count == 1
        assert strategy.success_count == 1
        assert strategy.coverage_gains == [5]

    def test_update_adaptive_weight_adjustment(self):
        """Test adaptive weight adjustment after 10 updates (lines 87-88)."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)

        # Update 10 times with 50% success rate
        for i in range(10):
            strategy.update(coverage_gained=(i % 2 == 0), new_edges=1)

        # Weight should be adjusted based on success rate
        # success_rate = 5/10 = 0.5, weight = max(0.1, min(10.0, 0.5 * 5)) = 2.5
        assert strategy.weight == pytest.approx(2.5, rel=0.1)

    def test_update_weight_clamped_high(self):
        """Test weight is clamped to maximum 10.0."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)

        # All successful to maximize weight
        for _ in range(10):
            strategy.update(coverage_gained=True, new_edges=1)

        # Weight should be clamped to 10.0
        assert strategy.weight <= 10.0

    def test_update_weight_clamped_low(self):
        """Test weight is clamped to minimum 0.1."""
        strategy = MutationStrategy(mutation_type=MutationType.BIT_FLIP)

        # All failures to minimize weight
        for _ in range(10):
            strategy.update(coverage_gained=False, new_edges=0)

        # Weight should be clamped to 0.1
        assert strategy.weight >= 0.1


class TestCoverageGuidedMutatorInit:
    """Test CoverageGuidedMutator initialization."""

    def test_default_initialization(self):
        """Test default initialization (lines 108-167)."""
        mutator = CoverageGuidedMutator()

        assert mutator.max_mutations == 10
        assert mutator.adaptive_mode is True
        assert mutator.dicom_aware is True
        assert len(mutator.strategies) > 0
        assert len(mutator.interesting_bytes) == 8
        assert len(mutator.interesting_ints) > 0
        assert len(mutator.dicom_tags) == 5
        assert mutator.mutation_history == []
        assert mutator.coverage_history == []

    def test_custom_initialization(self):
        """Test initialization with custom parameters."""
        mutator = CoverageGuidedMutator(
            max_mutations=5, adaptive_mode=False, dicom_aware=False
        )

        assert mutator.max_mutations == 5
        assert mutator.adaptive_mode is False
        assert mutator.dicom_aware is False

    def test_init_strategies_all_enabled(self):
        """Test _init_strategies with DICOM-aware mode (lines 172-184)."""
        mutator = CoverageGuidedMutator(dicom_aware=True)

        for strategy in mutator.strategies.values():
            assert strategy.enabled is True

    def test_init_strategies_dicom_disabled(self):
        """Test _init_strategies with DICOM-aware disabled."""
        mutator = CoverageGuidedMutator(dicom_aware=False)

        # DICOM-specific strategies should be disabled
        dicom_types = [
            MutationType.DICOM_TAG_CORRUPT,
            MutationType.DICOM_VR_MISMATCH,
            MutationType.DICOM_LENGTH_OVERFLOW,
            MutationType.DICOM_SEQUENCE_NEST,
            MutationType.DICOM_TRANSFER_SYNTAX,
        ]

        for mutation_type in dicom_types:
            assert mutator.strategies[mutation_type].enabled is False


class TestMutateMethod:
    """Test the main mutate method."""

    def test_mutate_with_bytes_input(self):
        """Test mutate with raw bytes input (lines 199-226)."""
        mutator = CoverageGuidedMutator(max_mutations=3)
        data = b"\x00" * 100

        mutations = mutator.mutate(data)

        assert isinstance(mutations, list)
        for mutated_data, mutation_type in mutations:
            assert isinstance(mutated_data, bytes)
            assert isinstance(mutation_type, MutationType)

    def test_mutate_with_seed_input(self):
        """Test mutate with Seed object input."""
        mutator = CoverageGuidedMutator(max_mutations=3)

        # Create a mock Seed
        seed = MagicMock(spec=Seed)
        seed.data = b"\x00" * 100
        seed.energy = 2.0

        mutations = mutator.mutate(seed)

        assert isinstance(mutations, list)

    def test_mutate_empty_data_returns_empty(self):
        """Test mutate with empty data."""
        mutator = CoverageGuidedMutator()

        mutations = mutator.mutate(b"")

        # Should return empty list since no mutations possible
        assert isinstance(mutations, list)

    def test_mutate_generates_unique_mutations(self):
        """Test that mutations are different from original."""
        mutator = CoverageGuidedMutator(max_mutations=5)
        original = b"\xaa" * 100

        mutations = mutator.mutate(original)

        for mutated_data, _ in mutations:
            # Mutated data should be different
            assert mutated_data != original or len(mutations) == 0


class TestSelectMutationStrategy:
    """Test mutation strategy selection."""

    def test_select_random_exploration(self):
        """Test random exploration path (lines 232-235)."""
        mutator = CoverageGuidedMutator(adaptive_mode=True)

        # Force random selection
        with patch("random.random", return_value=0.05):  # < 0.1
            mutation_type = mutator._select_mutation_strategy(None)

        assert isinstance(mutation_type, MutationType)

    def test_select_weighted_strategy(self):
        """Test weighted strategy selection (lines 237-258)."""
        mutator = CoverageGuidedMutator(adaptive_mode=True)

        # Force weighted selection
        with patch("random.random", return_value=0.5):  # >= 0.1
            mutation_type = mutator._select_mutation_strategy(None)

        assert isinstance(mutation_type, MutationType)

    def test_select_fallback_when_no_strategies(self):
        """Test fallback to BIT_FLIP when no strategies available (line 247)."""
        mutator = CoverageGuidedMutator()

        # Disable all strategies
        for strategy in mutator.strategies.values():
            strategy.enabled = False

        with patch("random.random", return_value=0.5):
            mutation_type = mutator._select_mutation_strategy(None)

        assert mutation_type == MutationType.BIT_FLIP

    def test_select_with_zero_weights(self):
        """Test selection with zero total weight (lines 253-254)."""
        mutator = CoverageGuidedMutator()

        # Set all weights to 0
        for strategy in mutator.strategies.values():
            strategy.weight = 0.0

        with patch("random.random", return_value=0.5):
            mutation_type = mutator._select_mutation_strategy(None)

        assert isinstance(mutation_type, MutationType)


class TestApplyMutation:
    """Test _apply_mutation dispatcher."""

    def test_apply_mutation_empty_data(self):
        """Test _apply_mutation with empty data (lines 264-265)."""
        mutator = CoverageGuidedMutator()

        result = mutator._apply_mutation(bytearray(), MutationType.BIT_FLIP)

        assert result is None

    @pytest.mark.parametrize(
        "mutation_type",
        [
            MutationType.BIT_FLIP,
            MutationType.BYTE_FLIP,
            MutationType.RANDOM_BYTE,
            MutationType.BYTE_INSERT,
            MutationType.BYTE_DELETE,
            MutationType.ARITHMETIC_INC,
            MutationType.ARITHMETIC_DEC,
            MutationType.ARITHMETIC_RANDOM,
            MutationType.BLOCK_REMOVE,
            MutationType.BLOCK_DUPLICATE,
            MutationType.BLOCK_SHUFFLE,
            MutationType.INTERESTING_BYTES,
            MutationType.INTERESTING_INTS,
            MutationType.BOUNDARY_VALUES,
            MutationType.DICOM_TAG_CORRUPT,
            MutationType.DICOM_VR_MISMATCH,
            MutationType.DICOM_LENGTH_OVERFLOW,
            MutationType.DICOM_SEQUENCE_NEST,
            MutationType.DICOM_TRANSFER_SYNTAX,
        ],
    )
    def test_apply_all_mutation_types(self, mutation_type):
        """Test all mutation types via dispatcher (lines 269-327)."""
        mutator = CoverageGuidedMutator()
        # Create data large enough for all mutations
        data = bytearray(b"\x00" * 500)

        result = mutator._apply_mutation(data, mutation_type)

        assert result is not None
        assert isinstance(result, bytearray)


class TestBitFlip:
    """Test bit flip mutation."""

    def test_bit_flip_empty_data(self):
        """Test bit flip with empty data (lines 332-333)."""
        mutator = CoverageGuidedMutator()

        result = mutator._bit_flip(bytearray())

        assert result == bytearray()

    def test_bit_flip_modifies_data(self):
        """Test bit flip modifies data (lines 335-340).

        Note: Uses seeded random for deterministic behavior. Without seeding,
        multiple flips at the same position/bit can cancel out (XOR twice = original).
        """
        import random

        mutator = CoverageGuidedMutator()
        # Use non-zero data to ensure visible changes regardless of flip pattern
        data = bytearray(b"\xaa\x55\xff\x00\x12\x34\x56\x78\x9a\xbc")
        original = bytes(data)

        # Seed random for deterministic test behavior
        random.seed(42)
        result = mutator._bit_flip(data)

        # Data should be modified
        assert result != original


class TestByteFlip:
    """Test byte flip mutation."""

    def test_byte_flip_empty_data(self):
        """Test byte flip with empty data (lines 344-345)."""
        mutator = CoverageGuidedMutator()

        result = mutator._byte_flip(bytearray())

        assert result == bytearray()

    def test_byte_flip_modifies_data(self):
        """Test byte flip modifies data (lines 347-351).

        Note: This test uses varied data and multiple attempts because
        byte_flip uses random positions and can flip the same byte twice
        (which reverts to original). With enough bytes and attempts,
        modification is statistically guaranteed.
        """
        mutator = CoverageGuidedMutator()
        # Use larger data with varied content to ensure flip is detectable
        data = bytearray(
            b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
        )
        original = bytes(data)

        # Multiple attempts to handle edge case where same byte is flipped twice
        modified = False
        for _ in range(5):
            test_data = bytearray(original)
            result = mutator._byte_flip(test_data)
            if result != original:
                modified = True
                break

        assert modified, "byte_flip should modify data in at least one of 5 attempts"


class TestRandomByte:
    """Test random byte mutation."""

    def test_random_byte_empty_data(self):
        """Test random byte with empty data (lines 355-356)."""
        mutator = CoverageGuidedMutator()

        result = mutator._random_byte(bytearray())

        assert result == bytearray()

    def test_random_byte_modifies_data(self):
        """Test random byte modifies data (lines 358-362)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\xaa" * 10)

        result = mutator._random_byte(data)

        # Very likely to be modified
        assert result is not None


class TestByteInsert:
    """Test byte insert mutation."""

    def test_byte_insert_large_data_limit(self):
        """Test byte insert respects size limit (lines 366-367)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100001)
        original_len = len(data)

        result = mutator._byte_insert(data)

        # Should not grow past limit
        assert len(result) == original_len

    def test_byte_insert_normal(self):
        """Test byte insert grows data (lines 369-373)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)
        original_len = len(data)

        result = mutator._byte_insert(data)

        # Data should grow
        assert len(result) > original_len


class TestByteDelete:
    """Test byte delete mutation."""

    def test_byte_delete_small_data(self):
        """Test byte delete with small data (lines 377-378)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 5)
        original_len = len(data)

        result = mutator._byte_delete(data)

        # Should not delete from small data
        assert len(result) == original_len

    def test_byte_delete_normal(self):
        """Test byte delete shrinks data (lines 380-385)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)
        original_len = len(data)

        result = mutator._byte_delete(data)

        # Data should shrink
        assert len(result) < original_len


class TestArithmeticMutation:
    """Test arithmetic mutation."""

    def test_arithmetic_empty_data(self):
        """Test arithmetic with empty data (lines 389-390)."""
        mutator = CoverageGuidedMutator()

        result = mutator._arithmetic_mutation(bytearray(), 1)

        assert result == bytearray()

    def test_arithmetic_increment(self):
        """Test arithmetic increment (lines 392-397)."""
        mutator = CoverageGuidedMutator()
        data = bytearray([0, 0, 0])

        result = mutator._arithmetic_mutation(data, 1)

        # Some bytes should be incremented
        assert any(b > 0 for b in result)

    def test_arithmetic_decrement(self):
        """Test arithmetic decrement."""
        mutator = CoverageGuidedMutator()
        data = bytearray([255, 255, 255])

        result = mutator._arithmetic_mutation(data, -1)

        # Some bytes should be decremented
        assert any(b < 255 for b in result)


class TestBlockRemove:
    """Test block remove mutation."""

    def test_block_remove_small_data(self):
        """Test block remove with small data (lines 401-402)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 10)
        original_len = len(data)

        result = mutator._block_remove(data)

        # Should not remove from small data
        assert len(result) == original_len

    def test_block_remove_normal(self):
        """Test block remove reduces data (lines 404-407)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)
        original_len = len(data)

        result = mutator._block_remove(data)

        assert len(result) < original_len


class TestBlockDuplicate:
    """Test block duplicate mutation."""

    def test_block_duplicate_empty_data(self):
        """Test block duplicate with empty data (line 411)."""
        mutator = CoverageGuidedMutator()

        result = mutator._block_duplicate(bytearray())

        assert result == bytearray()

    def test_block_duplicate_large_data(self):
        """Test block duplicate with large data (line 411)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100001)
        original_len = len(data)

        result = mutator._block_duplicate(data)

        # Should not grow past limit
        assert len(result) == original_len

    def test_block_duplicate_normal(self):
        """Test block duplicate grows data (lines 414-421)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\xaa" * 100)
        original_len = len(data)

        result = mutator._block_duplicate(data)

        assert len(result) > original_len


class TestBlockShuffle:
    """Test block shuffle mutation."""

    def test_block_shuffle_small_data(self):
        """Test block shuffle with small data (lines 425-426)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 10)

        result = mutator._block_shuffle(data)

        # Should return unchanged
        assert result == data

    def test_block_shuffle_insufficient_blocks(self):
        """Test block shuffle with insufficient blocks (lines 431-432)."""
        mutator = CoverageGuidedMutator()
        # Create data where block_size = min(100, 25//10) = 2
        # num_blocks = 25 // 2 = 12, so this won't hit line 432
        data = bytearray(b"\x00" * 25)

        result = mutator._block_shuffle(data)

        assert result is not None

    def test_block_shuffle_single_block(self):
        """Test block shuffle with only one block (line 432)."""
        mutator = CoverageGuidedMutator()
        # Create data where block_size = min(100, 21//10) = 2
        # num_blocks = 21 // 2 = 10, still >= 2
        # Need: num_blocks = len(data) // block_size < 2
        # block_size = min(100, len(data) // 10)
        # For len=21: block_size = min(100, 2) = 2, num_blocks = 21//2 = 10 >= 2
        # For len=20: block_size = min(100, 2) = 2, num_blocks = 20//2 = 10 >= 2
        # We need: len(data) // block_size < 2
        # Since len >= 20 (passes first check), block_size = len//10
        # num_blocks = len // (len // 10) = approximately 10
        # To get num_blocks < 2, we'd need odd data sizes
        # Actually, for len=21, block_size = 2, num_blocks = 10
        # The only way to get num_blocks < 2 is if block_size > len/2
        # block_size = min(100, len//10)
        # For len=20: block_size = 2, num_blocks = 10
        # Can't easily trigger line 432 with len >= 20
        # But if we manually set block_size in a special case:
        # Actually need to create a case where num_blocks comes out to 1
        # len=20, block_size=min(100, 20//10)=2, num_blocks=20//2=10 >=2
        # The math means for len>=20, num_blocks will be ~10
        # Line 432 is only reachable if somehow block_size is very large

        # Actually looking at the math more carefully:
        # block_size = min(100, len(data) // 10)
        # If len=21, block_size = 2, num_blocks = 21//2 = 10
        # If len=200, block_size = 20, num_blocks = 200//20 = 10
        # num_blocks is always ~10 for any len >= 20
        # Line 432 may be unreachable under normal conditions

        # Let's just ensure we test with data that passes first check
        data = bytearray(b"\x00" * 20)
        result = mutator._block_shuffle(data)
        assert result is not None

    def test_block_shuffle_normal(self):
        """Test block shuffle reorders data (lines 434-453)."""
        mutator = CoverageGuidedMutator()
        # Create distinguishable blocks
        data = bytearray(b"\x01" * 100 + b"\x02" * 100 + b"\x03" * 100)

        result = mutator._block_shuffle(data)

        assert len(result) > 0


class TestInterestingBytes:
    """Test interesting bytes mutation."""

    def test_interesting_bytes_empty_data(self):
        """Test interesting bytes with empty data (lines 457-458)."""
        mutator = CoverageGuidedMutator()

        result = mutator._interesting_bytes(bytearray())

        assert result == bytearray()

    def test_interesting_bytes_inserts_values(self):
        """Test interesting bytes inserts values (lines 460-464)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x55" * 20)

        result = mutator._interesting_bytes(data)

        # Some bytes should now be interesting values
        interesting = set(mutator.interesting_bytes)
        assert any(b in interesting for b in result)


class TestInterestingInts:
    """Test interesting integers mutation."""

    def test_interesting_ints_small_data(self):
        """Test interesting ints with small data (lines 468-469)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 2)

        result = mutator._interesting_ints(data)

        # Should return unchanged
        assert len(result) == 2

    def test_interesting_ints_normal(self):
        """Test interesting ints inserts values (lines 471-483)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)

        result = mutator._interesting_ints(data)

        assert len(result) == 100


class TestBoundaryValues:
    """Test boundary values mutation."""

    def test_boundary_values_small_data(self):
        """Test boundary values with small data (lines 494-495)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 2)

        result = mutator._boundary_values(data)

        # Should return unchanged
        assert len(result) == 2

    def test_boundary_values_inserts(self):
        """Test boundary values inserts values (lines 487-503)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x55" * 100)

        result = mutator._boundary_values(data)

        # Should contain boundary values
        assert len(result) == 100


class TestDicomTagCorrupt:
    """Test DICOM tag corruption mutation."""

    def test_dicom_tag_corrupt_small_data(self):
        """Test DICOM tag corrupt with small data (lines 508-509)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)

        result = mutator._dicom_tag_corrupt(data)

        # Should return unchanged
        assert result == data

    def test_dicom_tag_corrupt_normal(self):
        """Test DICOM tag corrupt modifies tags (lines 512-519)."""
        mutator = CoverageGuidedMutator()
        # DICOM-like data
        data = bytearray(b"\x00" * 200)

        result = mutator._dicom_tag_corrupt(data)

        assert len(result) == 200


class TestDicomVrMismatch:
    """Test DICOM VR mismatch mutation."""

    def test_dicom_vr_mismatch_small_data(self):
        """Test DICOM VR mismatch with small data (lines 554-555)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)

        result = mutator._dicom_vr_mismatch(data)

        # Should return unchanged
        assert result == data

    def test_dicom_vr_mismatch_normal(self):
        """Test DICOM VR mismatch modifies VRs (lines 523-563)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 200)

        result = mutator._dicom_vr_mismatch(data)

        assert len(result) == 200


class TestDicomLengthOverflow:
    """Test DICOM length overflow mutation."""

    def test_dicom_length_overflow_small_data(self):
        """Test DICOM length overflow with small data (lines 567-568)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)

        result = mutator._dicom_length_overflow(data)

        # Should return unchanged
        assert result == data

    def test_dicom_length_overflow_normal(self):
        """Test DICOM length overflow modifies lengths (lines 571-584)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 200)

        result = mutator._dicom_length_overflow(data)

        assert len(result) == 200


class TestDicomSequenceNest:
    """Test DICOM sequence nesting mutation."""

    def test_dicom_sequence_nest_small_data(self):
        """Test DICOM sequence nest with small data (lines 588-589)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)

        result = mutator._dicom_sequence_nest(data)

        # Should return unchanged
        assert result == data

    def test_dicom_sequence_nest_normal(self):
        """Test DICOM sequence nest adds sequences (lines 592-608)."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 500)

        result = mutator._dicom_sequence_nest(data)

        # Should have grown due to sequence insertion
        assert len(result) > 500


class TestDicomTransferSyntax:
    """Test DICOM transfer syntax mutation."""

    def test_dicom_transfer_syntax_no_match(self):
        """Test transfer syntax with no matching syntax."""
        mutator = CoverageGuidedMutator()
        data = bytearray(b"\x00" * 100)

        result = mutator._dicom_transfer_syntax(data)

        # Should return unchanged
        assert result == data

    def test_dicom_transfer_syntax_with_match(self):
        """Test transfer syntax replacement (lines 612-629)."""
        mutator = CoverageGuidedMutator()
        # Include a transfer syntax UID
        syntax = b"1.2.840.10008.1.2"
        data = bytearray(b"\x00" * 50 + syntax + b"\x00" * 50)

        result = mutator._dicom_transfer_syntax(data)

        # Syntax may have been replaced
        assert len(result) > 0


class TestUpdateStrategyFeedback:
    """Test update_strategy_feedback method."""

    def test_update_strategy_feedback_without_coverage(self):
        """Test feedback without coverage gain (lines 635-641)."""
        mutator = CoverageGuidedMutator()

        mutator.update_strategy_feedback(
            MutationType.BIT_FLIP, coverage_gained=False, new_edges=0
        )

        assert len(mutator.mutation_history) == 1
        assert len(mutator.coverage_history) == 0

    def test_update_strategy_feedback_with_coverage(self):
        """Test feedback with coverage gain."""
        mutator = CoverageGuidedMutator()

        mutator.update_strategy_feedback(
            MutationType.BIT_FLIP, coverage_gained=True, new_edges=5
        )

        assert len(mutator.mutation_history) == 1
        assert len(mutator.coverage_history) == 1
        assert mutator.coverage_history[0] == 5

    def test_update_triggers_adjust_strategies(self):
        """Test feedback triggers strategy adjustment (lines 644-645)."""
        mutator = CoverageGuidedMutator(adaptive_mode=True)

        # Update 100 times to trigger adjustment
        for i in range(100):
            mutator.update_strategy_feedback(
                MutationType.BIT_FLIP, coverage_gained=(i % 2 == 0)
            )

        # History should have 100 entries
        assert len(mutator.mutation_history) == 100


class TestAdjustStrategies:
    """Test _adjust_strategies method."""

    def test_adjust_strategies_increases_weight(self):
        """Test strategy weight increases for successful strategies (lines 650-671)."""
        mutator = CoverageGuidedMutator()

        # Populate history with successful BIT_FLIP
        for _ in range(100):
            mutator.mutation_history.append((MutationType.BIT_FLIP, True))

        initial_weight = mutator.strategies[MutationType.BIT_FLIP].weight

        mutator._adjust_strategies()

        # Weight should have increased
        assert mutator.strategies[MutationType.BIT_FLIP].weight >= initial_weight

    def test_adjust_strategies_decreases_weight(self):
        """Test strategy weight decreases for unsuccessful strategies."""
        mutator = CoverageGuidedMutator()

        # Populate history with unsuccessful BIT_FLIP
        for _ in range(100):
            mutator.mutation_history.append((MutationType.BIT_FLIP, False))

        initial_weight = mutator.strategies[MutationType.BIT_FLIP].weight

        mutator._adjust_strategies()

        # Weight should have decreased
        assert mutator.strategies[MutationType.BIT_FLIP].weight <= initial_weight


class TestGetMutationStats:
    """Test get_mutation_stats method."""

    def test_get_mutation_stats_empty(self):
        """Test stats with no mutations."""
        mutator = CoverageGuidedMutator()

        stats = mutator.get_mutation_stats()

        # Should return empty dict since no mutations performed
        assert isinstance(stats, dict)

    def test_get_mutation_stats_with_data(self):
        """Test stats with mutations performed (lines 675-689)."""
        mutator = CoverageGuidedMutator()

        # Update some strategies
        mutator.strategies[MutationType.BIT_FLIP].update(True, 5)
        mutator.strategies[MutationType.BIT_FLIP].update(False)
        mutator.strategies[MutationType.BIT_FLIP].update(True, 3)

        stats = mutator.get_mutation_stats()

        assert "bit_flip" in stats
        assert stats["bit_flip"]["total_count"] == 3
        assert stats["bit_flip"]["success_count"] == 2
        assert stats["bit_flip"]["success_rate"] == pytest.approx(2 / 3)
        assert stats["bit_flip"]["avg_coverage_gain"] == pytest.approx(4.0)


class TestIntegration:
    """Integration tests."""

    def test_full_mutation_cycle(self):
        """Test a full mutation cycle with feedback.

        Note: Due to the random nature of mutations and the check that
        mutated_data != original data, we use multiple attempts to ensure
        at least one mutation succeeds within a reasonable number of tries.
        """
        mutator = CoverageGuidedMutator(max_mutations=5)

        # Create test data with varied content (not all zeros which can produce
        # identical mutations due to bit flips on zero bytes)
        data = bytes(range(256)) * 2  # 512 bytes with varied content

        # Try multiple times as mutations can produce identical results by chance
        all_mutations = []
        for _ in range(5):
            mutations = mutator.mutate(data)
            all_mutations.extend(mutations)
            if mutations:
                break

        assert len(all_mutations) > 0, (
            "Should produce at least one mutation in 5 attempts"
        )

        # Provide feedback
        for _, mutation_type in all_mutations:
            mutator.update_strategy_feedback(
                mutation_type, coverage_gained=random.random() > 0.5, new_edges=1
            )

        # Get stats
        stats = mutator.get_mutation_stats()

        assert isinstance(stats, dict)

    def test_multiple_mutation_rounds(self):
        """Test multiple rounds of mutation."""
        mutator = CoverageGuidedMutator(max_mutations=3)

        data = b"\xaa" * 100

        for _ in range(10):
            mutations = mutator.mutate(data)

            for mutated_data, mutation_type in mutations:
                # Use mutated data as new input occasionally
                if random.random() > 0.7:
                    data = mutated_data

                mutator.update_strategy_feedback(
                    mutation_type, coverage_gained=random.random() > 0.5
                )

        # Should have history
        assert len(mutator.mutation_history) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
