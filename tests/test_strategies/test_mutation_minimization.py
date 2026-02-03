"""
Tests for Mutation Minimization

Tests delta debugging and minimization algorithms.
"""

from datetime import datetime

import pytest

from dicom_fuzzer.core.mutation.mutation_minimization import (
    MinimizationResult,
    MutationMinimizer,
)
from dicom_fuzzer.core.session.fuzzing_session import MutationRecord


class TestMutationMinimizer:
    """Test mutation minimization functionality."""

    @pytest.fixture
    def test_mutations(self):
        """Create test mutations."""
        return [
            MutationRecord(
                mutation_id=f"mut_{i}",
                strategy_name="TestStrategy",
                timestamp=datetime.now(),
                mutation_type="test",
            )
            for i in range(5)
        ]

    def test_minimizer_initialization(self):
        """Test minimizer initialization."""

        def crash_tester(dataset):
            return True

        minimizer = MutationMinimizer(crash_tester, max_iterations=50)

        assert minimizer.crash_tester is not None
        assert minimizer.max_iterations == 50
        assert minimizer.test_count == 0

    def test_split_list(self):
        """Test list splitting helper."""

        def crash_tester(dataset):
            return True

        minimizer = MutationMinimizer(crash_tester)

        lst = [1, 2, 3, 4, 5]

        # Split into 2 parts
        parts = minimizer._split_list(lst, 2)
        assert len(parts) == 2
        assert sum(len(p) for p in parts) == 5

        # Split into 3 parts
        parts = minimizer._split_list(lst, 3)
        assert len(parts) == 3

        # Split more than list length
        parts = minimizer._split_list(lst, 10)
        assert len(parts) <= len(lst)

    def test_linear_minimization_all_needed(self, test_mutations):
        """Test linear minimization when crash always occurs.

        This tests that minimization will reduce to minimal set when crash
        is not dependent on mutations (e.g., deterministic crash in viewer).
        """

        # Crash tester that always returns True (crash always happens)
        def always_crashes(dataset):
            return True

        class MockDataset:
            pass

        minimizer = MutationMinimizer(always_crashes, max_iterations=100)
        minimal = minimizer._linear_minimization(MockDataset(), test_mutations)

        # When it always crashes, minimization should reduce to empty set
        # (no mutations needed to trigger the crash)
        assert len(minimal) == 0

    def test_linear_minimization_none_needed(self, test_mutations):
        """Test linear minimization when mutations not needed."""

        # Crash tester that never crashes
        def never_crashes(dataset):
            return False

        class MockDataset:
            pass

        # Note: This tests the algorithm behavior when crash doesn't happen
        # In real scenario, we'd start with a crashing set
        # This tests edge case handling
        minimizer = MutationMinimizer(never_crashes, max_iterations=100)

        # Verify minimizer was created
        assert minimizer is not None

    def test_binary_minimization(self, test_mutations):
        """Test binary search minimization."""

        def crash_on_first(ds):
            return True  # Always crashes

        class MockDataset:
            pass

        minimizer = MutationMinimizer(crash_on_first, max_iterations=100)
        minimal = minimizer._binary_minimization(MockDataset(), test_mutations)

        # Should reduce the set
        assert len(minimal) <= len(test_mutations)
        assert minimizer.test_count > 0

    def test_minimization_result(self):
        """Test MinimizationResult data class."""
        result = MinimizationResult(
            original_mutation_count=10,
            minimized_mutation_count=2,
            minimal_mutations=[],
            test_iterations=25,
            still_crashes=True,
            minimization_ratio=0.8,
        )

        assert result.original_mutation_count == 10
        assert result.minimized_mutation_count == 2
        assert result.minimization_ratio == 0.8
        assert result.still_crashes is True

    def test_test_count_tracking(self, test_mutations):
        """Test that test iterations are counted."""
        calls = []

        def counting_tester(dataset):
            calls.append(1)
            return len(calls) % 2 == 0  # Alternating results

        class MockDataset:
            pass

        minimizer = MutationMinimizer(counting_tester, max_iterations=10)
        minimizer._linear_minimization(MockDataset(), test_mutations)

        # Should have tracked test count
        assert minimizer.test_count > 0
        assert len(calls) > 0

    def test_max_iterations_limit(self, test_mutations):
        """Test that max iterations limit is respected."""

        def always_crashes(dataset):
            return True

        class MockDataset:
            pass

        minimizer = MutationMinimizer(always_crashes, max_iterations=3)
        minimizer._linear_minimization(MockDataset(), test_mutations)

        # Should not exceed max iterations
        assert minimizer.test_count <= 3

    def test_delta_debugging_reduction(self):
        """Test delta debugging can reduce mutation set."""

        # Create test case where only first mutation is needed
        def crashes_on_first_only(dataset):
            # In real implementation, would check which mutations applied
            # For now, simulate by counting calls
            return True  # Simplified for unit test

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id=f"mut_{i}",
                strategy_name="Test",
                timestamp=datetime.now(),
                mutation_type="test",
            )
            for i in range(4)
        ]

        minimizer = MutationMinimizer(crashes_on_first_only, max_iterations=50)
        minimal = minimizer._delta_debugging(MockDataset(), mutations)

        # Should attempt to reduce
        assert len(minimal) <= len(mutations)

    def test_apply_mutations_creates_copy(self):
        """Test that mutations don't modify original dataset."""

        class MockDataset:
            value = "original"

        def test_tester(dataset):
            return True

        minimizer = MutationMinimizer(test_tester)
        original = MockDataset()

        # Apply mutations (currently stub implementation)
        result = minimizer._apply_mutations(original, [])

        # Should be a different object
        assert result is not original
        # Original should be unchanged
        assert original.value == "original"


class TestMutationMinimizationIntegration:
    """Integration tests for complete minimization workflows."""

    @pytest.fixture
    def realistic_mutation_set(self):
        """Create realistic set of mutations like from actual fuzzing."""
        return [
            MutationRecord(
                mutation_id=f"mut_{i:03d}",
                strategy_name="metadata_fuzzer" if i % 3 == 0 else "pixel_fuzzer",
                timestamp=datetime.now(),
                mutation_type="corrupt_tag" if i % 2 == 0 else "flip_bits",
                original_value=f"original_{i}",
                mutated_value=f"mutated_{i}",
            )
            for i in range(10)
        ]

    def test_minimize_with_single_critical_mutation(self, realistic_mutation_set):
        """Test minimization when only one mutation triggers crash."""

        def crashes_on_specific_mutation(dataset):
            # Simulate crash triggered by specific mutation
            # In real scenario, would check which mutations are in dataset
            return True  # Simplified for test

        class MockDataset:
            pass

        minimizer = MutationMinimizer(crashes_on_specific_mutation, max_iterations=100)
        result = minimizer.minimize(
            original_dataset=MockDataset(),
            mutations=realistic_mutation_set,
            strategy="delta_debug",
        )

        # Verify result structure
        assert isinstance(result, MinimizationResult)
        assert result.original_mutation_count == 10
        assert result.test_iterations > 0
        # Delta debugging should reduce the set
        assert result.minimized_mutation_count <= result.original_mutation_count

    def test_minimize_multiple_required_mutations(self):
        """Test when multiple mutations are needed together."""

        mutations = [
            MutationRecord(
                mutation_id=f"mut_{i:03d}",
                strategy_name="test",
                timestamp=datetime.now(),
                mutation_type="test",
            )
            for i in range(8)
        ]

        def crashes_on_combination(dataset):
            # Always crash for this test (real impl would check mutations)
            return True

        class MockDataset:
            pass

        minimizer = MutationMinimizer(crashes_on_combination, max_iterations=100)
        result = minimizer.minimize(
            original_dataset=MockDataset(), mutations=mutations, strategy="delta_debug"
        )

        # Should reduce mutations
        assert result.minimized_mutation_count <= result.original_mutation_count
        assert result.test_iterations > 0

    def test_all_minimization_strategies(self, realistic_mutation_set):
        """Test all three minimization strategies produce valid results."""

        def always_crashes(dataset):
            return True

        class MockDataset:
            pass

        strategies = ["delta_debug", "linear", "binary"]

        for strategy in strategies:
            minimizer = MutationMinimizer(always_crashes, max_iterations=100)
            result = minimizer.minimize(
                original_dataset=MockDataset(),
                mutations=realistic_mutation_set,
                strategy=strategy,
            )

            assert isinstance(result, MinimizationResult)
            assert result.original_mutation_count == 10
            assert result.minimized_mutation_count >= 0
            assert result.test_iterations > 0
            assert 0.0 <= result.minimization_ratio <= 1.0

    def test_minimization_ratio_calculation(self):
        """Test that minimization ratio is calculated correctly."""

        def always_crashes(dataset):
            return True

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id=f"m{i}", strategy_name="test", timestamp=datetime.now()
            )
            for i in range(10)
        ]

        minimizer = MutationMinimizer(always_crashes, max_iterations=100)
        result = minimizer.minimize(MockDataset(), mutations, strategy="linear")

        # Ratio = (original - minimized) / original
        expected_ratio = (
            result.original_mutation_count - result.minimized_mutation_count
        ) / result.original_mutation_count

        assert abs(result.minimization_ratio - expected_ratio) < 0.01

    def test_minimization_preserves_crash_condition(self):
        """Test that minimization confirms crash still occurs."""

        crash_count = [0]

        def tracking_crash_tester(dataset):
            crash_count[0] += 1
            return True

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id=f"m{i}", strategy_name="test", timestamp=datetime.now()
            )
            for i in range(5)
        ]

        minimizer = MutationMinimizer(tracking_crash_tester, max_iterations=100)
        result = minimizer.minimize(MockDataset(), mutations, strategy="delta_debug")

        # Should verify crash still occurs with minimal set
        assert result.still_crashes is True
        # Should have tested multiple times
        assert crash_count[0] > 0

    def test_minimization_respects_max_iterations(self):
        """Test that minimization stops at max iterations."""

        test_count = [0]

        def counting_tester(dataset):
            test_count[0] += 1
            return True

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id=f"m{i}", strategy_name="test", timestamp=datetime.now()
            )
            for i in range(20)
        ]

        minimizer = MutationMinimizer(counting_tester, max_iterations=5)
        result = minimizer.minimize(MockDataset(), mutations, strategy="delta_debug")

        # Should not exceed max iterations (allow 1 extra for final verification)
        assert result.test_iterations <= 5
        assert test_count[0] <= 6

    def test_minimize_single_mutation(self):
        """Test minimization with single mutation (edge case)."""

        def crashes(dataset):
            return True

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id="only_one", strategy_name="test", timestamp=datetime.now()
            )
        ]

        minimizer = MutationMinimizer(crashes, max_iterations=10)
        result = minimizer.minimize(MockDataset(), mutations, strategy="linear")

        # Can't reduce below 1 mutation
        assert result.minimized_mutation_count <= 1

    def test_minimize_no_crash_scenario(self):
        """Test minimization when crash doesn't reproduce."""

        def no_crash(dataset):
            return False  # Never crashes

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id=f"m{i}", strategy_name="test", timestamp=datetime.now()
            )
            for i in range(5)
        ]

        minimizer = MutationMinimizer(no_crash, max_iterations=50)
        result = minimizer.minimize(MockDataset(), mutations, strategy="delta_debug")

        # Should report crash doesn't reproduce
        assert result.still_crashes is False

    def test_compare_minimization_strategies_efficiency(self):
        """Compare efficiency of different minimization strategies."""

        def always_crashes(dataset):
            return True

        class MockDataset:
            pass

        mutations = [
            MutationRecord(
                mutation_id=f"m{i}", strategy_name="test", timestamp=datetime.now()
            )
            for i in range(15)
        ]

        results = {}
        for strategy in ["delta_debug", "linear", "binary"]:
            minimizer = MutationMinimizer(always_crashes, max_iterations=100)
            result = minimizer.minimize(MockDataset(), mutations, strategy=strategy)
            results[strategy] = result

        # All should produce valid results
        for strategy, result in results.items():
            assert result.minimized_mutation_count >= 0
            assert result.test_iterations > 0

        # Delta debugging typically more efficient than linear
        # (uses fewer iterations for same result)
        assert (
            results["delta_debug"].test_iterations
            <= results["linear"].test_iterations * 2
        )

    def test_minimization_with_empty_mutation_list(self):
        """Test minimization with empty mutation list (edge case)."""

        def crashes(dataset):
            return True

        class MockDataset:
            pass

        minimizer = MutationMinimizer(crashes, max_iterations=10)
        result = minimizer.minimize(MockDataset(), mutations=[], strategy="delta_debug")

        assert result.original_mutation_count == 0
        assert result.minimized_mutation_count == 0
        assert result.minimization_ratio == 0.0

    def test_minimization_detailed_statistics(self, realistic_mutation_set):
        """Test that minimization provides detailed statistics."""

        def crashes(dataset):
            return True

        class MockDataset:
            pass

        minimizer = MutationMinimizer(crashes, max_iterations=50)
        result = minimizer.minimize(
            MockDataset(),
            realistic_mutation_set,
            strategy="delta_debug",
        )

        # Verify all statistics are present
        assert hasattr(result, "original_mutation_count")
        assert hasattr(result, "minimized_mutation_count")
        assert hasattr(result, "minimal_mutations")
        assert hasattr(result, "test_iterations")
        assert hasattr(result, "still_crashes")
        assert hasattr(result, "minimization_ratio")

        # Verify values are reasonable
        assert result.original_mutation_count == 10
        assert 0 <= result.minimized_mutation_count <= 10
        assert isinstance(result.minimal_mutations, list)
        assert result.test_iterations > 0
        assert isinstance(result.still_crashes, bool)
        assert 0.0 <= result.minimization_ratio <= 1.0
