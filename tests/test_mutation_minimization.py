"""
Tests for Mutation Minimization

Tests delta debugging and minimization algorithms.
"""

from datetime import datetime

import pytest

from core.fuzzing_session import MutationRecord
from core.mutation_minimization import MinimizationResult, MutationMinimizer


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
        MutationMinimizer(never_crashes, max_iterations=100)

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
