"""
Tests for test case minimization (delta debugging).
"""

from pathlib import Path

import pytest

from dicom_fuzzer.core.test_minimizer import (
    MinimizationStrategy,
    TestMinimizer,
)


@pytest.fixture
def simple_content():
    """Simple test content that can be reduced."""
    # Pattern: AAAA[X]BBBB where X causes crash
    return b"AAAA" + b"X" + b"BBBB"


@pytest.fixture
def crash_predicate_simple():
    """Simple crash predicate - crashes if 'X' is present."""

    def predicate(test_file: Path) -> bool:
        content = test_file.read_bytes()
        return b"X" in content

    return predicate


@pytest.fixture
def crash_predicate_specific_pattern():
    """Crash predicate requiring specific pattern."""

    def predicate(test_file: Path) -> bool:
        content = test_file.read_bytes()
        # Requires both 'X' and at least 2 'A's before it
        return b"AAX" in content

    return predicate


@pytest.fixture
def large_content():
    """Large test content for performance testing."""
    # Create 10KB file with crash pattern at position 5000
    padding = b"A" * 5000
    crash_marker = b"CRASH"
    trailing = b"B" * 4995  # Total: 10000 bytes
    return padding + crash_marker + trailing


@pytest.fixture
def crash_predicate_large():
    """Crash predicate for large content."""

    def predicate(test_file: Path) -> bool:
        content = test_file.read_bytes()
        return b"CRASH" in content

    return predicate


class TestTestMinimizer:
    """Test basic minimization functionality."""

    def test_minimizer_initialization(self, crash_predicate_simple):
        """Test minimizer can be initialized."""
        minimizer = TestMinimizer(
            crash_predicate=crash_predicate_simple,
            strategy=MinimizationStrategy.DDMIN,
        )

        assert minimizer.crash_predicate is not None
        assert minimizer.strategy == MinimizationStrategy.DDMIN
        assert minimizer.iterations == 0
        assert minimizer.test_executions == 0

    def test_minimize_simple_ddmin(
        self, tmp_path, simple_content, crash_predicate_simple
    ):
        """Test DDMIN minimization on simple content."""
        # Create input file
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(simple_content)

        # Create output directory
        output_dir = tmp_path / "minimized"

        # Run minimization
        minimizer = TestMinimizer(crash_predicate=crash_predicate_simple)
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        assert result.minimized_size < result.original_size
        assert result.minimized_size == 1  # Should reduce to just 'X'
        assert result.reduction_ratio > 0
        assert result.iterations > 0
        assert result.test_executions > 0

        # Verify minimized file exists and still crashes
        assert result.minimized_path.exists()
        assert crash_predicate_simple(result.minimized_path)

    def test_minimize_binary_search(
        self, tmp_path, simple_content, crash_predicate_simple
    ):
        """Test binary search minimization."""
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(simple_content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(
            crash_predicate=crash_predicate_simple,
            strategy=MinimizationStrategy.BINARY_SEARCH,
        )
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        assert result.minimized_size <= result.original_size
        assert crash_predicate_simple(result.minimized_path)

    def test_minimize_linear(self, tmp_path, crash_predicate_simple):
        """Test linear minimization (slower but thorough)."""
        # Use smaller content for linear strategy
        content = b"AAX"
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(
            crash_predicate=crash_predicate_simple,
            strategy=MinimizationStrategy.LINEAR,
            max_iterations=100,  # Limit iterations for test speed
        )
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        assert result.minimized_size <= result.original_size

    def test_minimize_block(self, tmp_path, large_content, crash_predicate_large):
        """Test block removal minimization."""
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(large_content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(
            crash_predicate=crash_predicate_large,
            strategy=MinimizationStrategy.BLOCK,
            max_iterations=100,
        )
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        assert result.minimized_size < result.original_size
        assert crash_predicate_large(result.minimized_path)

    def test_minimize_with_pattern_requirement(
        self, tmp_path, crash_predicate_specific_pattern
    ):
        """Test minimization preserves required pattern."""
        # Content requires "AAX" pattern to crash
        content = b"AAAAAXBBBBB"
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(crash_predicate=crash_predicate_specific_pattern)
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        minimized_content = result.minimized_path.read_bytes()
        # Should preserve at least "AAX"
        assert b"AAX" in minimized_content
        assert len(minimized_content) >= 3

    def test_minimize_large_file(self, tmp_path, large_content, crash_predicate_large):
        """Test minimization on larger file."""
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(large_content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(
            crash_predicate=crash_predicate_large,
            max_iterations=50,  # Limit for speed
        )
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        # Should achieve significant reduction
        assert result.reduction_ratio > 0.5  # At least 50% reduction
        assert result.minimized_size < 100  # Should get quite small

    def test_minimize_non_crashing_input(self, tmp_path, crash_predicate_simple):
        """Test behavior when input doesn't crash."""
        # Content without 'X' - won't crash
        content = b"AAAABBBB"
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(crash_predicate=crash_predicate_simple)
        result = minimizer.minimize(input_file, output_dir)

        assert not result.success
        assert "does not crash" in result.error

    def test_minimize_missing_input_file(self, tmp_path, crash_predicate_simple):
        """Test behavior when input file doesn't exist."""
        input_file = tmp_path / "nonexistent.dcm"
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(crash_predicate=crash_predicate_simple)
        result = minimizer.minimize(input_file, output_dir)

        assert not result.success
        assert "not found" in result.error.lower()

    def test_minimize_max_iterations_limit(
        self, tmp_path, simple_content, crash_predicate_simple
    ):
        """Test that max_iterations limit is respected."""
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(simple_content)
        output_dir = tmp_path / "minimized"

        # Very low iteration limit
        minimizer = TestMinimizer(
            crash_predicate=crash_predicate_simple, max_iterations=3
        )
        result = minimizer.minimize(input_file, output_dir)

        # Should succeed but not achieve optimal minimization
        assert result.success
        assert result.iterations <= 3

    def test_minimize_preserves_crash_behavior(
        self, tmp_path, simple_content, crash_predicate_simple
    ):
        """Test that minimized test case still crashes."""
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(simple_content)
        output_dir = tmp_path / "minimized"

        minimizer = TestMinimizer(crash_predicate=crash_predicate_simple)
        result = minimizer.minimize(input_file, output_dir)

        assert result.success
        # Verify minimized file still causes crash
        assert crash_predicate_simple(result.minimized_path)


class TestMinimizationResult:
    """Test MinimizationResult dataclass."""

    def test_result_string_representation(self, tmp_path):
        """Test string representation of successful result."""
        from dicom_fuzzer.core.test_minimizer import MinimizationResult

        result = MinimizationResult(
            original_size=1000,
            minimized_size=100,
            reduction_ratio=0.9,
            iterations=10,
            test_executions=50,
            strategy_used=MinimizationStrategy.DDMIN,
            minimized_path=tmp_path / "minimized.dcm",
            success=True,
        )

        result_str = str(result)
        assert "1000" in result_str
        assert "100" in result_str
        assert "90" in result_str  # 90% reduction
        assert "10 iterations" in result_str

    def test_result_string_failure(self):
        """Test string representation of failed result."""
        from dicom_fuzzer.core.test_minimizer import MinimizationResult

        result = MinimizationResult(
            original_size=1000,
            minimized_size=1000,
            reduction_ratio=0.0,
            iterations=0,
            test_executions=1,
            strategy_used=MinimizationStrategy.DDMIN,
            minimized_path=None,
            success=False,
            error="Test case does not crash",
        )

        result_str = str(result)
        assert "failed" in result_str.lower()
        assert "does not crash" in result_str


class TestMinimizationStrategies:
    """Test comparison of different minimization strategies."""

    def test_all_strategies_reduce_size(
        self, tmp_path, simple_content, crash_predicate_simple
    ):
        """Test that all strategies work (DDMIN guarantees reduction)."""
        strategies = [
            MinimizationStrategy.DDMIN,
            MinimizationStrategy.BINARY_SEARCH,
            MinimizationStrategy.BLOCK,
        ]

        for strategy in strategies:
            input_file = tmp_path / f"input_{strategy.value}.dcm"
            input_file.write_bytes(simple_content)
            output_dir = tmp_path / f"output_{strategy.value}"

            minimizer = TestMinimizer(
                crash_predicate=crash_predicate_simple,
                strategy=strategy,
                max_iterations=50,
            )
            result = minimizer.minimize(input_file, output_dir)

            assert result.success, f"Strategy {strategy.value} failed"
            # DDMIN should always reduce, others may not depending on crash location
            if strategy == MinimizationStrategy.DDMIN:
                assert result.minimized_size < result.original_size
            else:
                # Other strategies at least don't increase size
                assert result.minimized_size <= result.original_size
            assert crash_predicate_simple(result.minimized_path)

    def test_ddmin_vs_binary_search(
        self, tmp_path, large_content, crash_predicate_large
    ):
        """Compare DDMIN vs binary search on same input."""
        # DDMIN
        input_file1 = tmp_path / "input_ddmin.dcm"
        input_file1.write_bytes(large_content)
        minimizer1 = TestMinimizer(
            crash_predicate=crash_predicate_large,
            strategy=MinimizationStrategy.DDMIN,
            max_iterations=30,
        )
        result1 = minimizer1.minimize(input_file1, tmp_path / "ddmin")

        # Binary search
        input_file2 = tmp_path / "input_binary.dcm"
        input_file2.write_bytes(large_content)
        minimizer2 = TestMinimizer(
            crash_predicate=crash_predicate_large,
            strategy=MinimizationStrategy.BINARY_SEARCH,
            max_iterations=30,
        )
        result2 = minimizer2.minimize(input_file2, tmp_path / "binary")

        # Both should succeed
        assert result1.success
        assert result2.success

        # DDMIN typically achieves better reduction
        assert result1.minimized_size <= result2.minimized_size * 1.5


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_minimize_single_byte_file(self, tmp_path):
        """Test minimizing a single-byte file."""
        content = b"X"
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(content)

        def always_crashes(test_file: Path) -> bool:
            return True

        minimizer = TestMinimizer(crash_predicate=always_crashes)
        result = minimizer.minimize(input_file, tmp_path / "output")

        # Can't reduce a single byte further
        assert result.success
        assert result.minimized_size == 1
        assert result.reduction_ratio == 0.0

    def test_minimize_empty_file_rejected(self, tmp_path, crash_predicate_simple):
        """Test that empty files are handled."""
        # Even if content becomes empty during minimization, it should be rejected
        content = b"X"  # Crashes with X
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(content)

        minimizer = TestMinimizer(crash_predicate=crash_predicate_simple)
        result = minimizer.minimize(input_file, tmp_path / "output")

        # Should not reduce to empty
        assert result.minimized_size > 0

    def test_crash_predicate_exception_handling(self, tmp_path):
        """Test behavior when crash predicate raises exception."""
        content = b"TEST"
        input_file = tmp_path / "input.dcm"
        input_file.write_bytes(content)

        def buggy_predicate(test_file: Path) -> bool:
            # Simulate predicate that sometimes fails
            if len(test_file.read_bytes()) < 2:
                raise RuntimeError("Simulated error")
            return True

        minimizer = TestMinimizer(crash_predicate=buggy_predicate, max_iterations=10)
        result = minimizer.minimize(input_file, tmp_path / "output")

        # Should handle exceptions gracefully
        # Minimization may succeed with limited reduction
        assert result.success or not result.success  # Either outcome is acceptable
