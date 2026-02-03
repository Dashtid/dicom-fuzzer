"""Test Case Minimization - Delta Debugging for Crashes.

Implements automatic test case minimization using delta debugging to reduce
crashing inputs to their smallest form while preserving crash behavior.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class MinimizationStrategy(Enum):
    """Strategies for test case minimization."""

    BINARY_SEARCH = "binary_search"  # Cut in half repeatedly
    LINEAR = "linear"  # Remove one byte at a time
    BLOCK = "block"  # Remove fixed-size blocks
    DDMIN = "ddmin"  # Delta debugging minimization


@dataclass
class MinimizationResult:
    """Result of test case minimization.

    Contains the minimized test case, statistics, and metadata.
    """

    original_size: int
    minimized_size: int
    reduction_ratio: float
    iterations: int
    test_executions: int
    strategy_used: MinimizationStrategy
    minimized_path: Path | None
    success: bool
    error: str | None = None

    def __str__(self) -> str:
        """String representation for reports."""
        if not self.success:
            return f"Minimization failed: {self.error}"

        return (
            f"Reduced from {self.original_size} to {self.minimized_size} bytes "
            f"({self.reduction_ratio:.1%} reduction) "
            f"in {self.iterations} iterations ({self.test_executions} tests)"
        )


class TestMinimizer:
    """Automatic test case minimization engine.

    Uses delta debugging to reduce crashing inputs to minimal form.
    """

    def __init__(
        self,
        crash_predicate: Callable[[Path], bool],
        strategy: MinimizationStrategy = MinimizationStrategy.DDMIN,
        max_iterations: int = 1000,
        timeout_seconds: int = 300,
    ):
        """Initialize test minimizer.

        Args:
            crash_predicate: Function that returns True if test case crashes
            strategy: Minimization strategy to use
            max_iterations: Maximum iterations before giving up
            timeout_seconds: Maximum time in seconds for minimization

        """
        self.crash_predicate = crash_predicate
        self.strategy = strategy
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds

        self.iterations = 0
        self.test_executions = 0

    def minimize(self, input_file: Path, output_dir: Path) -> MinimizationResult:
        """Minimize a crashing test case.

        Args:
            input_file: Path to crashing test case
            output_dir: Directory to store minimized test case

        Returns:
            Minimization result

        """
        if not input_file.exists():
            return MinimizationResult(
                original_size=0,
                minimized_size=0,
                reduction_ratio=0.0,
                iterations=0,
                test_executions=0,
                strategy_used=self.strategy,
                minimized_path=None,
                success=False,
                error=f"Input file not found: {input_file}",
            )

        # Read original content
        original_content = input_file.read_bytes()
        original_size = len(original_content)

        logger.info(
            f"Starting minimization of {input_file.name} ({original_size} bytes)"
        )

        # Verify it crashes first
        if not self._test_case_crashes(input_file):
            return MinimizationResult(
                original_size=original_size,
                minimized_size=original_size,
                reduction_ratio=0.0,
                iterations=0,
                test_executions=1,
                strategy_used=self.strategy,
                minimized_path=None,
                success=False,
                error="Test case does not crash",
            )

        # Reset counters
        self.iterations = 0
        self.test_executions = 0

        # Perform minimization based on strategy
        if self.strategy == MinimizationStrategy.DDMIN:
            minimized_content = self._ddmin(original_content)
        elif self.strategy == MinimizationStrategy.BINARY_SEARCH:
            minimized_content = self._binary_search(original_content)
        elif self.strategy == MinimizationStrategy.LINEAR:
            minimized_content = self._linear(original_content)
        elif self.strategy == MinimizationStrategy.BLOCK:
            minimized_content = self._block_removal(original_content)
        else:  # pragma: no cover - all strategies handled above
            minimized_content = original_content  # type: ignore[unreachable]

        minimized_size = len(minimized_content)

        # Save minimized test case
        output_dir.mkdir(parents=True, exist_ok=True)
        minimized_path = output_dir / f"minimized_{input_file.name}"
        minimized_path.write_bytes(minimized_content)

        logger.info(
            f"Minimization complete: {original_size} -> {minimized_size} bytes "
            f"({(1 - minimized_size / original_size) * 100:.1f}% reduction)"
        )

        return MinimizationResult(
            original_size=original_size,
            minimized_size=minimized_size,
            reduction_ratio=1.0 - (minimized_size / original_size),
            iterations=self.iterations,
            test_executions=self.test_executions,
            strategy_used=self.strategy,
            minimized_path=minimized_path,
            success=True,
        )

    def _test_case_crashes(self, test_file: Path) -> bool:
        """Test if a file causes crash.

        Args:
            test_file: Path to test file

        Returns:
            True if crash occurs

        """
        self.test_executions += 1
        try:
            return self.crash_predicate(test_file)
        except Exception as e:
            logger.warning(f"Error testing file: {e}")
            return False

    def _ddmin(self, content: bytes) -> bytes:
        """Delta debugging minimization algorithm.

        Repeatedly try removing subsets of the input until no more
        reductions are possible.

        Args:
            content: Original content

        Returns:
            Minimized content

        """
        current = content
        chunk_size = len(current) // 2

        while chunk_size > 0 and self.iterations < self.max_iterations:
            reduced = False

            # Try removing each chunk
            for i in range(0, len(current), chunk_size):
                self.iterations += 1

                # Create variant with chunk removed
                variant = current[:i] + current[i + chunk_size :]

                if len(variant) == 0:
                    continue

                # Test if still crashes
                temp_file = self._create_temp_file(variant)
                if self._test_case_crashes(temp_file):
                    current = variant
                    reduced = True
                    logger.debug(f"Reduced to {len(current)} bytes")
                    break

                temp_file.unlink()

            # If no reduction this pass, try smaller chunks
            if not reduced:
                chunk_size //= 2

        return current

    def _binary_search(self, content: bytes) -> bytes:
        """Binary search minimization.

        Repeatedly cut file in half until crash disappears.

        Args:
            content: Original content

        Returns:
            Minimized content

        """
        current = content

        while len(current) > 1 and self.iterations < self.max_iterations:
            self.iterations += 1

            # Try cutting in half
            half = len(current) // 2
            variant = current[:half]

            temp_file = self._create_temp_file(variant)
            if self._test_case_crashes(temp_file):
                current = variant
                logger.debug(f"Reduced to {len(current)} bytes")
            else:
                # Can't reduce further
                break

            temp_file.unlink()

        return current

    def _linear(self, content: bytes) -> bytes:
        """Linear minimization - remove one byte at a time.

        Slow but thorough.

        Args:
            content: Original content

        Returns:
            Minimized content

        """
        current = content
        i = 0

        while i < len(current) and self.iterations < self.max_iterations:
            self.iterations += 1

            # Try removing byte at position i
            variant = current[:i] + current[i + 1 :]

            if len(variant) == 0:
                break

            temp_file = self._create_temp_file(variant)
            if self._test_case_crashes(temp_file):
                current = variant
                # Don't increment i, check same position again
            else:
                i += 1

            temp_file.unlink()

        return current

    def _block_removal(self, content: bytes, block_size: int = 1024) -> bytes:
        """Block removal minimization.

        Remove fixed-size blocks until no more can be removed.

        Args:
            content: Original content
            block_size: Size of blocks to remove

        Returns:
            Minimized content

        """
        current = content

        while block_size > 0 and self.iterations < self.max_iterations:
            reduced = False

            for i in range(0, len(current), block_size):
                self.iterations += 1

                variant = current[:i] + current[i + block_size :]

                if len(variant) == 0:
                    continue

                temp_file = self._create_temp_file(variant)
                if self._test_case_crashes(temp_file):
                    current = variant
                    reduced = True
                    logger.debug(f"Reduced to {len(current)} bytes")
                    break

                temp_file.unlink()

            if not reduced:
                block_size //= 2

        return current

    def _create_temp_file(self, content: bytes) -> Path:
        """Create temporary file for testing.

        Args:
            content: File content

        Returns:
            Path to temporary file

        """
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".dcm")
        with open(fd, "wb") as f:
            f.write(content)
        return Path(path)


def minimize_crash_case(
    crash_file: Path,
    target_runner: Any,
    output_dir: Path,
    strategy: MinimizationStrategy = MinimizationStrategy.DDMIN,
) -> MinimizationResult:
    """Convenience function to minimize a crash case using target runner.

    Args:
        crash_file: Path to crashing input file
        target_runner: TargetRunner instance for testing
        output_dir: Output directory for minimized file
        strategy: Minimization strategy

    Returns:
        Minimization result

    """

    def crash_predicate(test_file: Path) -> bool:
        """Test if file causes crash."""
        result = target_runner.execute_test(test_file)
        # Consider CRASH, HANG, and OOM as crashes
        from dicom_fuzzer.core.harness.target_runner import ExecutionStatus

        return result.result in [
            ExecutionStatus.CRASH,
            ExecutionStatus.HANG,
            ExecutionStatus.OOM,
        ]

    minimizer = TestMinimizer(crash_predicate=crash_predicate, strategy=strategy)
    return minimizer.minimize(crash_file, output_dir)
