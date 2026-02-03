"""Stability Metrics Tracking - AFL++-Style.

Tracks fuzzing stability to detect non-deterministic behavior.
Same input should produce same coverage every time.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.hashing import hash_file_quick, md5_hash
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class InstabilityCause(Enum):
    """Root causes of execution instability.

    CONCEPT: Different types of non-determinism require different fixes:
    - Race conditions: Need better synchronization
    - Uninitialized memory: Memory safety bugs
    - Entropy: Random number generators, timestamps
    - Timing: Execution time dependencies
    """

    RACE_CONDITION = "race_condition"  # Threading/concurrency issues
    UNINITIALIZED_MEMORY = "uninitialized"  # Memory not initialized
    ENTROPY_SOURCE = "entropy"  # Random numbers, timestamps
    TIMING_DEPENDENT = "timing"  # Timing-based behavior
    UNKNOWN = "unknown"  # Cannot determine cause


@dataclass
class StabilityMetrics:
    """Stability metrics for a fuzzing campaign.

    Tracks consistency of execution across multiple runs of same inputs.
    """

    total_executions: int = 0
    stable_executions: int = 0
    unstable_executions: int = 0
    stability_percentage: float = 100.0

    # Track which inputs show instability
    unstable_inputs: set[str] = field(default_factory=set)

    # Detailed tracking
    execution_variance: dict[str, list[str]] = field(default_factory=dict)

    # Root cause analysis
    instability_causes: dict[str, InstabilityCause] = field(default_factory=dict)
    cause_counts: dict[InstabilityCause, int] = field(
        default_factory=lambda: defaultdict(int)
    )

    def __str__(self) -> str:
        """String representation for logging."""
        return (
            f"Stability: {self.stability_percentage:.1f}% "
            f"({self.stable_executions}/{self.total_executions} stable)"
        )


class StabilityTracker:
    """Track stability metrics during fuzzing campaigns.

    Monitors whether the same input produces consistent behavior across
    multiple executions, flagging non-deterministic behavior.
    """

    def __init__(self, stability_window: int = 100, retest_frequency: int = 10):
        """Initialize stability tracker.

        Args:
            stability_window: Number of recent executions to consider
            retest_frequency: How often to retest inputs for stability (every N iterations)

        """
        self.stability_window = stability_window
        self.retest_frequency = retest_frequency

        # Track execution results by input hash
        self.execution_history: dict[str, list[str]] = defaultdict(list)

        # Track overall metrics
        self.metrics = StabilityMetrics()

        # Iteration counter for retesting
        self.iteration_count = 0

        # Inputs that have been tested multiple times
        self.retested_inputs: set[str] = set()

    def record_execution(
        self, test_file: Path, execution_signature: str, retest: bool = False
    ) -> bool:
        """Record an execution and check stability.

        Args:
            test_file: Path to test file
            execution_signature: Signature of execution (exit code, output hash, coverage)
            retest: Whether this is a stability retest

        Returns:
            True if execution was stable, False if unstable

        """
        input_hash = self._hash_file(test_file)

        # Record execution
        self.execution_history[input_hash].append(execution_signature)
        self.metrics.total_executions += 1

        # Keep only recent history
        if len(self.execution_history[input_hash]) > self.stability_window:
            self.execution_history[input_hash] = self.execution_history[input_hash][
                -self.stability_window :
            ]

        # Check stability if this is a retest or we have multiple executions
        is_stable = True
        if retest or len(self.execution_history[input_hash]) > 1:
            is_stable = self._check_stability(input_hash)

            if is_stable:
                self.metrics.stable_executions += 1
                # Remove from unstable set if it was there
                self.metrics.unstable_inputs.discard(input_hash)
            else:
                self.metrics.unstable_executions += 1
                self.metrics.unstable_inputs.add(input_hash)
                logger.warning(f"Unstable execution detected for {test_file.name}")

                # Store variance details
                self.metrics.execution_variance[input_hash] = list(
                    set(self.execution_history[input_hash])
                )

        # Update stability percentage
        if self.metrics.total_executions > 0:
            self.metrics.stability_percentage = (
                100.0 * self.metrics.stable_executions / self.metrics.total_executions
            )

        return is_stable

    def should_retest(self, test_file: Path) -> bool:
        """Determine if input should be retested for stability.

        Args:
            test_file: Path to test file

        Returns:
            True if should retest

        """
        self.iteration_count += 1

        # Retest periodically
        if self.iteration_count % self.retest_frequency != 0:
            return False

        input_hash = self._hash_file(test_file)

        # Don't retest if already tested multiple times
        if input_hash in self.retested_inputs:
            return False

        # Retest if we only have one execution recorded
        if len(self.execution_history.get(input_hash, [])) == 1:
            self.retested_inputs.add(input_hash)
            return True

        return False

    def get_metrics(self) -> StabilityMetrics:
        """Get current stability metrics.

        Returns:
            Current metrics

        """
        return self.metrics

    def get_unstable_inputs_report(self) -> list[dict[str, Any]]:
        """Get detailed report of unstable inputs.

        Returns:
            List of dictionaries with unstable input details

        """
        report = []
        for input_hash in self.metrics.unstable_inputs:
            variants = self.metrics.execution_variance.get(input_hash, [])
            report.append(
                {
                    "input_hash": input_hash,
                    "unique_behaviors": len(variants),
                    "execution_count": len(self.execution_history.get(input_hash, [])),
                    "variants": variants[:5],  # First 5 variants
                }
            )

        return report

    def is_campaign_stable(self, threshold: float = 95.0) -> bool:
        """Check if campaign is considered stable.

        Args:
            threshold: Minimum stability percentage required

        Returns:
            True if stability >= threshold

        """
        return self.metrics.stability_percentage >= threshold

    def reset(self) -> None:
        """Reset all tracking data."""
        self.execution_history.clear()
        self.metrics = StabilityMetrics()
        self.iteration_count = 0
        self.retested_inputs.clear()

    def _check_stability(self, input_hash: str) -> bool:
        """Check if input shows stable behavior.

        Args:
            input_hash: Hash of input file

        Returns:
            True if stable (all executions have same signature)

        """
        signatures = self.execution_history.get(input_hash, [])

        if len(signatures) < 2:
            return True  # Need at least 2 to compare

        # Check if all signatures are the same
        return len(set(signatures)) == 1

    def _hash_file(self, file_path: Path) -> str:
        """Generate hash of file content.

        Args:
            file_path: Path to file

        Returns:
            SHA256 hash of file content (16 chars)

        """
        return hash_file_quick(file_path, 16)


def generate_execution_signature(
    exit_code: int, output_hash: str | None = None, coverage: "set[str] | None" = None
) -> str:
    """Generate signature for an execution.

    Combines exit code, output hash, and coverage into a single signature
    that can be used to detect non-deterministic behavior.

    Args:
        exit_code: Process exit code
        output_hash: Hash of stdout/stderr (optional)
        coverage: Set of covered code points (optional)

    Returns:
        Execution signature string

    """
    parts = [str(exit_code)]

    if output_hash:
        parts.append(output_hash)

    if coverage:
        # Sort coverage for consistency
        coverage_str = ",".join(sorted(str(c) for c in coverage))
        parts.append(md5_hash(coverage_str, 8))

    return "|".join(parts)


def detect_stability_issues(tracker: StabilityTracker) -> list[str]:
    """Analyze stability tracker and detect common issues.

    Args:
        tracker: StabilityTracker instance

    Returns:
        List of detected issues with recommendations

    """
    issues = []

    metrics = tracker.get_metrics()

    # Low overall stability
    if metrics.stability_percentage < 90.0:
        issues.append(
            f"Low stability detected ({metrics.stability_percentage:.1f}%). "
            "This may indicate uninitialized memory, race conditions, or "
            "entropy sources in the target application."
        )

    # Many unstable inputs
    if len(metrics.unstable_inputs) > 10:
        issues.append(
            f"{len(metrics.unstable_inputs)} inputs show non-deterministic behavior. "
            "Consider investigating with tools like AddressSanitizer or ThreadSanitizer."
        )

    # Gradual degradation
    if metrics.total_executions > 100:
        recent_stability = (
            metrics.stable_executions / metrics.total_executions
            if metrics.total_executions > 0
            else 1.0
        )
        if recent_stability < 0.8:
            issues.append(
                "Stability has degraded significantly. Check for memory leaks "
                "or accumulating state in the fuzzing harness."
            )

    return issues if issues else ["No stability issues detected"]
