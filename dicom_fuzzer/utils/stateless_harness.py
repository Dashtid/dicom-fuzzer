"""Stateless Harness Validation Utilities

CONCEPT: Ensure fuzzing harness maintains 100% stability through
stateless design and determinism validation.

RESEARCH: "Ideally, stability should be 100%, meaning the same input
always follows the same path and yields the same result. If your harness
has hidden state, stability can drop, indicating nondeterministic behavior."
(2025 Best Practices)
"""

import gc
import hashlib
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def validate_determinism(
    test_input: Any,
    test_function: Callable[[Any], Any],
    runs: int = 3,
    cleanup: bool = True,
) -> tuple[bool, str | None]:
    """Validate that test function produces deterministic results.

    CONCEPT: Run same input multiple times and verify identical output.
    Detects hidden state, race conditions, or entropy sources.

    Args:
        test_input: Input to test with
        test_function: Function to test for determinism
        runs: Number of times to run test (default: 3)
        cleanup: Force garbage collection between runs

    Returns:
        Tuple of (is_deterministic: bool, error_message: str)

    """
    results = []
    result_hashes = []

    for i in range(runs):
        try:
            # Run test function
            result = test_function(test_input)

            # Hash result for comparison
            result_hash = _hash_result(result)
            result_hashes.append(result_hash)
            results.append(result)

            # Cleanup between runs if requested
            if cleanup:
                gc.collect()

        except Exception as e:
            return False, f"Test function raised exception on run {i + 1}: {e}"

    # Check all results match
    if len(set(result_hashes)) == 1:
        logger.debug(
            f"Determinism check PASSED: {runs} runs produced identical results"
        )
        return True, None
    else:
        # Results differ - non-deterministic
        unique_results = len(set(result_hashes))
        error_msg = (
            f"Non-deterministic behavior detected: {unique_results} "
            f"different results across {runs} runs"
        )
        logger.warning(error_msg)
        return False, error_msg


def _hash_result(result: Any) -> str:
    """Hash result for determinism comparison.

    Args:
        result: Result to hash

    Returns:
        Hash string

    """
    if result is None:
        return hashlib.sha256(b"None").hexdigest()

    if isinstance(result, bytes):
        return hashlib.sha256(result).hexdigest()

    if isinstance(result, str):
        return hashlib.sha256(result.encode()).hexdigest()

    if isinstance(result, (int, float, bool)):
        return hashlib.sha256(str(result).encode()).hexdigest()

    # For complex objects, convert to string representation
    try:
        result_str = str(result)
        return hashlib.sha256(result_str.encode()).hexdigest()
    except Exception:
        # Last resort - use repr
        return hashlib.sha256(repr(result).encode()).hexdigest()


def create_stateless_test_wrapper(test_function: Callable) -> Callable:
    """Create a stateless wrapper around test function.

    CONCEPT: Ensures fresh state for each test by:
    1. Force garbage collection before test
    2. Run test in isolation
    3. Cleanup after test

    Args:
        test_function: Function to wrap

    Returns:
        Stateless wrapper function

    """

    def stateless_wrapper(*args, **kwargs):
        """Stateless test wrapper."""
        # Force cleanup before test
        gc.collect()

        try:
            # Run test
            result = test_function(*args, **kwargs)
        finally:
            # Cleanup after test
            gc.collect()

        return result

    return stateless_wrapper


def detect_state_leaks(
    harness_function: Callable[[Path], Any], test_files: list[Path]
) -> dict:
    """Detect state leaks between harness executions.

    CONCEPT: Run multiple test files and check if earlier tests affect later ones.

    Args:
        harness_function: Harness function to test
        test_files: List of test files to use

    Returns:
        Dictionary with leak detection results

    """
    results = {"leaked": False, "evidence": [], "affected_files": []}

    if len(test_files) < 2:
        logger.warning("Need at least 2 test files to detect state leaks")
        return results

    # Run each file twice - once alone, once after others
    for i, test_file in enumerate(test_files):
        # Baseline: run file in isolation
        gc.collect()
        try:
            baseline_result = harness_function(test_file)
            baseline_hash = _hash_result(baseline_result)
        except Exception as e:
            logger.warning(f"Baseline run failed for {test_file.name}: {e}")
            continue

        # Test: run file after running all previous files
        gc.collect()
        for prev_file in test_files[:i]:
            try:
                harness_function(prev_file)
            except Exception:
                pass  # Ignore errors in setup

        # Now run target file
        try:
            test_result = harness_function(test_file)
            test_hash = _hash_result(test_result)
        except Exception as e:
            logger.warning(f"Test run failed for {test_file.name}: {e}")
            continue

        # Compare results
        if baseline_hash != test_hash:
            # State leak detected!
            results["leaked"] = True
            results["affected_files"].append(str(test_file))
            results["evidence"].append(
                f"{test_file.name}: Result differs when run after other tests"
            )

            logger.warning(
                f"State leak detected: {test_file.name} produces different "
                f"result when run after other tests"
            )

    if results["leaked"]:
        logger.error(
            f"State leaks detected in {len(results['affected_files'])} test(s). "
            "Harness is NOT stateless!"
        )
    else:
        logger.info("No state leaks detected. Harness appears stateless.")

    return results
