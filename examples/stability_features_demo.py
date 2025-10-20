"""
DICOM Fuzzer Stability Features Demo

Demonstrates the new stability enhancements added in 2025:
- Corpus minimization
- Stateless harness validation
- Timeout budget management
- Coverage correlation analysis

Usage:
    python examples/stability_features_demo.py
"""

import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def demo_corpus_minimization():
    """
    Demonstrate corpus minimization before fuzzing campaign.

    CONCEPT: Reduce corpus size by removing redundant seeds that don't
    add new coverage.
    """
    print("\n" + "=" * 70)
    print("DEMO 1: Corpus Minimization")
    print("=" * 70)

    from dicom_fuzzer.utils.corpus_minimization import (
        minimize_corpus_for_campaign,
        validate_corpus_quality,
    )

    # Example corpus directory (adjust path)
    corpus_dir = Path("./data/seeds")
    output_dir = Path("./artifacts/minimized_corpus")

    if not corpus_dir.exists():
        print(f"[!] Corpus directory not found: {corpus_dir}")
        print("    Creating example corpus...")
        corpus_dir.mkdir(parents=True, exist_ok=True)
        print(f"    Add DICOM files to {corpus_dir} and re-run")
        return

    # Validate corpus quality
    print("\n[*] Validating corpus quality...")
    metrics = validate_corpus_quality(corpus_dir)

    print("\nCorpus Statistics:")
    print(f"  Total Files:     {metrics['total_files']:,}")
    print(f"  Total Size:      {metrics['total_size_mb']:.1f} MB")
    print(f"  Avg File Size:   {metrics['avg_file_size_kb']:.1f} KB")
    print(f"  Size Range:      {metrics['min_size_kb']:.1f} - {metrics['max_size_kb']:.1f} KB")
    print(f"  Valid DICOM:     {metrics['valid_dicom']:,}")
    print(f"  Corrupted:       {metrics['corrupted']:,}")

    # Minimize corpus
    print("\n[*] Minimizing corpus...")
    print(f"    Source: {corpus_dir}")
    print(f"    Output: {output_dir}")

    minimized_files = minimize_corpus_for_campaign(
        corpus_dir=corpus_dir,
        output_dir=output_dir,
        max_corpus_size=500,
    )

    print("\n[+] Corpus minimized successfully!")
    print(f"    Minimized corpus: {len(minimized_files)} files")
    print(f"    Location: {output_dir}")


def demo_stateless_harness_validation():
    """
    Demonstrate stateless harness validation.

    CONCEPT: Ensure fuzzing harness maintains 100% stability through
    determinism validation.
    """
    print("\n" + "=" * 70)
    print("DEMO 2: Stateless Harness Validation")
    print("=" * 70)

    from dicom_fuzzer.utils.stateless_harness import (
        validate_determinism,
        create_stateless_test_wrapper,
    )

    # Example test function
    def example_harness(test_input):
        """Example fuzzing harness (stateless)."""
        import hashlib

        return hashlib.sha256(str(test_input).encode()).hexdigest()

    # Example test function with hidden state (BAD)
    class StatefulHarness:
        """Example of stateful harness (NOT recommended)."""

        def __init__(self):
            self.counter = 0

        def __call__(self, test_input):
            self.counter += 1
            return f"{test_input}_{self.counter}"

    print("\n[*] Testing stateless harness...")
    test_input = "example_test_data"

    is_deterministic, error = validate_determinism(
        test_input=test_input,
        test_function=example_harness,
        runs=5,
    )

    if is_deterministic:
        print("[+] Harness is deterministic (stateless)")
    else:
        print(f"[-] Harness is NON-deterministic: {error}")

    # Test stateful harness (should fail)
    print("\n[*] Testing stateful harness (should fail)...")
    stateful = StatefulHarness()

    is_deterministic, error = validate_determinism(
        test_input=test_input,
        test_function=stateful,
        runs=5,
    )

    if is_deterministic:
        print("[!] Unexpected: stateful harness appears deterministic")
    else:
        print("[+] Correctly detected non-deterministic behavior:")
        print(f"    {error}")

    # Demonstrate stateless wrapper
    print("\n[*] Creating stateless wrapper...")
    wrapped_harness = create_stateless_test_wrapper(example_harness)
    result = wrapped_harness(test_input)
    print(f"[+] Wrapper ensures cleanup: {result[:16]}...")


def demo_timeout_budget_management():
    """
    Demonstrate timeout budget management.

    CONCEPT: Prevent wasting time on consistently slow/hanging inputs
    through adaptive timeout adjustment.
    """
    print("\n" + "=" * 70)
    print("DEMO 3: Timeout Budget Management")
    print("=" * 70)

    from dicom_fuzzer.utils.timeout_budget import (
        TimeoutBudgetManager,
        ExecutionTimer,
    )
    import time

    # Initialize timeout budget manager
    print("\n[*] Initializing timeout budget manager...")
    budget = TimeoutBudgetManager(
        max_timeout_ratio=0.10,  # Max 10% time on timeouts
        min_timeout=1.0,
        max_timeout=10.0,
        adjustment_interval=10,
    )

    print(f"    Max timeout ratio: {budget.max_timeout_ratio * 100:.0f}%")
    print(f"    Timeout range: [{budget.min_timeout}, {budget.max_timeout}]s")

    # Simulate fuzzing campaign
    print("\n[*] Simulating fuzzing campaign...")

    for i in range(50):
        with ExecutionTimer() as timer:
            # Simulate execution
            if i % 5 == 0:
                # Simulate timeout every 5 iterations
                time.sleep(0.1)
                timed_out = True
            else:
                # Simulate successful run
                time.sleep(0.01)
                timed_out = False

        # Record execution
        budget.record_execution(duration=timer.duration, timed_out=timed_out)

        if (i + 1) % 10 == 0:
            stats = budget.get_statistics()
            print(
                f"    Iteration {i + 1}: "
                f"Timeout ratio={stats.timeout_ratio * 100:.1f}%, "
                f"Current timeout={budget.current_timeout:.2f}s"
            )

    # Generate report
    print("\n" + budget.generate_report())


def demo_coverage_correlation():
    """
    Demonstrate coverage correlation analysis.

    CONCEPT: Identify which code paths are most strongly associated
    with crashes.
    """
    print("\n" + "=" * 70)
    print("DEMO 4: Coverage Correlation Analysis")
    print("=" * 70)

    from dicom_fuzzer.utils.coverage_correlation import (
        correlate_crashes_with_coverage,
        generate_correlation_report,
    )
    from dataclasses import dataclass

    # Mock crash record
    @dataclass
    class MockCrash:
        crash_id: str
        test_case_path: str

    # Example data
    print("\n[*] Setting up example coverage data...")

    # Simulated coverage data
    coverage_data = {
        "safe_input_1.dcm": {"func_a", "func_b", "func_c"},
        "safe_input_2.dcm": {"func_a", "func_b", "func_d"},
        "safe_input_3.dcm": {"func_a", "func_c", "func_d"},
        "crash_input_1.dcm": {"func_a", "func_e", "func_vuln"},  # Crash path
        "crash_input_2.dcm": {"func_b", "func_e", "func_vuln"},  # Crash path
        "crash_input_3.dcm": {"func_a", "func_vuln"},  # Crash path
    }

    # Simulated crashes
    crashes = [
        MockCrash(crash_id="crash_001", test_case_path="crash_input_1.dcm"),
        MockCrash(crash_id="crash_002", test_case_path="crash_input_2.dcm"),
        MockCrash(crash_id="crash_003", test_case_path="crash_input_3.dcm"),
    ]

    safe_inputs = ["safe_input_1.dcm", "safe_input_2.dcm", "safe_input_3.dcm"]

    print(f"    Coverage points: {len(set().union(*coverage_data.values()))}")
    print(f"    Safe inputs: {len(safe_inputs)}")
    print(f"    Crashes: {len(crashes)}")

    # Perform correlation analysis
    print("\n[*] Performing coverage correlation analysis...")

    correlation = correlate_crashes_with_coverage(
        crashes=crashes,
        coverage_data=coverage_data,
        safe_inputs=safe_inputs,
    )

    # Generate and display report
    print("\n" + generate_correlation_report(correlation, top_n=10))

    # Show crash-only paths
    print("[*] Crash-only code paths (never hit during safe execution):")
    for crash_id, paths in correlation.crash_only_coverage.items():
        print(f"    {crash_id}: {paths}")


def main():
    """Run all stability feature demos."""
    print("\n")
    print("=" * 70)
    print("DICOM FUZZER STABILITY FEATURES DEMONSTRATION")
    print("=" * 70)
    print("\nThis demo showcases new stability enhancements based on")
    print("2025 fuzzing best practices research.")
    print("\nFeatures:")
    print("  1. Corpus Minimization")
    print("  2. Stateless Harness Validation")
    print("  3. Timeout Budget Management")
    print("  4. Coverage Correlation Analysis")

    try:
        # Run demos
        demo_corpus_minimization()
        demo_stateless_harness_validation()
        demo_timeout_budget_management()
        demo_coverage_correlation()

        print("\n" + "=" * 70)
        print("DEMO COMPLETE")
        print("=" * 70)
        print("\n[+] All stability features demonstrated successfully!")
        print("\nNext steps:")
        print("  - Review STABILITY_IMPROVEMENTS.md for full documentation")
        print("  - Integrate features into your fuzzing campaigns")
        print("  - Run pre-flight health checks before campaigns")
        print("  - Monitor stability metrics during fuzzing")

    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        print(f"\n[ERROR] Demo encountered an error: {e}")
        print("See logs above for details.")


if __name__ == "__main__":
    main()
