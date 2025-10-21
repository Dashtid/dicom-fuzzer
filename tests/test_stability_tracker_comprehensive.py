"""Comprehensive tests for stability_tracker module.

Tests stability metrics tracking, instability detection, and root cause analysis.
"""

from dicom_fuzzer.core.stability_tracker import (
    InstabilityCause,
    StabilityMetrics,
    StabilityTracker,
)


class TestInstabilityCause:
    """Test InstabilityCause enum."""

    def test_all_causes_defined(self):
        """Test all instability causes are defined."""
        assert InstabilityCause.RACE_CONDITION
        assert InstabilityCause.UNINITIALIZED_MEMORY
        assert InstabilityCause.ENTROPY_SOURCE
        assert InstabilityCause.TIMING_DEPENDENT
        assert InstabilityCause.UNKNOWN

    def test_cause_values(self):
        """Test instability cause values."""
        assert InstabilityCause.RACE_CONDITION.value == "race_condition"
        assert InstabilityCause.ENTROPY_SOURCE.value == "entropy"
        assert InstabilityCause.UNKNOWN.value == "unknown"


class TestStabilityMetrics:
    """Test StabilityMetrics dataclass."""

    def test_initialization_defaults(self):
        """Test metrics initialize with default values."""
        metrics = StabilityMetrics()

        assert metrics.total_executions == 0
        assert metrics.stable_executions == 0
        assert metrics.unstable_executions == 0
        assert metrics.stability_percentage == 100.0
        assert len(metrics.unstable_inputs) == 0

    def test_initialization_custom_values(self):
        """Test metrics with custom values."""
        metrics = StabilityMetrics(
            total_executions=100,
            stable_executions=95,
            unstable_executions=5,
            stability_percentage=95.0,
        )

        assert metrics.total_executions == 100
        assert metrics.stable_executions == 95
        assert metrics.stability_percentage == 95.0

    def test_unstable_inputs_tracking(self):
        """Test tracking unstable inputs."""
        metrics = StabilityMetrics()
        metrics.unstable_inputs.add("input1.dcm")
        metrics.unstable_inputs.add("input2.dcm")

        assert len(metrics.unstable_inputs) == 2
        assert "input1.dcm" in metrics.unstable_inputs

    def test_string_representation(self):
        """Test string representation."""
        metrics = StabilityMetrics(
            total_executions=100, stable_executions=90, stability_percentage=90.0
        )

        str_repr = str(metrics)

        assert "90.0%" in str_repr
        assert "90/100" in str_repr
        assert "stable" in str_repr

    def test_execution_variance_tracking(self):
        """Test execution variance tracking."""
        metrics = StabilityMetrics()
        metrics.execution_variance["input1"] = ["hash1", "hash2"]

        assert "input1" in metrics.execution_variance
        assert len(metrics.execution_variance["input1"]) == 2

    def test_cause_counts_tracking(self):
        """Test instability cause counting."""
        metrics = StabilityMetrics()
        metrics.cause_counts[InstabilityCause.RACE_CONDITION] = 5
        metrics.cause_counts[InstabilityCause.ENTROPY_SOURCE] = 3

        assert metrics.cause_counts[InstabilityCause.RACE_CONDITION] == 5
        assert metrics.cause_counts[InstabilityCause.ENTROPY_SOURCE] == 3


class TestStabilityTrackerInitialization:
    """Test StabilityTracker initialization."""

    def test_default_initialization(self):
        """Test tracker with default parameters."""
        tracker = StabilityTracker()

        assert isinstance(tracker.metrics, StabilityMetrics)
        assert tracker.stability_window == 100
        assert tracker.retest_frequency == 10

    def test_custom_parameters(self):
        """Test tracker with custom parameters."""
        tracker = StabilityTracker(stability_window=50, retest_frequency=5)

        assert tracker.stability_window == 50
        assert tracker.retest_frequency == 5

    def test_metrics_initialization(self):
        """Test metrics are properly initialized."""
        tracker = StabilityTracker()

        assert tracker.metrics.total_executions == 0
        assert tracker.metrics.stability_percentage == 100.0


class TestStabilityCalculation:
    """Test stability percentage calculation."""

    def test_perfect_stability(self, temp_dir):
        """Test calculation with perfect stability."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Record same execution signature multiple times (stable)
        for _ in range(5):
            tracker.record_execution(test_file, "signature1", retest=True)

        # Should be 100% stable (all executions have same signature)
        assert tracker.metrics.stability_percentage == 100.0
        assert tracker.metrics.stable_executions == 5  # All retests are stable

    def test_partial_stability(self, temp_dir):
        """Test calculation with partial stability."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Mix of stable and unstable executions
        tracker.record_execution(test_file, "signature1", retest=False)
        tracker.record_execution(test_file, "signature1", retest=True)  # Stable
        tracker.record_execution(test_file, "signature2", retest=True)  # Unstable
        tracker.record_execution(test_file, "signature2", retest=True)  # Stable again

        # Should have some instability
        assert tracker.metrics.unstable_executions > 0

    def test_zero_executions(self):
        """Test calculation with zero executions."""
        tracker = StabilityTracker()

        # Default should be 100% with no executions
        assert tracker.metrics.stability_percentage == 100.0
        assert tracker.metrics.total_executions == 0


class TestExecutionTracking:
    """Test execution tracking."""

    def test_record_stable_execution(self, temp_dir):
        """Test recording stable execution."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Record same signature twice - should be stable
        tracker.record_execution(test_file, "signature1", retest=False)
        assert tracker.metrics.total_executions == 1

        is_stable = tracker.record_execution(test_file, "signature1", retest=True)
        assert tracker.metrics.total_executions == 2
        assert is_stable is True
        assert tracker.metrics.stable_executions == 1

    def test_record_unstable_execution(self, temp_dir):
        """Test recording unstable execution."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Record different signatures - should be unstable
        tracker.record_execution(test_file, "signature1", retest=False)
        is_stable = tracker.record_execution(test_file, "signature2", retest=True)

        assert is_stable is False
        assert tracker.metrics.total_executions == 2
        assert tracker.metrics.unstable_executions == 1

    def test_multiple_executions(self, temp_dir):
        """Test recording multiple executions."""
        tracker = StabilityTracker()

        # Create multiple test files
        file1 = temp_dir / "test1.dcm"
        file2 = temp_dir / "test2.dcm"
        file3 = temp_dir / "test3.dcm"

        file1.write_text("content1")
        file2.write_text("content2")
        file3.write_text("content3")

        # Record executions for different files
        tracker.record_execution(file1, "sig1", retest=False)
        tracker.record_execution(file2, "sig2", retest=False)
        tracker.record_execution(file3, "sig3", retest=False)

        assert tracker.metrics.total_executions == 3


class TestStabilityThresholds:
    """Test stability threshold checking."""

    def test_meets_target_stability(self, temp_dir):
        """Test checking if target stability is met."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Create 95% stability (95 stable out of 100)
        for i in range(100):
            sig = "stable_sig" if i < 95 else f"unstable_sig_{i}"
            tracker.record_execution(test_file, sig, retest=(i > 0))

        # Should meet 90% threshold
        is_stable = tracker.is_campaign_stable(threshold=90.0)
        assert is_stable is True

    def test_below_target_stability(self, temp_dir):
        """Test detection of below-target stability."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Create many unstable executions
        for i in range(20):
            # Different signature each time - very unstable
            tracker.record_execution(test_file, f"sig_{i}", retest=(i > 0))

        # Should not meet 90% threshold
        is_stable = tracker.is_campaign_stable(threshold=90.0)
        assert is_stable is False


class TestMetricsRetrieval:
    """Test metrics retrieval."""

    def test_get_metrics(self, temp_dir):
        """Test retrieving metrics."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        tracker.record_execution(test_file, "sig1", retest=False)

        metrics = tracker.get_metrics()

        assert isinstance(metrics, StabilityMetrics)
        assert metrics.total_executions == 1

    def test_get_unstable_inputs(self, temp_dir):
        """Test retrieving unstable inputs."""
        tracker = StabilityTracker()

        file1 = temp_dir / "unstable1.dcm"
        file2 = temp_dir / "unstable2.dcm"
        file1.write_text("content1")
        file2.write_text("content2")

        # Create unstable executions
        tracker.record_execution(file1, "sig1", retest=False)
        tracker.record_execution(file1, "sig2", retest=True)  # Unstable

        tracker.record_execution(file2, "sig3", retest=False)
        tracker.record_execution(file2, "sig4", retest=True)  # Unstable

        report = tracker.get_unstable_inputs_report()

        assert len(report) == 2
        assert all("input_hash" in item for item in report)


class TestIntegrationScenarios:
    """Test integration scenarios."""

    def test_complete_stability_tracking_workflow(self, temp_dir):
        """Test complete stability tracking workflow."""
        tracker = StabilityTracker()

        # Create test files
        stable_file = temp_dir / "stable.dcm"
        unstable_file = temp_dir / "unstable.dcm"
        stable_file.write_text("stable content")
        unstable_file.write_text("unstable content")

        # Simulate fuzzing campaign with mix of stable/unstable
        for i in range(50):
            # Stable file always produces same signature
            tracker.record_execution(stable_file, "stable_sig", retest=(i > 0))

        for i in range(50):
            # Unstable file produces different signatures
            sig = f"unstable_sig_{i % 5}"  # 5 different signatures
            tracker.record_execution(unstable_file, sig, retest=(i > 0))

        metrics = tracker.get_metrics()

        # Should have tracked both stable and unstable executions
        assert metrics.total_executions == 100
        assert metrics.unstable_executions > 0

    def test_detecting_instability_issues(self, temp_dir):
        """Test detecting instability issues."""
        tracker = StabilityTracker()
        test_file = temp_dir / "problematic.dcm"
        test_file.write_text("test content")

        # Simulate non-deterministic behavior
        signatures = ["sig_a", "sig_b", "sig_c"]
        for i in range(30):
            sig = signatures[i % 3]  # Cycles through 3 different signatures
            tracker.record_execution(test_file, sig, retest=(i > 0))

        # Should detect instability
        assert tracker.metrics.unstable_executions > 0
        assert len(tracker.metrics.unstable_inputs) > 0

        # Should have report available
        report = tracker.get_unstable_inputs_report()
        assert len(report) > 0
        assert report[0]["unique_behaviors"] >= 2

    def test_stability_improvement_tracking(self, temp_dir):
        """Test tracking stability improvements."""
        tracker = StabilityTracker()
        test_file = temp_dir / "improving.dcm"
        test_file.write_text("test content")

        # Start unstable
        for i in range(10):
            sig = f"random_sig_{i}"
            tracker.record_execution(test_file, sig, retest=(i > 0))

        early_stability = tracker.metrics.stability_percentage

        # Reset and try again with more stable behavior
        tracker.reset()

        # Now much more stable
        for i in range(50):
            sig = "consistent_sig"
            tracker.record_execution(test_file, sig, retest=(i > 0))

        later_stability = tracker.metrics.stability_percentage

        # Later should be more stable
        assert later_stability > early_stability


class TestShouldRetest:
    """Test retest decision logic."""

    def test_retest_frequency(self, temp_dir):
        """Test that retest happens at correct frequency."""
        tracker = StabilityTracker(retest_frequency=10)
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Record initial execution
        tracker.record_execution(test_file, "sig1", retest=False)

        # Should not retest initially
        for i in range(9):
            should_retest = tracker.should_retest(test_file)
            assert should_retest is False

        # Should retest on 10th iteration
        should_retest = tracker.should_retest(test_file)
        assert should_retest is True

    def test_no_duplicate_retests(self, temp_dir):
        """Test that same input is not retested multiple times."""
        tracker = StabilityTracker(retest_frequency=5)
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Record initial execution
        tracker.record_execution(test_file, "sig1", retest=False)

        # should_retest increments iteration_count each call
        # First 4 calls: iteration_count = 1,2,3,4 (not multiples of 5)
        for _ in range(4):
            should_retest = tracker.should_retest(test_file)
            assert should_retest is False

        # 5th call: iteration_count = 5 (multiple of 5, has 1 execution)
        should_retest_first = tracker.should_retest(test_file)
        assert should_retest_first is True

        # Now the input is in retested_inputs

        # Next 4 calls: iteration_count = 6,7,8,9
        for _ in range(4):
            tracker.should_retest(test_file)

        # 10th call: iteration_count = 10 (multiple of 5, but already retested)
        should_retest_second = tracker.should_retest(test_file)
        assert should_retest_second is False  # Already in retested_inputs


class TestReset:
    """Test reset functionality."""

    def test_reset_clears_all_data(self, temp_dir):
        """Test that reset clears all tracking data."""
        tracker = StabilityTracker()
        test_file = temp_dir / "test.dcm"
        test_file.write_text("test content")

        # Add some data
        tracker.record_execution(test_file, "sig1", retest=False)
        tracker.record_execution(test_file, "sig2", retest=True)

        assert tracker.metrics.total_executions > 0

        # Reset
        tracker.reset()

        # Should be back to defaults
        assert tracker.metrics.total_executions == 0
        assert tracker.metrics.stability_percentage == 100.0
        assert len(tracker.execution_history) == 0
        assert tracker.iteration_count == 0
