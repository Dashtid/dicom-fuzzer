"""
Tests for stability metrics tracking.
"""

import pytest

from dicom_fuzzer.core.stability_tracker import (
    StabilityMetrics,
    StabilityTracker,
    detect_stability_issues,
    generate_execution_signature,
)


@pytest.fixture
def tracker():
    """Create a stability tracker instance."""
    return StabilityTracker(stability_window=10, retest_frequency=5)


@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file."""
    test_file = tmp_path / "test.dcm"
    test_file.write_bytes(b"TEST_CONTENT_123")
    return test_file


class TestStabilityMetrics:
    """Test StabilityMetrics dataclass."""

    def test_default_initialization(self):
        """Test default metrics initialization."""
        metrics = StabilityMetrics()

        assert metrics.total_executions == 0
        assert metrics.stable_executions == 0
        assert metrics.unstable_executions == 0
        assert metrics.stability_percentage == 100.0
        assert len(metrics.unstable_inputs) == 0
        assert len(metrics.execution_variance) == 0

    def test_str_representation(self):
        """Test string representation."""
        metrics = StabilityMetrics(
            total_executions=10, stable_executions=9, stability_percentage=90.0
        )

        metrics_str = str(metrics)
        assert "90.0%" in metrics_str
        assert "9/10" in metrics_str


class TestGenerateExecutionSignature:
    """Test execution signature generation."""

    def test_exit_code_only(self):
        """Test signature with only exit code."""
        sig = generate_execution_signature(exit_code=0)
        assert sig == "0"

    def test_with_output_hash(self):
        """Test signature with output hash."""
        sig = generate_execution_signature(exit_code=0, output_hash="abc123")
        assert sig == "0|abc123"

    def test_with_coverage(self):
        """Test signature with coverage."""
        coverage = {1, 2, 3}
        sig = generate_execution_signature(exit_code=0, coverage=coverage)

        assert sig.startswith("0|")
        assert len(sig.split("|")) == 2

    def test_with_all_components(self):
        """Test signature with all components."""
        coverage = {10, 20, 30}
        sig = generate_execution_signature(
            exit_code=0, output_hash="xyz789", coverage=coverage
        )

        parts = sig.split("|")
        assert len(parts) == 3
        assert parts[0] == "0"
        assert parts[1] == "xyz789"

    def test_coverage_consistency(self):
        """Test that same coverage produces same signature."""
        coverage1 = {3, 1, 2}  # Different order
        coverage2 = {1, 2, 3}  # Different order

        sig1 = generate_execution_signature(exit_code=0, coverage=coverage1)
        sig2 = generate_execution_signature(exit_code=0, coverage=coverage2)

        assert sig1 == sig2  # Should be same due to sorting


class TestStabilityTracker:
    """Test StabilityTracker functionality."""

    def test_initialization(self, tracker):
        """Test tracker initialization."""
        assert tracker.stability_window == 10
        assert tracker.retest_frequency == 5
        assert tracker.metrics.total_executions == 0
        assert tracker.iteration_count == 0

    def test_record_stable_execution(self, tracker, temp_test_file):
        """Test recording a stable execution."""
        signature = "0|abc123"

        # First execution
        is_stable = tracker.record_execution(temp_test_file, signature)
        assert is_stable is True
        assert tracker.metrics.total_executions == 1

        # Second execution with same signature
        is_stable = tracker.record_execution(temp_test_file, signature, retest=True)
        assert is_stable is True
        assert tracker.metrics.stable_executions == 1
        assert tracker.metrics.unstable_executions == 0

    def test_record_unstable_execution(self, tracker, temp_test_file):
        """Test recording an unstable execution."""
        signature1 = "0|abc123"
        signature2 = "0|xyz789"  # Different signature

        # First execution
        tracker.record_execution(temp_test_file, signature1)

        # Second execution with different signature
        is_stable = tracker.record_execution(temp_test_file, signature2, retest=True)

        assert is_stable is False
        assert tracker.metrics.unstable_executions == 1
        assert len(tracker.metrics.unstable_inputs) == 1

    def test_stability_percentage_calculation(self, tracker, temp_test_file):
        """Test stability percentage calculation."""
        # Record 2 stable retests
        for _ in range(2):
            tracker.record_execution(temp_test_file, "0|stable", retest=True)

        # Create different file for unstable test
        unstable_file = temp_test_file.parent / "unstable.dcm"
        unstable_file.write_bytes(b"UNSTABLE")

        tracker.record_execution(unstable_file, "0|sig1")
        tracker.record_execution(unstable_file, "0|sig2", retest=True)

        # 2 stable executions, 1 unstable, out of 4 total = 50.0%
        # (2 stable + 1 unstable = 3 retests that were evaluated, plus 1 first execution)
        metrics = tracker.get_metrics()
        assert metrics.total_executions == 4
        assert metrics.stable_executions == 2
        assert metrics.unstable_executions == 1
        assert metrics.stability_percentage == 50.0

    def test_stability_window_limiting(self, tracker, temp_test_file):
        """Test that execution history is limited by window size."""
        # Record more executions than window size
        for i in range(15):
            tracker.record_execution(temp_test_file, f"sig_{i}")

        input_hash = tracker._hash_file(temp_test_file)
        history = tracker.execution_history[input_hash]

        # Should be limited to window size (10)
        assert len(history) == tracker.stability_window

    def test_should_retest_frequency(self, tracker, temp_test_file):
        """Test retest frequency logic."""
        # Record initial execution
        tracker.record_execution(temp_test_file, "0|sig1")

        # Check retest logic
        for i in range(10):
            should_retest = tracker.should_retest(temp_test_file)

            # Should retest at frequency intervals
            if (i + 1) % tracker.retest_frequency == 0:
                # First time at this interval
                if i == 4:
                    assert should_retest is True
                else:
                    # Already retested
                    assert should_retest is False
            else:
                assert should_retest is False

    def test_get_unstable_inputs_report(self, tracker, temp_test_file):
        """Test unstable inputs report generation."""
        # Create unstable execution
        tracker.record_execution(temp_test_file, "0|sig1")
        tracker.record_execution(temp_test_file, "0|sig2", retest=True)
        tracker.record_execution(temp_test_file, "0|sig3", retest=True)

        report = tracker.get_unstable_inputs_report()

        assert len(report) == 1
        assert report[0]["unique_behaviors"] == 3
        assert "input_hash" in report[0]
        assert "variants" in report[0]

    def test_is_campaign_stable(self, tracker, temp_test_file):
        """Test campaign stability check."""
        # Record stable executions
        for _ in range(10):
            tracker.record_execution(temp_test_file, "0|stable", retest=True)

        assert tracker.is_campaign_stable(threshold=95.0) is True

        # Add unstable execution
        unstable_file = temp_test_file.parent / "unstable.dcm"
        unstable_file.write_bytes(b"UNSTABLE")
        tracker.record_execution(unstable_file, "0|sig1")
        tracker.record_execution(unstable_file, "0|sig2", retest=True)

        # Stability should now be below 95%
        assert tracker.is_campaign_stable(threshold=95.0) is False

    def test_reset(self, tracker, temp_test_file):
        """Test tracker reset."""
        # Record some data
        tracker.record_execution(temp_test_file, "0|sig1")
        tracker.record_execution(temp_test_file, "0|sig2", retest=True)

        # Reset
        tracker.reset()

        assert tracker.metrics.total_executions == 0
        assert tracker.metrics.stable_executions == 0
        assert len(tracker.execution_history) == 0
        assert tracker.iteration_count == 0

    def test_multiple_different_files(self, tracker, tmp_path):
        """Test tracking multiple different files."""
        files = []
        for i in range(3):
            f = tmp_path / f"file{i}.dcm"
            f.write_bytes(f"CONTENT_{i}".encode())
            files.append(f)

        # Record executions for different files
        for f in files:
            tracker.record_execution(f, "0|sig1")
            tracker.record_execution(f, "0|sig1", retest=True)

        # All should be stable
        assert tracker.metrics.stable_executions == 3
        assert tracker.metrics.unstable_executions == 0

    def test_variance_tracking(self, tracker, temp_test_file):
        """Test that execution variance is tracked."""
        signatures = ["0|sig1", "0|sig2", "0|sig3"]

        for sig in signatures:
            tracker.record_execution(temp_test_file, sig, retest=True)

        input_hash = tracker._hash_file(temp_test_file)
        variance = tracker.metrics.execution_variance.get(input_hash, [])

        # Should have all unique signatures
        assert len(variance) == 3


class TestDetectStabilityIssues:
    """Test stability issue detection."""

    def test_no_issues(self, tmp_path):
        """Test when no issues are detected."""
        tracker = StabilityTracker()
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"TEST")

        # Record perfectly stable executions
        for _ in range(20):
            tracker.record_execution(test_file, "0|stable", retest=True)

        issues = detect_stability_issues(tracker)
        assert len(issues) == 1
        assert "No stability issues" in issues[0]

    def test_low_stability_detected(self, tmp_path):
        """Test detection of low stability."""
        tracker = StabilityTracker()

        # Create multiple files with varying signatures to create low stability
        for i in range(20):
            f = tmp_path / f"file{i}.dcm"
            f.write_bytes(f"CONTENT_{i}".encode())

            # First execution
            tracker.record_execution(f, f"0|sig{i % 2}")
            # Retest with different signature to create instability
            tracker.record_execution(f, f"0|sig{(i + 1) % 2}", retest=True)

        issues = detect_stability_issues(tracker)

        # Should detect low stability (will be around 0% since all retests are unstable)
        assert any("Low stability" in issue for issue in issues)

    def test_many_unstable_inputs_detected(self, tmp_path):
        """Test detection of many unstable inputs."""
        tracker = StabilityTracker()

        # Create 15 unstable inputs
        for i in range(15):
            f = tmp_path / f"file{i}.dcm"
            f.write_bytes(f"CONTENT_{i}".encode())
            tracker.record_execution(f, "0|sig1")
            tracker.record_execution(f, "0|sig2", retest=True)

        issues = detect_stability_issues(tracker)

        # Should detect many unstable inputs
        assert any("inputs show non-deterministic" in issue for issue in issues)

    def test_gradual_degradation_detected(self, tmp_path):
        """Test detection of gradual stability degradation with >100 executions.

        Covers lines 328-334 in stability_tracker.py.
        """
        tracker = StabilityTracker()

        # Create test files
        files = []
        for i in range(20):
            f = tmp_path / f"file{i}.dcm"
            f.write_bytes(f"CONTENT_{i}".encode())
            files.append(f)

        # Run >100 executions with low stability (< 80%)
        # Mix stable and unstable to get below 80% stability
        for iteration in range(6):
            for i, f in enumerate(files):
                if i < 4:
                    # These files are stable
                    tracker.record_execution(f, "0|stable_sig")
                    if iteration > 0:
                        tracker.record_execution(f, "0|stable_sig", retest=True)
                else:
                    # These files are unstable (majority)
                    tracker.record_execution(f, f"0|sig_{iteration}")
                    if iteration > 0:
                        # Different signature on retest
                        tracker.record_execution(
                            f, f"0|sig_{iteration + 10}", retest=True
                        )

        # Ensure we have >100 executions
        metrics = tracker.get_metrics()
        assert metrics.total_executions > 100

        # Stability should be low (< 80%)
        assert metrics.stability_percentage < 80

        issues = detect_stability_issues(tracker)

        # Should detect gradual degradation
        assert any("Stability has degraded" in issue for issue in issues)


class TestIntegration:
    """Integration tests for stability tracking."""

    def test_realistic_fuzzing_scenario(self, tmp_path):
        """Test realistic fuzzing scenario with mixed stability."""
        tracker = StabilityTracker(stability_window=50, retest_frequency=10)

        # Create corpus of test files
        stable_files = []
        unstable_files = []

        for i in range(5):
            f = tmp_path / f"stable{i}.dcm"
            f.write_bytes(f"STABLE_{i}".encode())
            stable_files.append(f)

        for i in range(2):
            f = tmp_path / f"unstable{i}.dcm"
            f.write_bytes(f"UNSTABLE_{i}".encode())
            unstable_files.append(f)

        # Simulate fuzzing campaign
        iteration = 0
        for _ in range(10):
            # Run stable files
            for f in stable_files:
                tracker.record_execution(f, "0|stable_sig")
                iteration += 1

                if tracker.should_retest(f):
                    tracker.record_execution(f, "0|stable_sig", retest=True)

            # Run unstable files (non-deterministic)
            for i, f in enumerate(unstable_files):
                sig = f"0|unstable_sig_{iteration % 3}"  # Varies
                tracker.record_execution(f, sig)
                iteration += 1

                if tracker.should_retest(f):
                    sig_retest = f"0|unstable_sig_{(iteration + 1) % 3}"
                    tracker.record_execution(f, sig_retest, retest=True)

        # Check results
        metrics = tracker.get_metrics()
        assert metrics.total_executions > 0

        # Stability should be moderate (mix of stable and unstable files)
        # With 5 stable files and 2 unstable files, expect around 60-70%
        assert 60 <= metrics.stability_percentage <= 70

        # Should detect unstable inputs
        assert len(metrics.unstable_inputs) >= 2  # Both unstable files

        # Campaign should not be considered fully stable
        assert tracker.is_campaign_stable(threshold=98.0) is False
        # But should pass with lower threshold
        assert tracker.is_campaign_stable(threshold=60.0) is True

        # Get report
        report = tracker.get_unstable_inputs_report()
        assert len(report) == 2  # Exactly 2 unstable files
