"""Tests for Stability Tracker Module.

Tests cover:
- InstabilityCause enum
- StabilityMetrics dataclass
- StabilityTracker class
- generate_execution_signature function
- detect_stability_issues function
"""

import pytest

from dicom_fuzzer.core.stability_tracker import (
    InstabilityCause,
    StabilityMetrics,
    StabilityTracker,
    detect_stability_issues,
    generate_execution_signature,
)


class TestInstabilityCause:
    """Test InstabilityCause enum."""

    def test_all_causes_exist(self):
        """Test that all expected causes are defined."""
        assert InstabilityCause.RACE_CONDITION.value == "race_condition"
        assert InstabilityCause.UNINITIALIZED_MEMORY.value == "uninitialized"
        assert InstabilityCause.ENTROPY_SOURCE.value == "entropy"
        assert InstabilityCause.TIMING_DEPENDENT.value == "timing"
        assert InstabilityCause.UNKNOWN.value == "unknown"

    def test_cause_count(self):
        """Test that exactly 5 causes are defined."""
        causes = list(InstabilityCause)
        assert len(causes) == 5


class TestStabilityMetrics:
    """Test StabilityMetrics dataclass."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = StabilityMetrics()

        assert metrics.total_executions == 0
        assert metrics.stable_executions == 0
        assert metrics.unstable_executions == 0
        assert metrics.stability_percentage == 100.0
        assert metrics.unstable_inputs == set()
        assert metrics.execution_variance == {}
        assert metrics.instability_causes == {}

    def test_custom_values(self):
        """Test creating metrics with custom values."""
        metrics = StabilityMetrics(
            total_executions=100,
            stable_executions=95,
            unstable_executions=5,
            stability_percentage=95.0,
            unstable_inputs={"hash1", "hash2"},
        )

        assert metrics.total_executions == 100
        assert metrics.stable_executions == 95
        assert metrics.unstable_executions == 5
        assert metrics.stability_percentage == 95.0
        assert len(metrics.unstable_inputs) == 2

    def test_str_representation(self):
        """Test string representation of metrics."""
        metrics = StabilityMetrics(
            total_executions=100,
            stable_executions=95,
            stability_percentage=95.0,
        )

        result = str(metrics)
        assert "95.0%" in result
        assert "95/100" in result
        assert "stable" in result

    def test_cause_counts_default_factory(self):
        """Test that cause_counts uses defaultdict."""
        metrics = StabilityMetrics()

        # Access non-existent key should return 0
        assert metrics.cause_counts[InstabilityCause.UNKNOWN] == 0

        # Increment should work
        metrics.cause_counts[InstabilityCause.RACE_CONDITION] += 1
        assert metrics.cause_counts[InstabilityCause.RACE_CONDITION] == 1


class TestStabilityTracker:
    """Test StabilityTracker class."""

    def test_init_default_values(self):
        """Test tracker initialization with defaults."""
        tracker = StabilityTracker()

        assert tracker.stability_window == 100
        assert tracker.retest_frequency == 10
        assert tracker.iteration_count == 0
        assert len(tracker.execution_history) == 0
        assert len(tracker.retested_inputs) == 0

    def test_init_custom_values(self):
        """Test tracker initialization with custom values."""
        tracker = StabilityTracker(stability_window=50, retest_frequency=5)

        assert tracker.stability_window == 50
        assert tracker.retest_frequency == 5

    def test_record_execution_first_time(self, sample_dicom_file):
        """Test recording first execution of a file."""
        tracker = StabilityTracker()

        result = tracker.record_execution(sample_dicom_file, "exit:0|hash:abc123")

        # First execution is always considered stable
        assert result is True
        assert tracker.metrics.total_executions == 1

    def test_record_execution_stable(self, sample_dicom_file):
        """Test recording stable executions (same signature)."""
        tracker = StabilityTracker()
        signature = "exit:0|hash:abc123"

        # Record same signature twice
        tracker.record_execution(sample_dicom_file, signature)
        result = tracker.record_execution(sample_dicom_file, signature)

        assert result is True
        assert tracker.metrics.stable_executions == 1
        assert tracker.metrics.unstable_executions == 0

    def test_record_execution_unstable(self, sample_dicom_file):
        """Test recording unstable executions (different signatures)."""
        tracker = StabilityTracker()

        # Record different signatures for same file
        tracker.record_execution(sample_dicom_file, "exit:0|hash:abc123")
        result = tracker.record_execution(sample_dicom_file, "exit:1|hash:xyz789")

        assert result is False
        assert tracker.metrics.unstable_executions == 1
        assert len(tracker.metrics.unstable_inputs) == 1

    def test_record_execution_with_retest(self, sample_dicom_file):
        """Test recording with retest flag."""
        tracker = StabilityTracker()
        signature = "exit:0|hash:abc123"

        tracker.record_execution(sample_dicom_file, signature)
        result = tracker.record_execution(sample_dicom_file, signature, retest=True)

        assert result is True
        assert tracker.metrics.stable_executions == 1

    def test_stability_window_limit(self, sample_dicom_file):
        """Test that execution history is limited by stability window."""
        tracker = StabilityTracker(stability_window=5)

        # Record more than window size
        for i in range(10):
            tracker.record_execution(sample_dicom_file, f"sig:{i}")

        # Get hash used for this file
        input_hash = tracker._hash_file(sample_dicom_file)
        history = tracker.execution_history[input_hash]

        assert len(history) == 5  # Limited to window size

    def test_stability_percentage_calculation(self, sample_dicom_file):
        """Test stability percentage is calculated correctly."""
        tracker = StabilityTracker()

        # Record stable execution
        tracker.record_execution(sample_dicom_file, "sig1")
        tracker.record_execution(sample_dicom_file, "sig1")  # Stable

        assert tracker.metrics.total_executions == 2
        # First execution doesn't count toward stable/unstable
        # Second is stable
        assert tracker.metrics.stability_percentage > 0

    def test_should_retest_frequency(self, sample_dicom_file):
        """Test retest frequency logic."""
        tracker = StabilityTracker(retest_frequency=5)

        # First few iterations shouldn't trigger retest
        for _ in range(4):
            assert tracker.should_retest(sample_dicom_file) is False

        # 5th iteration should trigger (if conditions met)
        # Need to have exactly 1 execution recorded
        tracker.record_execution(sample_dicom_file, "sig1")
        tracker.iteration_count = 4  # Reset to test 5th
        result = tracker.should_retest(sample_dicom_file)
        assert result is True

    def test_should_retest_already_retested(self, sample_dicom_file):
        """Test that files aren't retested twice."""
        tracker = StabilityTracker(retest_frequency=1)

        # Record one execution
        tracker.record_execution(sample_dicom_file, "sig1")

        # First check - should retest
        assert tracker.should_retest(sample_dicom_file) is True

        # Already in retested set now
        tracker.iteration_count = 0  # Reset counter
        assert tracker.should_retest(sample_dicom_file) is False

    def test_should_retest_multiple_executions(self, sample_dicom_file):
        """Test no retest if file has multiple executions already."""
        tracker = StabilityTracker(retest_frequency=1)

        # Record multiple executions
        tracker.record_execution(sample_dicom_file, "sig1")
        tracker.record_execution(sample_dicom_file, "sig1")

        # Has 2 executions, shouldn't retest
        result = tracker.should_retest(sample_dicom_file)
        assert result is False

    def test_get_metrics(self):
        """Test get_metrics returns current metrics."""
        tracker = StabilityTracker()

        metrics = tracker.get_metrics()

        assert isinstance(metrics, StabilityMetrics)
        assert metrics is tracker.metrics

    def test_get_unstable_inputs_report_empty(self):
        """Test report with no unstable inputs."""
        tracker = StabilityTracker()

        report = tracker.get_unstable_inputs_report()

        assert report == []

    def test_get_unstable_inputs_report(self, sample_dicom_file):
        """Test detailed unstable inputs report."""
        tracker = StabilityTracker()

        # Create unstable execution
        tracker.record_execution(sample_dicom_file, "sig1")
        tracker.record_execution(sample_dicom_file, "sig2")

        report = tracker.get_unstable_inputs_report()

        assert len(report) == 1
        assert "input_hash" in report[0]
        assert "unique_behaviors" in report[0]
        assert "execution_count" in report[0]
        assert "variants" in report[0]

    def test_is_campaign_stable_default_threshold(self):
        """Test campaign stability check with default threshold."""
        tracker = StabilityTracker()
        tracker.metrics.stability_percentage = 96.0

        assert tracker.is_campaign_stable() is True

        tracker.metrics.stability_percentage = 94.0
        assert tracker.is_campaign_stable() is False

    def test_is_campaign_stable_custom_threshold(self):
        """Test campaign stability with custom threshold."""
        tracker = StabilityTracker()
        tracker.metrics.stability_percentage = 85.0

        assert tracker.is_campaign_stable(threshold=80.0) is True
        assert tracker.is_campaign_stable(threshold=90.0) is False

    def test_reset(self, sample_dicom_file):
        """Test reset clears all tracking data."""
        tracker = StabilityTracker()

        # Add some data
        tracker.record_execution(sample_dicom_file, "sig1")
        tracker.iteration_count = 50

        tracker.reset()

        assert tracker.metrics.total_executions == 0
        assert tracker.iteration_count == 0
        assert len(tracker.execution_history) == 0
        assert len(tracker.retested_inputs) == 0

    def test_check_stability_single_signature(self):
        """Test _check_stability with single execution."""
        tracker = StabilityTracker()
        tracker.execution_history["hash1"] = ["sig1"]

        result = tracker._check_stability("hash1")

        # Single execution is always stable
        assert result is True

    def test_check_stability_matching_signatures(self):
        """Test _check_stability with matching signatures."""
        tracker = StabilityTracker()
        tracker.execution_history["hash1"] = ["sig1", "sig1", "sig1"]

        result = tracker._check_stability("hash1")

        assert result is True

    def test_check_stability_different_signatures(self):
        """Test _check_stability with different signatures."""
        tracker = StabilityTracker()
        tracker.execution_history["hash1"] = ["sig1", "sig2"]

        result = tracker._check_stability("hash1")

        assert result is False

    def test_hash_file(self, sample_dicom_file):
        """Test file hashing."""
        tracker = StabilityTracker()

        hash1 = tracker._hash_file(sample_dicom_file)
        hash2 = tracker._hash_file(sample_dicom_file)

        # Same file should have same hash
        assert hash1 == hash2
        assert len(hash1) == 16  # 16 chars as specified

    def test_unstable_input_removed_when_stable(self, sample_dicom_file):
        """Test unstable input is removed when it becomes stable."""
        tracker = StabilityTracker()

        # Make unstable
        tracker.record_execution(sample_dicom_file, "sig1")
        tracker.record_execution(sample_dicom_file, "sig2")
        assert len(tracker.metrics.unstable_inputs) == 1

        # Clear history and make stable
        input_hash = tracker._hash_file(sample_dicom_file)
        tracker.execution_history[input_hash] = ["sig3"]
        tracker.record_execution(sample_dicom_file, "sig3")

        # Should be removed from unstable set
        assert len(tracker.metrics.unstable_inputs) == 0


class TestGenerateExecutionSignature:
    """Test generate_execution_signature function."""

    def test_exit_code_only(self):
        """Test signature with just exit code."""
        sig = generate_execution_signature(0)

        assert sig == "0"

    def test_with_output_hash(self):
        """Test signature with exit code and output hash."""
        sig = generate_execution_signature(0, output_hash="abc123")

        assert sig == "0|abc123"

    def test_with_coverage(self):
        """Test signature with exit code and coverage."""
        sig = generate_execution_signature(0, coverage={"line1", "line2"})

        parts = sig.split("|")
        assert parts[0] == "0"
        assert len(parts) == 2
        assert len(parts[1]) == 8  # MD5 hash truncated to 8 chars

    def test_with_all_parameters(self):
        """Test signature with all parameters."""
        sig = generate_execution_signature(
            exit_code=1,
            output_hash="deadbeef",
            coverage={"a", "b", "c"},
        )

        parts = sig.split("|")
        assert len(parts) == 3
        assert parts[0] == "1"
        assert parts[1] == "deadbeef"

    def test_coverage_sorted_for_consistency(self):
        """Test that coverage is sorted for consistent signatures."""
        # Same coverage in different order should produce same signature
        sig1 = generate_execution_signature(0, coverage={"a", "b", "c"})
        sig2 = generate_execution_signature(0, coverage={"c", "a", "b"})

        assert sig1 == sig2

    def test_different_exit_codes(self):
        """Test different exit codes produce different signatures."""
        sig1 = generate_execution_signature(0)
        sig2 = generate_execution_signature(1)

        assert sig1 != sig2


class TestDetectStabilityIssues:
    """Test detect_stability_issues function."""

    def test_no_issues_detected(self):
        """Test when no stability issues exist."""
        tracker = StabilityTracker()
        tracker.metrics.stability_percentage = 99.0
        tracker.metrics.total_executions = 50

        issues = detect_stability_issues(tracker)

        assert issues == ["No stability issues detected"]

    def test_low_stability_detected(self):
        """Test detection of low stability."""
        tracker = StabilityTracker()
        tracker.metrics.stability_percentage = 80.0
        tracker.metrics.total_executions = 50

        issues = detect_stability_issues(tracker)

        assert len(issues) >= 1
        assert any("Low stability" in issue for issue in issues)

    def test_many_unstable_inputs_detected(self):
        """Test detection of many unstable inputs."""
        tracker = StabilityTracker()
        tracker.metrics.stability_percentage = 95.0
        tracker.metrics.unstable_inputs = {f"hash{i}" for i in range(15)}

        issues = detect_stability_issues(tracker)

        assert len(issues) >= 1
        assert any("15 inputs" in issue for issue in issues)

    def test_stability_degradation_detected(self):
        """Test detection of stability degradation."""
        tracker = StabilityTracker()
        tracker.metrics.total_executions = 150
        tracker.metrics.stable_executions = 100  # ~67% stability
        tracker.metrics.stability_percentage = 67.0

        issues = detect_stability_issues(tracker)

        # Should detect both low stability and degradation
        assert len(issues) >= 1

    def test_multiple_issues_detected(self):
        """Test that multiple issues can be detected simultaneously."""
        tracker = StabilityTracker()
        tracker.metrics.stability_percentage = 75.0
        tracker.metrics.total_executions = 200
        tracker.metrics.stable_executions = 100
        tracker.metrics.unstable_inputs = {f"hash{i}" for i in range(20)}

        issues = detect_stability_issues(tracker)

        # Should have multiple issues
        assert len(issues) >= 2


class TestIntegration:
    """Integration tests for stability tracking workflow."""

    def test_full_tracking_workflow(self, sample_dicom_file, temp_dir):
        """Test complete tracking workflow."""
        tracker = StabilityTracker(stability_window=10, retest_frequency=3)

        # Create second file
        second_file = temp_dir / "second.dcm"
        second_file.write_bytes(sample_dicom_file.read_bytes() + b"extra")

        # Record stable executions
        for _ in range(5):
            tracker.record_execution(sample_dicom_file, "stable_sig")

        # Record unstable execution for second file
        tracker.record_execution(second_file, "sig1")
        tracker.record_execution(second_file, "sig2")

        # Check metrics
        metrics = tracker.get_metrics()
        assert metrics.total_executions == 7
        assert len(metrics.unstable_inputs) == 1

        # Get report
        report = tracker.get_unstable_inputs_report()
        assert len(report) == 1

        # Check stability
        assert not tracker.is_campaign_stable(threshold=99.0)

    def test_stability_with_issue_detection(self, sample_dicom_file):
        """Test stability tracking with issue detection."""
        tracker = StabilityTracker()

        # Create many unstable executions
        for i in range(20):
            sig1 = f"sig_{i}_a"
            sig2 = f"sig_{i}_b"
            tracker.record_execution(sample_dicom_file, sig1)
            tracker.record_execution(sample_dicom_file, sig2)

        # Detect issues
        issues = detect_stability_issues(tracker)

        # Should detect problems
        assert len(issues) >= 1
        assert issues != ["No stability issues detected"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
