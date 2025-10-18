"""Comprehensive tests for stability_tracker module.

Tests stability metrics tracking, instability detection, and root cause analysis.
"""

from collections import defaultdict
from unittest.mock import Mock, patch

import pytest

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

    def test_custom_target_stability(self):
        """Test tracker with custom target stability."""
        tracker = StabilityTracker(target_stability=95.0)

        assert tracker.target_stability == 95.0

    def test_metrics_initialization(self):
        """Test metrics are properly initialized."""
        tracker = StabilityTracker()

        assert tracker.metrics.total_executions == 0
        assert tracker.metrics.stability_percentage == 100.0


class TestStabilityCalculation:
    """Test stability percentage calculation."""

    def test_perfect_stability(self):
        """Test calculation with perfect stability."""
        tracker = StabilityTracker()
        tracker.metrics.total_executions = 100
        tracker.metrics.stable_executions = 100

        tracker.update_stability_percentage()

        assert tracker.metrics.stability_percentage == 100.0

    def test_partial_stability(self):
        """Test calculation with partial stability."""
        tracker = StabilityTracker()
        tracker.metrics.total_executions = 100
        tracker.metrics.stable_executions = 90

        tracker.update_stability_percentage()

        assert tracker.metrics.stability_percentage == 90.0

    def test_zero_executions(self):
        """Test calculation with zero executions."""
        tracker = StabilityTracker()

        tracker.update_stability_percentage()

        assert tracker.metrics.stability_percentage == 100.0


class TestExecutionTracking:
    """Test execution tracking."""

    def test_record_stable_execution(self):
        """Test recording stable execution."""
        tracker = StabilityTracker()

        tracker.record_execution("input1", is_stable=True)

        assert tracker.metrics.total_executions == 1
        assert tracker.metrics.stable_executions == 1
        assert tracker.metrics.unstable_executions == 0

    def test_record_unstable_execution(self):
        """Test recording unstable execution."""
        tracker = StabilityTracker()

        tracker.record_execution("input1", is_stable=False)

        assert tracker.metrics.total_executions == 1
        assert tracker.metrics.stable_executions == 0
        assert tracker.metrics.unstable_executions == 1
        assert "input1" in tracker.metrics.unstable_inputs

    def test_multiple_executions(self):
        """Test recording multiple executions."""
        tracker = StabilityTracker()

        tracker.record_execution("input1", is_stable=True)
        tracker.record_execution("input2", is_stable=False)
        tracker.record_execution("input3", is_stable=True)

        assert tracker.metrics.total_executions == 3
        assert tracker.metrics.stable_executions == 2
        assert tracker.metrics.unstable_executions == 1


class TestStabilityThresholds:
    """Test stability threshold checking."""

    def test_meets_target_stability(self):
        """Test checking if target stability is met."""
        tracker = StabilityTracker(target_stability=90.0)
        tracker.metrics.total_executions = 100
        tracker.metrics.stable_executions = 95
        tracker.update_stability_percentage()

        meets_target = tracker.meets_target()

        assert meets_target is True

    def test_below_target_stability(self):
        """Test detection of below-target stability."""
        tracker = StabilityTracker(target_stability=90.0)
        tracker.metrics.total_executions = 100
        tracker.metrics.stable_executions = 80
        tracker.update_stability_percentage()

        meets_target = tracker.meets_target()

        assert meets_target is False


class TestMetricsRetrieval:
    """Test metrics retrieval."""

    def test_get_metrics(self):
        """Test retrieving metrics."""
        tracker = StabilityTracker()
        tracker.record_execution("input1", is_stable=True)

        metrics = tracker.get_metrics()

        assert isinstance(metrics, StabilityMetrics)
        assert metrics.total_executions == 1

    def test_get_unstable_inputs(self):
        """Test retrieving unstable inputs."""
        tracker = StabilityTracker()
        tracker.record_execution("unstable1", is_stable=False)
        tracker.record_execution("unstable2", is_stable=False)

        unstable = tracker.get_unstable_inputs()

        assert len(unstable) == 2
        assert "unstable1" in unstable
        assert "unstable2" in unstable


class TestIntegrationScenarios:
    """Test integration scenarios."""

    def test_complete_stability_tracking_workflow(self):
        """Test complete stability tracking workflow."""
        tracker = StabilityTracker(target_stability=95.0)

        # Simulate fuzzing campaign
        for i in range(100):
            is_stable = i < 97  # 97% stability
            tracker.record_execution(f"input{i}", is_stable=is_stable)

        tracker.update_stability_percentage()

        assert tracker.metrics.total_executions == 100
        assert tracker.metrics.stable_executions == 97
        assert tracker.metrics.stability_percentage == 97.0
        assert tracker.meets_target() is True

    def test_detecting_instability_issues(self):
        """Test detecting instability issues."""
        tracker = StabilityTracker(target_stability=99.0)

        # Simulate campaign with instability
        for i in range(50):
            tracker.record_execution(f"stable{i}", is_stable=True)

        for i in range(10):
            tracker.record_execution(f"unstable{i}", is_stable=False)

        tracker.update_stability_percentage()

        assert tracker.metrics.unstable_executions == 10
        assert len(tracker.metrics.unstable_inputs) == 10
        assert tracker.meets_target() is False  # 83.3% < 99%

    def test_stability_improvement_tracking(self):
        """Test tracking stability improvements."""
        tracker = StabilityTracker()

        # Initial poor stability
        for i in range(10):
            tracker.record_execution(f"input{i}", is_stable=i % 2 == 0)
        tracker.update_stability_percentage()

        initial_stability = tracker.metrics.stability_percentage

        # Improved stability
        for i in range(10, 20):
            tracker.record_execution(f"input{i}", is_stable=True)
        tracker.update_stability_percentage()

        final_stability = tracker.metrics.stability_percentage

        assert final_stability > initial_stability
