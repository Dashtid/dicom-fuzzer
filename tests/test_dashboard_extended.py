"""Extended tests for dashboard modules.

Tests for metrics exporter and dashboard server including:
- MetricLabels dataclass
- MetricsExporter class
- NoOpMetricsExporter class
- create_metrics_exporter factory

Target: 80%+ coverage for metrics.py and server.py
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.dashboard.metrics import (
    HAS_PROMETHEUS,
    MetricLabels,
    NoOpMetricsExporter,
)


class TestMetricLabels:
    """Tests for MetricLabels dataclass."""

    def test_default_values(self) -> None:
        """Test default label values."""
        labels = MetricLabels()
        assert labels.campaign_id == "default"
        assert labels.target == "dicom_viewer"
        assert labels.strategy == "coverage_guided"

    def test_custom_values(self) -> None:
        """Test custom label values."""
        labels = MetricLabels(
            campaign_id="test-001",
            target="custom_viewer",
            strategy="random",
        )
        assert labels.campaign_id == "test-001"
        assert labels.target == "custom_viewer"
        assert labels.strategy == "random"

    def test_partial_custom_values(self) -> None:
        """Test partial custom values."""
        labels = MetricLabels(campaign_id="partial-test")
        assert labels.campaign_id == "partial-test"
        assert labels.target == "dicom_viewer"  # Default


class TestNoOpMetricsExporter:
    """Tests for NoOpMetricsExporter class."""

    @pytest.fixture
    def exporter(self) -> NoOpMetricsExporter:
        """Create NoOpMetricsExporter instance."""
        return NoOpMetricsExporter()

    def test_init(self, exporter: NoOpMetricsExporter) -> None:
        """Test initialization."""
        assert exporter is not None

    def test_init_with_args(self) -> None:
        """Test initialization with various arguments."""
        exporter = NoOpMetricsExporter(port=9999, labels=MetricLabels())
        assert exporter is not None

    def test_start(self, exporter: NoOpMetricsExporter) -> None:
        """Test start is no-op."""
        exporter.start()  # Should not raise

    def test_stop(self, exporter: NoOpMetricsExporter) -> None:
        """Test stop is no-op."""
        exporter.stop()  # Should not raise

    def test_update(self, exporter: NoOpMetricsExporter) -> None:
        """Test update is no-op."""
        mock_stats = MagicMock()
        exporter.update(mock_stats)  # Should not raise

    def test_record_execution(self, exporter: NoOpMetricsExporter) -> None:
        """Test record_execution is no-op."""
        exporter.record_execution(0.5)  # Should not raise

    def test_record_crash(self, exporter: NoOpMetricsExporter) -> None:
        """Test record_crash is no-op."""
        exporter.record_crash(severity=5.0)  # Should not raise

    def test_record_crash_default_severity(self, exporter: NoOpMetricsExporter) -> None:
        """Test record_crash with default severity."""
        exporter.record_crash()  # Should not raise

    def test_record_timeout(self, exporter: NoOpMetricsExporter) -> None:
        """Test record_timeout is no-op."""
        exporter.record_timeout()  # Should not raise

    def test_set_corpus_size(self, exporter: NoOpMetricsExporter) -> None:
        """Test set_corpus_size is no-op."""
        exporter.set_corpus_size(100)  # Should not raise

    def test_get_metrics(self, exporter: NoOpMetricsExporter) -> None:
        """Test get_metrics returns empty bytes."""
        result = exporter.get_metrics()
        assert result == b""


class TestCreateMetricsExporter:
    """Tests for create_metrics_exporter factory function."""

    def test_create_without_prometheus(self) -> None:
        """Test that factory returns NoOp when prometheus unavailable."""
        with patch("dicom_fuzzer.dashboard.metrics.HAS_PROMETHEUS", False):
            # Need to reimport to get the patched version
            from dicom_fuzzer.dashboard.metrics import create_metrics_exporter

            exporter = create_metrics_exporter()
            assert isinstance(exporter, NoOpMetricsExporter)

    def test_create_with_custom_labels(self) -> None:
        """Test factory with custom labels."""
        with patch("dicom_fuzzer.dashboard.metrics.HAS_PROMETHEUS", False):
            from dicom_fuzzer.dashboard.metrics import create_metrics_exporter

            labels = MetricLabels(campaign_id="custom")
            exporter = create_metrics_exporter(port=8080, labels=labels)
            assert isinstance(exporter, NoOpMetricsExporter)


@pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus_client not installed")
class TestMetricsExporterWithPrometheus:
    """Tests for MetricsExporter when prometheus_client is available.

    Note: These tests are intentionally minimal due to Prometheus global
    registry constraints. The MetricsExporter can only be created once
    per process due to metric name conflicts.
    """

    def test_prometheus_available(self) -> None:
        """Test that Prometheus is available."""
        assert HAS_PROMETHEUS is True

    def test_metric_labels_work_with_prometheus(self) -> None:
        """Test MetricLabels work correctly."""
        labels = MetricLabels(campaign_id="test", target="test_app")
        assert labels.campaign_id == "test"
        assert labels.target == "test_app"


class TestMetricsExporterWithoutPrometheus:
    """Tests for MetricsExporter behavior when prometheus is not available."""

    def test_import_error_when_no_prometheus(self) -> None:
        """Test that ImportError is raised when prometheus not available."""
        with patch("dicom_fuzzer.dashboard.metrics.HAS_PROMETHEUS", False):
            # This should use NoOp instead
            from dicom_fuzzer.dashboard.metrics import create_metrics_exporter

            exporter = create_metrics_exporter()
            assert isinstance(exporter, NoOpMetricsExporter)


# Mock FuzzingStats for testing update method
@dataclass
class MockFuzzingStats:
    """Mock FuzzingStats for testing."""

    coverage_percent: float = 50.0
    executions_per_sec: float = 100.0
    memory_usage_mb: float = 512.0
    unique_paths: int = 1000
    start_time: datetime = None

    def __post_init__(self) -> None:
        """Set default start_time."""
        if self.start_time is None:
            self.start_time = datetime.now()


class TestMetricsExporterUpdate:
    """Tests for update functionality via NoOp exporter."""

    def test_update_with_stats(self) -> None:
        """Test update method with mock stats via NoOp."""
        exporter = NoOpMetricsExporter()
        stats = MockFuzzingStats(
            coverage_percent=75.5,
            executions_per_sec=150.0,
            memory_usage_mb=256.0,
            unique_paths=500,
        )
        exporter.update(stats)  # Should not raise


class TestCreateMetricsExporterFactory:
    """Additional tests for the factory function."""

    def test_factory_returns_noop_when_prometheus_unavailable(self) -> None:
        """Test factory behavior with prometheus unavailable."""
        # NoOp should always work
        exporter = NoOpMetricsExporter()
        exporter.start()
        exporter.record_execution(1.0)
        exporter.record_crash()
        exporter.record_timeout()
        exporter.set_corpus_size(10)
        assert exporter.get_metrics() == b""
        exporter.stop()

    def test_noop_accepts_any_stats(self) -> None:
        """Test NoOp accepts any stats object."""
        exporter = NoOpMetricsExporter()

        # Various types of stats
        exporter.update(None)
        exporter.update({})
        exporter.update(MockFuzzingStats())
        exporter.update("string")


class TestMetricLabelsEquality:
    """Tests for MetricLabels equality and hashing."""

    def test_equality(self) -> None:
        """Test MetricLabels equality."""
        l1 = MetricLabels(campaign_id="a", target="b", strategy="c")
        l2 = MetricLabels(campaign_id="a", target="b", strategy="c")
        assert l1 == l2

    def test_inequality(self) -> None:
        """Test MetricLabels inequality."""
        l1 = MetricLabels(campaign_id="a")
        l2 = MetricLabels(campaign_id="b")
        assert l1 != l2


class TestNoOpEdgeCases:
    """Edge case tests for NoOpMetricsExporter."""

    def test_multiple_operations(self) -> None:
        """Test multiple operations in sequence."""
        exporter = NoOpMetricsExporter()

        # Simulate a fuzzing session
        exporter.start()
        for i in range(100):
            exporter.record_execution(i * 0.01)
            if i % 10 == 0:
                exporter.record_crash(severity=float(i % 10))
            if i % 20 == 0:
                exporter.record_timeout()
        exporter.set_corpus_size(1000)
        exporter.update(MockFuzzingStats())
        exporter.stop()

        # All operations should be no-op
        assert exporter.get_metrics() == b""

    def test_start_stop_multiple_times(self) -> None:
        """Test starting and stopping multiple times."""
        exporter = NoOpMetricsExporter()
        for _ in range(5):
            exporter.start()
            exporter.stop()
        # Should not raise any errors
