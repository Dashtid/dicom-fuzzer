"""Tests for the dashboard metrics module.

This module tests the MetricsExporter and related classes.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from dicom_fuzzer.dashboard.metrics import (
    HAS_PROMETHEUS,
    MetricLabels,
    NoOpMetricsExporter,
    create_metrics_exporter,
)
from dicom_fuzzer.dashboard.server import FuzzingStats

if TYPE_CHECKING:
    pass


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
            campaign_id="campaign-001",
            target="custom_viewer",
            strategy="mutation_based",
        )
        assert labels.campaign_id == "campaign-001"
        assert labels.target == "custom_viewer"
        assert labels.strategy == "mutation_based"


class TestNoOpMetricsExporter:
    """Tests for NoOpMetricsExporter class."""

    def test_initialization(self) -> None:
        """Test no-op exporter initializes without error."""
        exporter = NoOpMetricsExporter()
        assert exporter is not None

    def test_initialization_with_args(self) -> None:
        """Test no-op exporter accepts arbitrary arguments."""
        exporter = NoOpMetricsExporter(port=9090, labels=MetricLabels())
        assert exporter is not None

    def test_start(self) -> None:
        """Test start does nothing."""
        exporter = NoOpMetricsExporter()
        exporter.start()  # Should not raise

    def test_stop(self) -> None:
        """Test stop does nothing."""
        exporter = NoOpMetricsExporter()
        exporter.stop()  # Should not raise

    def test_update(self) -> None:
        """Test update does nothing."""
        exporter = NoOpMetricsExporter()
        stats = FuzzingStats(total_executions=100)
        exporter.update(stats)  # Should not raise

    def test_record_execution(self) -> None:
        """Test record_execution does nothing."""
        exporter = NoOpMetricsExporter()
        exporter.record_execution(0.5)  # Should not raise

    def test_record_crash(self) -> None:
        """Test record_crash does nothing."""
        exporter = NoOpMetricsExporter()
        exporter.record_crash(5.0)  # Should not raise

    def test_record_timeout(self) -> None:
        """Test record_timeout does nothing."""
        exporter = NoOpMetricsExporter()
        exporter.record_timeout()  # Should not raise

    def test_set_corpus_size(self) -> None:
        """Test set_corpus_size does nothing."""
        exporter = NoOpMetricsExporter()
        exporter.set_corpus_size(100)  # Should not raise

    def test_get_metrics(self) -> None:
        """Test get_metrics returns empty bytes."""
        exporter = NoOpMetricsExporter()
        assert exporter.get_metrics() == b""


class TestCreateMetricsExporter:
    """Tests for create_metrics_exporter factory function."""

    def test_create_without_prometheus(self) -> None:
        """Test creates NoOpMetricsExporter when prometheus not available."""
        with patch("dicom_fuzzer.dashboard.metrics.HAS_PROMETHEUS", False):
            exporter = create_metrics_exporter()
            assert isinstance(exporter, NoOpMetricsExporter)

    def test_create_with_custom_labels(self) -> None:
        """Test creates exporter with custom labels."""
        labels = MetricLabels(campaign_id="test-campaign")
        with patch("dicom_fuzzer.dashboard.metrics.HAS_PROMETHEUS", False):
            exporter = create_metrics_exporter(port=9091, labels=labels)
            assert isinstance(exporter, NoOpMetricsExporter)


@pytest.mark.skipif(not HAS_PROMETHEUS, reason="prometheus_client not installed")
class TestMetricsExporter:
    """Tests for MetricsExporter class (requires prometheus_client)."""

    @pytest.fixture(autouse=True)
    def reset_registry(self) -> Any:
        """Reset Prometheus registry between tests."""
        from prometheus_client import REGISTRY

        # Collect all collector names
        collectors_to_remove = list(REGISTRY._names_to_collectors.values())

        # Unregister collectors (skip default ones)
        for collector in collectors_to_remove:
            try:
                REGISTRY.unregister(collector)
            except Exception:
                pass

        return

    def test_initialization(self) -> None:
        """Test MetricsExporter initializes with metrics."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19090)
        assert exporter.port == 19090
        assert exporter.labels is not None
        assert exporter._running is False

    def test_initialization_custom_labels(self) -> None:
        """Test initialization with custom labels."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        labels = MetricLabels(campaign_id="custom")
        exporter = MetricsExporter(port=19091, labels=labels)
        assert exporter.labels.campaign_id == "custom"

    def test_get_labels(self) -> None:
        """Test _get_labels returns correct dictionary."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        labels = MetricLabels(
            campaign_id="test",
            target="viewer",
            strategy="coverage",
        )
        exporter = MetricsExporter(port=19092, labels=labels)
        label_dict = exporter._get_labels()

        assert label_dict["campaign_id"] == "test"
        assert label_dict["target"] == "viewer"
        assert label_dict["strategy"] == "coverage"

    def test_record_execution(self) -> None:
        """Test recording an execution."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19093)
        exporter.record_execution(0.5)
        # Should not raise

    def test_record_crash(self) -> None:
        """Test recording a crash."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19094)
        exporter.record_crash(7.5)
        # Should not raise

    def test_record_timeout(self) -> None:
        """Test recording a timeout."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19095)
        exporter.record_timeout()
        # Should not raise

    def test_set_corpus_size(self) -> None:
        """Test setting corpus size."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19096)
        exporter.set_corpus_size(500)
        # Should not raise

    def test_update_stats(self) -> None:
        """Test updating stats from FuzzingStats."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19097)
        stats = FuzzingStats(
            total_executions=1000,
            coverage_percent=75.5,
            executions_per_sec=50.0,
            memory_usage_mb=512.0,
            unique_paths=100,
            start_time=datetime.now(),
        )
        exporter.update(stats)
        # Should not raise

    def test_get_metrics(self) -> None:
        """Test getting metrics in Prometheus format."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19098)
        exporter.record_execution(0.1)
        metrics = exporter.get_metrics()

        assert isinstance(metrics, bytes)
        assert b"dicom_fuzzer_executions_total" in metrics

    def test_start_stop(self) -> None:
        """Test start and stop methods."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19099)

        # Mock start_http_server to avoid actually starting server
        with patch("dicom_fuzzer.dashboard.metrics.start_http_server"):
            exporter.start()
            assert exporter._running is True

            exporter.stop()
            assert exporter._running is False

    def test_start_already_running(self) -> None:
        """Test starting when already running."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19100)
        exporter._running = True

        with patch("dicom_fuzzer.dashboard.metrics.start_http_server") as mock:
            exporter.start()
            mock.assert_not_called()

    def test_start_port_error(self) -> None:
        """Test handling port binding error."""
        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19101)

        with patch(
            "dicom_fuzzer.dashboard.metrics.start_http_server",
            side_effect=OSError("Port in use"),
        ):
            with pytest.raises(OSError, match="Port in use"):
                exporter.start()

    def test_thread_safety(self) -> None:
        """Test thread-safe metric updates."""
        import threading

        from dicom_fuzzer.dashboard.metrics import MetricsExporter

        exporter = MetricsExporter(port=19102)
        errors: list[Exception] = []

        def record_many(n: int) -> None:
            try:
                for i in range(100):
                    exporter.record_execution(0.01 * i)
                    exporter.record_crash(float(i % 10))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_many, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
