"""Prometheus metrics exporter for DICOM Fuzzer.

This module provides Prometheus-compatible metrics for fuzzing campaigns,
enabling integration with monitoring systems like Grafana.

Metrics exported:
- dicom_fuzzer_executions_total: Total test executions
- dicom_fuzzer_crashes_total: Total crashes found
- dicom_fuzzer_coverage_percent: Current coverage percentage
- dicom_fuzzer_execution_rate: Executions per second
- dicom_fuzzer_memory_usage_bytes: Memory usage
- dicom_fuzzer_unique_paths: Unique code paths discovered
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dicom_fuzzer.dashboard.server import FuzzingStats

logger = logging.getLogger(__name__)

# Try to import prometheus_client
try:
    from prometheus_client import (
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        Summary,
        generate_latest,
        start_http_server,
    )

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    # Set to None when prometheus_client not installed
    REGISTRY = None
    Counter = None
    Gauge = None
    Histogram = None
    Summary = None


@dataclass
class MetricLabels:
    """Labels for Prometheus metrics.

    Attributes:
        campaign_id: Unique identifier for the fuzzing campaign
        target: Name of the target being fuzzed
        strategy: Fuzzing strategy being used

    """

    campaign_id: str = "default"
    target: str = "dicom_viewer"
    strategy: str = "coverage_guided"


class MetricsExporter:
    """Prometheus metrics exporter for fuzzing campaigns.

    Exports real-time fuzzing metrics in Prometheus format, allowing
    integration with monitoring systems like Grafana.

    Usage:
        exporter = MetricsExporter(port=9090)
        exporter.start()

        # Update metrics from fuzzing loop
        exporter.update(stats)

        # Stop exporter
        exporter.stop()

    """

    def __init__(
        self,
        port: int = 9090,
        labels: MetricLabels | None = None,
    ):
        """Initialize metrics exporter.

        Args:
            port: Port number for Prometheus HTTP endpoint
            labels: Labels to attach to all metrics

        Raises:
            ImportError: If prometheus_client is not installed

        """
        if not HAS_PROMETHEUS:
            raise ImportError(
                "prometheus_client is required for metrics export. "
                "Install with: pip install prometheus-client"
            )

        self.port = port
        self.labels = labels or MetricLabels()
        self._running = False
        self._lock = threading.Lock()

        # Initialize metrics
        self._init_metrics()

        logger.info(f"Metrics exporter initialized on port {port}")

    def _init_metrics(self) -> None:
        """Initialize Prometheus metrics."""
        label_names = ["campaign_id", "target", "strategy"]

        # Counters
        self.executions_total = Counter(
            "dicom_fuzzer_executions_total",
            "Total number of test executions",
            label_names,
        )

        self.crashes_total = Counter(
            "dicom_fuzzer_crashes_total",
            "Total number of crashes found",
            label_names,
        )

        self.timeouts_total = Counter(
            "dicom_fuzzer_timeouts_total",
            "Total number of timeouts",
            label_names,
        )

        # Gauges
        self.coverage_percent = Gauge(
            "dicom_fuzzer_coverage_percent",
            "Current code coverage percentage",
            label_names,
        )

        self.execution_rate = Gauge(
            "dicom_fuzzer_execution_rate",
            "Current executions per second",
            label_names,
        )

        self.memory_usage_bytes = Gauge(
            "dicom_fuzzer_memory_usage_bytes",
            "Current memory usage in bytes",
            label_names,
        )

        self.unique_paths = Gauge(
            "dicom_fuzzer_unique_paths",
            "Number of unique code paths discovered",
            label_names,
        )

        self.corpus_size = Gauge(
            "dicom_fuzzer_corpus_size",
            "Number of files in the corpus",
            label_names,
        )

        self.campaign_runtime_seconds = Gauge(
            "dicom_fuzzer_campaign_runtime_seconds",
            "Campaign runtime in seconds",
            label_names,
        )

        # Histograms
        self.execution_duration = Histogram(
            "dicom_fuzzer_execution_duration_seconds",
            "Execution duration in seconds",
            label_names,
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
        )

        # Summary
        self.crash_severity = Summary(
            "dicom_fuzzer_crash_severity",
            "Distribution of crash severity scores",
            label_names,
        )

    def _get_labels(self) -> dict[str, str]:
        """Get label values as dictionary.

        Returns:
            Dictionary of label names to values

        """
        return {
            "campaign_id": self.labels.campaign_id,
            "target": self.labels.target,
            "strategy": self.labels.strategy,
        }

    def start(self) -> None:
        """Start the Prometheus HTTP server."""
        if self._running:
            logger.warning("Metrics exporter is already running")
            return

        try:
            start_http_server(self.port)
            self._running = True
            logger.info(
                f"Prometheus metrics available at http://0.0.0.0:{self.port}/metrics"
            )
        except OSError as e:
            logger.error(f"Failed to start metrics server: {e}")
            raise

    def stop(self) -> None:
        """Stop the metrics exporter."""
        self._running = False
        logger.info("Metrics exporter stopped")

    def update(self, stats: FuzzingStats) -> None:
        """Update metrics from fuzzing statistics.

        Args:
            stats: Current fuzzing statistics

        """
        labels = self._get_labels()

        with self._lock:
            # Update gauges
            self.coverage_percent.labels(**labels).set(stats.coverage_percent)
            self.execution_rate.labels(**labels).set(stats.executions_per_sec)
            self.memory_usage_bytes.labels(**labels).set(
                stats.memory_usage_mb * 1024 * 1024
            )
            self.unique_paths.labels(**labels).set(stats.unique_paths)
            self.campaign_runtime_seconds.labels(**labels).set(
                time.time() - stats.start_time.timestamp()
            )

    def record_execution(self, duration: float) -> None:
        """Record a single execution.

        Args:
            duration: Execution duration in seconds

        """
        labels = self._get_labels()
        self.executions_total.labels(**labels).inc()
        self.execution_duration.labels(**labels).observe(duration)

    def record_crash(self, severity: float = 1.0) -> None:
        """Record a crash discovery.

        Args:
            severity: Crash severity score (0-10)

        """
        labels = self._get_labels()
        self.crashes_total.labels(**labels).inc()
        self.crash_severity.labels(**labels).observe(severity)

    def record_timeout(self) -> None:
        """Record a timeout occurrence."""
        labels = self._get_labels()
        self.timeouts_total.labels(**labels).inc()

    def set_corpus_size(self, size: int) -> None:
        """Set the current corpus size.

        Args:
            size: Number of files in the corpus

        """
        labels = self._get_labels()
        self.corpus_size.labels(**labels).set(size)

    def get_metrics(self) -> bytes:
        """Get metrics in Prometheus format.

        Returns:
            Metrics in Prometheus text format

        """
        result: bytes = generate_latest(REGISTRY)
        return result


class NoOpMetricsExporter:
    """No-operation metrics exporter for when Prometheus is not available.

    Provides the same interface as MetricsExporter but does nothing,
    allowing code to work without prometheus_client installed.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize no-op exporter."""
        logger.debug("Using no-op metrics exporter (prometheus_client not installed)")

    def start(self) -> None:
        """No-op start."""
        pass

    def stop(self) -> None:
        """No-op stop."""
        pass

    def update(self, stats: Any) -> None:
        """No-op update."""
        pass

    def record_execution(self, duration: float) -> None:
        """No-op record execution."""
        pass

    def record_crash(self, severity: float = 1.0) -> None:
        """No-op record crash."""
        pass

    def record_timeout(self) -> None:
        """No-op record timeout."""
        pass

    def set_corpus_size(self, size: int) -> None:
        """No-op set corpus size."""
        pass

    def get_metrics(self) -> bytes:
        """Return empty metrics."""
        return b""


def create_metrics_exporter(
    port: int = 9090,
    labels: MetricLabels | None = None,
) -> MetricsExporter | NoOpMetricsExporter:
    """Create a metrics exporter, falling back to no-op if Prometheus unavailable.

    Args:
        port: Port number for Prometheus HTTP endpoint
        labels: Labels to attach to all metrics

    Returns:
        MetricsExporter if prometheus_client is installed, NoOpMetricsExporter otherwise

    """
    if HAS_PROMETHEUS:
        return MetricsExporter(port=port, labels=labels)
    return NoOpMetricsExporter()
