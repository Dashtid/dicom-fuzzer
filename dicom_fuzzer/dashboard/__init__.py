"""Real-time monitoring dashboard for DICOM Fuzzer.

This module provides a web-based dashboard for monitoring fuzzing campaigns
in real-time using WebSocket connections.

Components:
- server: FastAPI-based WebSocket server
- metrics: Prometheus metrics exporter
- static: Web UI files

Usage:
    from dicom_fuzzer.dashboard import DashboardServer

    server = DashboardServer(host="0.0.0.0", port=8080)
    server.start()
"""

from dicom_fuzzer.dashboard.metrics import MetricsExporter
from dicom_fuzzer.dashboard.server import DashboardServer

__all__ = ["DashboardServer", "MetricsExporter"]
