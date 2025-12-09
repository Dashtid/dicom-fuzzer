"""FastAPI WebSocket server for real-time fuzzing dashboard.

This module provides a real-time monitoring dashboard for DICOM fuzzing
campaigns using WebSocket connections for live updates.

Features:
- Real-time fuzzing statistics via WebSocket
- REST API for campaign management
- Static file serving for web UI
- Multi-client broadcast support
"""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


@dataclass
class FuzzingStats:
    """Real-time fuzzing statistics.

    Attributes:
        total_executions: Total number of test executions
        crashes_found: Number of unique crashes found
        coverage_percent: Current code coverage percentage
        executions_per_sec: Current execution rate
        start_time: Campaign start time
        current_file: Currently being tested file
        memory_usage_mb: Current memory usage
        unique_paths: Number of unique code paths discovered

    """

    total_executions: int = 0
    crashes_found: int = 0
    coverage_percent: float = 0.0
    executions_per_sec: float = 0.0
    start_time: datetime = field(default_factory=datetime.now)
    current_file: str = ""
    memory_usage_mb: float = 0.0
    unique_paths: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_executions": self.total_executions,
            "crashes_found": self.crashes_found,
            "coverage_percent": round(self.coverage_percent, 2),
            "executions_per_sec": round(self.executions_per_sec, 2),
            "start_time": self.start_time.isoformat(),
            "runtime_seconds": (datetime.now() - self.start_time).total_seconds(),
            "current_file": self.current_file,
            "memory_usage_mb": round(self.memory_usage_mb, 1),
            "unique_paths": self.unique_paths,
        }


@dataclass
class CrashInfo:
    """Information about a discovered crash.

    Attributes:
        crash_id: Unique identifier for the crash
        timestamp: When the crash was discovered
        test_file: File that triggered the crash
        crash_type: Type of crash (e.g., segfault, assertion)
        stack_hash: Hash of the stack trace
        severity: Crash severity level

    """

    crash_id: str
    timestamp: datetime
    test_file: str
    crash_type: str
    stack_hash: str
    severity: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "crash_id": self.crash_id,
            "timestamp": self.timestamp.isoformat(),
            "test_file": self.test_file,
            "crash_type": self.crash_type,
            "stack_hash": self.stack_hash,
            "severity": self.severity,
        }


class DashboardServer:
    """Real-time monitoring dashboard server.

    Provides WebSocket-based real-time updates and REST API for
    managing and monitoring DICOM fuzzing campaigns.

    Usage:
        server = DashboardServer(host="0.0.0.0", port=8080)
        server.start()

        # Update stats from fuzzing loop
        server.update_stats(stats)

        # Stop server
        server.stop()

    """

    def __init__(
        self,
        host: str = "0.0.0.0",  # noqa: S104 # nosec B104 - Intentional for dashboard access
        port: int = 8080,
        static_dir: Path | None = None,
    ):
        """Initialize dashboard server.

        Args:
            host: Host address to bind to
            port: Port number to listen on
            static_dir: Directory containing static web files

        """
        self.host = host
        self.port = port
        self.static_dir = static_dir or Path(__file__).parent / "static"

        self._stats = FuzzingStats()
        self._crashes: list[CrashInfo] = []
        self._connected_clients: set[Any] = set()
        self._lock = threading.Lock()
        self._running = False
        self._server_thread: threading.Thread | None = None
        self._app: Any = None
        self._update_callbacks: list[Callable[[FuzzingStats], None]] = []

        logger.info(f"Dashboard server initialized: {host}:{port}")

    def _create_app(self) -> Any:
        """Create FastAPI application.

        Returns:
            FastAPI application instance

        """
        try:
            from fastapi import FastAPI, WebSocket, WebSocketDisconnect
            from fastapi.responses import FileResponse, HTMLResponse
            from fastapi.staticfiles import StaticFiles
        except ImportError as e:
            raise ImportError(
                "FastAPI is required for dashboard. "
                "Install with: pip install fastapi uvicorn"
            ) from e

        app = FastAPI(
            title="DICOM Fuzzer Dashboard",
            description="Real-time monitoring for DICOM fuzzing campaigns",
            version="1.0.0",
        )

        # Mount static files if directory exists
        if self.static_dir.exists():
            app.mount(
                "/static", StaticFiles(directory=str(self.static_dir)), name="static"
            )

        @app.get("/", response_class=HTMLResponse)  # type: ignore[misc]
        async def index() -> HTMLResponse | FileResponse:
            """Serve the dashboard HTML page."""
            index_path = self.static_dir / "index.html"
            if index_path.exists():
                return FileResponse(str(index_path))
            return HTMLResponse(self._get_default_html())

        @app.get("/api/stats")  # type: ignore[misc]
        async def get_stats() -> dict[str, Any]:
            """Get current fuzzing statistics."""
            with self._lock:
                return {
                    "status": "running" if self._running else "stopped",
                    "stats": self._stats.to_dict(),
                }

        @app.get("/api/crashes")  # type: ignore[misc]
        async def get_crashes() -> dict[str, Any]:
            """Get list of discovered crashes."""
            with self._lock:
                return {
                    "total": len(self._crashes),
                    "crashes": [c.to_dict() for c in self._crashes[-100:]],
                }

        @app.websocket("/ws")  # type: ignore[misc]
        async def websocket_endpoint(websocket: WebSocket) -> None:
            """WebSocket endpoint for real-time updates."""
            await websocket.accept()
            with self._lock:
                self._connected_clients.add(websocket)
                client_count = len(self._connected_clients)
            logger.debug(f"Client connected. Total: {client_count}")

            try:
                # Send initial state
                with self._lock:
                    await websocket.send_json(
                        {
                            "type": "init",
                            "stats": self._stats.to_dict(),
                            "crashes": [c.to_dict() for c in self._crashes[-10:]],
                        }
                    )

                # Keep connection alive and wait for messages
                while True:
                    try:
                        data = await asyncio.wait_for(
                            websocket.receive_text(), timeout=30.0
                        )
                        # Handle ping/pong
                        if data == "ping":
                            await websocket.send_text("pong")
                    except TimeoutError:
                        # Send heartbeat
                        await websocket.send_json({"type": "heartbeat"})

            except WebSocketDisconnect:
                pass
            finally:
                with self._lock:
                    self._connected_clients.discard(websocket)
                    client_count = len(self._connected_clients)
                logger.debug(f"Client disconnected. Total: {client_count}")

        return app

    def _get_default_html(self) -> str:
        """Get default HTML when no static files exist.

        Returns:
            HTML string for basic dashboard

        """
        return """
<!DOCTYPE html>
<html>
<head>
    <title>DICOM Fuzzer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .stat-card { background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #00d4ff; }
        .stat-label { color: #888; margin-top: 10px; }
        .crashes { background: #16213e; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .crash-item { padding: 10px; border-bottom: 1px solid #333; }
        .crash-item:last-child { border-bottom: none; }
        .status { padding: 5px 10px; border-radius: 4px; display: inline-block; }
        .status.running { background: #00c853; color: #000; }
        .status.stopped { background: #ff5252; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DICOM Fuzzer Dashboard</h1>
        <p>Status: <span id="status" class="status stopped">Connecting...</span></p>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="executions">0</div>
                <div class="stat-label">Total Executions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="crashes">0</div>
                <div class="stat-label">Crashes Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="coverage">0%</div>
                <div class="stat-label">Coverage</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="speed">0</div>
                <div class="stat-label">Exec/sec</div>
            </div>
        </div>

        <div class="crashes">
            <h2>Recent Crashes</h2>
            <div id="crash-list">No crashes yet</div>
        </div>
    </div>

    <script>
        const ws = new WebSocket(`ws://${window.location.host}/ws`);

        ws.onopen = () => {
            document.getElementById('status').textContent = 'Connected';
            document.getElementById('status').className = 'status running';
        };

        ws.onclose = () => {
            document.getElementById('status').textContent = 'Disconnected';
            document.getElementById('status').className = 'status stopped';
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'stats' || data.type === 'init') {
                const stats = data.stats;
                document.getElementById('executions').textContent = stats.total_executions.toLocaleString();
                document.getElementById('crashes').textContent = stats.crashes_found;
                document.getElementById('coverage').textContent = stats.coverage_percent + '%';
                document.getElementById('speed').textContent = stats.executions_per_sec.toFixed(1);
            }
            if (data.type === 'crash' || data.type === 'init') {
                const crashes = data.crashes || [data.crash];
                if (crashes && crashes.length > 0) {
                    const list = document.getElementById('crash-list');
                    list.innerHTML = crashes.map(c =>
                        `<div class="crash-item"><strong>${c.crash_type}</strong> - ${c.test_file}<br><small>${c.timestamp}</small></div>`
                    ).join('');
                }
            }
        };

        // Keep connection alive
        setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping'); }, 25000);
    </script>
</body>
</html>
"""

    def start(self, blocking: bool = False) -> None:
        """Start the dashboard server.

        Args:
            blocking: If True, block until server stops

        """
        if self._running:
            logger.warning("Server is already running")
            return

        self._running = True
        self._app = self._create_app()

        if blocking:
            self._run_server()
        else:
            self._server_thread = threading.Thread(
                target=self._run_server,
                daemon=True,
            )
            self._server_thread.start()
            logger.info(f"Dashboard started at http://{self.host}:{self.port}")

    def _run_server(self) -> None:
        """Run the uvicorn server."""
        try:
            import uvicorn
        except ImportError as e:
            raise ImportError(
                "uvicorn is required for dashboard. Install with: pip install uvicorn"
            ) from e

        uvicorn.run(
            self._app,
            host=self.host,
            port=self.port,
            log_level="warning",
        )

    def stop(self) -> None:
        """Stop the dashboard server."""
        self._running = False
        logger.info("Dashboard server stopped")

    def update_stats(self, stats: FuzzingStats) -> None:
        """Update fuzzing statistics and broadcast to clients.

        Args:
            stats: Updated fuzzing statistics

        """
        with self._lock:
            self._stats = stats

        # Trigger callbacks
        for callback in self._update_callbacks:
            try:
                callback(stats)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

        # Broadcast to WebSocket clients
        self._broadcast(
            {
                "type": "stats",
                "stats": stats.to_dict(),
            }
        )

    def add_crash(self, crash: CrashInfo) -> None:
        """Add a discovered crash and broadcast to clients.

        Args:
            crash: Crash information

        """
        with self._lock:
            self._crashes.append(crash)
            # Keep only last 1000 crashes
            if len(self._crashes) > 1000:
                self._crashes = self._crashes[-1000:]

        self._broadcast(
            {
                "type": "crash",
                "crash": crash.to_dict(),
            }
        )

    def _broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast message to all connected WebSocket clients.

        Args:
            message: Message to broadcast

        """
        if not self._connected_clients:
            return

        # Schedule broadcast on event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self._async_broadcast(message), loop)
        except RuntimeError:
            pass

    async def _async_broadcast(self, message: dict[str, Any]) -> None:
        """Async broadcast to all clients.

        Args:
            message: Message to broadcast

        """
        disconnected = set()
        for client in self._connected_clients:
            try:
                await client.send_json(message)
            except Exception:
                disconnected.add(client)

        self._connected_clients -= disconnected

    def on_update(self, callback: Callable[[FuzzingStats], None]) -> None:
        """Register a callback for stats updates.

        Args:
            callback: Function to call when stats are updated

        """
        self._update_callbacks.append(callback)

    def get_stats(self) -> FuzzingStats:
        """Get current fuzzing statistics.

        Returns:
            Current FuzzingStats object

        """
        with self._lock:
            return self._stats

    def get_crashes(self) -> list[CrashInfo]:
        """Get list of discovered crashes.

        Returns:
            List of CrashInfo objects

        """
        with self._lock:
            return list(self._crashes)
