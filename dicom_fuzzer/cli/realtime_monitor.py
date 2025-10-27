#!/usr/bin/env python3
"""Real-Time Fuzzing Monitor

Provides live monitoring of fuzzing campaigns with auto-refreshing statistics.
Shows progress, crash detection, and performance metrics in real-time.

Usage:
    # Monitor a fuzzing session
    python tools/realtime_monitor.py --session-dir ./output

    # Monitor with specific refresh rate
    python tools/realtime_monitor.py --session-dir ./output --refresh 2
"""

import argparse
import json
import time
from pathlib import Path


class RealtimeMonitor:
    """Real-time monitoring of fuzzing campaigns."""

    def __init__(self, session_dir: Path, refresh_interval: int = 1):
        """Initialize real-time monitor.

        Args:
            session_dir: Directory containing fuzzing session
            refresh_interval: Refresh interval in seconds

        """
        self.session_dir = session_dir
        self.refresh_interval = refresh_interval
        self.start_time = time.time()

    def monitor(self):
        """Start monitoring loop."""
        print("\n" + "=" * 80)
        print("DICOM FUZZER - REAL-TIME MONITOR")
        print("=" * 80)
        print(f"Session Directory: {self.session_dir}")
        print(f"Refresh Interval: {self.refresh_interval}s")
        print("Press Ctrl+C to stop\n")

        try:
            while True:
                self._refresh_display()
                time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")

    def _refresh_display(self):
        """Refresh the display with current statistics."""
        # Find latest session JSON
        reports_dir = Path("./reports/json")
        if not reports_dir.exists():
            self._print_waiting()
            return

        session_files = list(reports_dir.glob("session_*.json"))
        if not session_files:
            self._print_waiting()
            return

        latest = max(session_files, key=lambda p: p.stat().st_mtime)

        try:
            with open(latest, encoding="utf-8") as f:
                data = json.load(f)

            self._display_stats(data)
        except Exception as e:
            print(f"Error reading session: {e}")

    def _print_waiting(self):
        """Print waiting message."""
        elapsed = time.time() - self.start_time
        print(f"\rWaiting for session data... ({elapsed:.0f}s)", end="", flush=True)

    def _display_stats(self, data: dict):
        """Display statistics from session data."""
        # Clear screen (platform independent)
        print("\033[2J\033[H", end="")

        session_info = data.get("session_info", {})
        stats = data.get("statistics", {})
        crashes = data.get("crashes", [])

        # Header
        print("=" * 80)
        print(f"SESSION: {session_info.get('session_name', 'Unknown')}")
        print(f"STARTED: {session_info.get('start_time', 'N/A')}")
        elapsed = time.time() - self.start_time
        print(f"ELAPSED: {elapsed:.1f}s")
        print("=" * 80)

        # Statistics Grid
        print("\n📊 FUZZING STATISTICS")
        print("-" * 80)

        col_width = 25
        row1 = [
            f"Files Fuzzed: {stats.get('files_fuzzed', 0)}",
            f"Mutations: {stats.get('mutations_applied', 0)}",
            f"Rate: {stats.get('files_fuzzed', 0) / max(elapsed, 1):.2f} files/s",
        ]
        print(" | ".join(s.ljust(col_width) for s in row1))

        # Results Grid
        print("\n🎯 TEST RESULTS")
        print("-" * 80)

        crashes_count = stats.get("crashes", 0)
        hangs_count = stats.get("hangs", 0)
        success_count = stats.get("successes", 0)
        total_tests = crashes_count + hangs_count + success_count

        row2 = [
            f"✓ Success: {success_count}",
            f"💥 Crashes: {crashes_count}",
            f"⏱️ Hangs: {hangs_count}",
        ]
        print(" | ".join(s.ljust(col_width) for s in row2))

        if total_tests > 0:
            crash_rate = (crashes_count / total_tests) * 100
            hang_rate = (hangs_count / total_tests) * 100

            print(f"\nCrash Rate: {crash_rate:.1f}% | Hang Rate: {hang_rate:.1f}%")

        # Recent Crashes
        if crashes:
            print("\n🔥 RECENT CRASHES")
            print("-" * 80)

            for crash in crashes[-5:]:  # Last 5 crashes
                crash_id = crash.get("crash_id", "Unknown")
                crash_type = crash.get("crash_type", "unknown")
                severity = crash.get("severity", "unknown")

                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(severity, "⚪")

                print(f"{severity_icon} {crash_id} | {crash_type} | {severity}")

        # Progress bar
        expected_total = 50  # Could be configurable
        progress = min(stats.get("files_fuzzed", 0), expected_total)
        bar_width = 60
        filled = int((progress / expected_total) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        print("\n📈 PROGRESS")
        print("-" * 80)
        print(f"[{bar}] {progress}/{expected_total}")

        print("\n" + "=" * 80)
        print(
            f"Last Update: {time.strftime('%H:%M:%S')} | Refresh: {self.refresh_interval}s"
        )
        print("Press Ctrl+C to stop")


def main():
    """Parse arguments and run real-time monitor."""
    parser = argparse.ArgumentParser(
        description="Real-time monitoring for DICOM fuzzing campaigns"
    )

    parser.add_argument(
        "--session-dir",
        type=Path,
        default=Path("./output"),
        help="Session directory to monitor (default: ./output)",
    )

    parser.add_argument(
        "--refresh",
        type=int,
        default=1,
        help="Refresh interval in seconds (default: 1)",
    )

    args = parser.parse_args()

    monitor = RealtimeMonitor(args.session_dir, args.refresh)
    monitor.monitor()


if __name__ == "__main__":
    main()
