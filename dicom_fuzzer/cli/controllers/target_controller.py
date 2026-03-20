"""Target Testing Controller for DICOM Fuzzer CLI.

Handles target application testing with fuzzed files.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import time
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.cli.utils import output as cli
from dicom_fuzzer.cli.utils.gui_runner import GUITargetRunner
from dicom_fuzzer.core.harness.target_runner import ExecutionStatus, TargetRunner
from dicom_fuzzer.core.reporting.enhanced_reporter import EnhancedReportGenerator
from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

if TYPE_CHECKING:
    from dicom_fuzzer.core.session.resource_manager import ResourceLimits

logger = logging.getLogger(__name__)

# Check for psutil availability
HAS_PSUTIL = importlib.util.find_spec("psutil") is not None


class TargetTestingController:
    """Controller for target application testing."""

    @staticmethod
    def run(
        args: Namespace,
        files: list[Path],
        output_dir: Path,
        resource_limits: ResourceLimits | None = None,
    ) -> int:
        """Run target testing campaign.

        Args:
            args: Parsed command-line arguments
            files: List of files to test with
            output_dir: Output directory for crash artifacts
            resource_limits: Optional resource limits for testing

        Returns:
            Exit code (0 for success, 1 for failure)

        """
        gui_mode = getattr(args, "gui_mode", False)
        memory_limit = getattr(args, "memory_limit", None)

        # Display header
        TargetTestingController._display_header(args, files, gui_mode, memory_limit)

        try:
            # Create appropriate runner
            runner = TargetTestingController._create_runner(
                args=args,
                output_dir=output_dir,
                gui_mode=gui_mode,
                memory_limit=memory_limit,
                resource_limits=resource_limits,
            )

            if resource_limits and not gui_mode:
                logger.info("Resource limits will be enforced during testing")

            # Create session for crash tracking and reporting
            crash_dir = output_dir / "crashes"
            session = FuzzingSession(
                session_name=f"target_test_{Path(args.target).stem}",
                output_dir=str(output_dir),
                reports_dir=str(output_dir / "reports"),
                crashes_dir=str(crash_dir),
                config={
                    "target": args.target,
                    "timeout": args.timeout,
                    "gui_mode": gui_mode,
                },
            )

            # Load mutation map (filename -> strategy) from generation phase
            mutation_map = TargetTestingController._load_mutation_map(files)

            # Register all test files with the session
            file_id_map: dict[Path, str] = {}
            for f in files:
                resolved = f.resolve()
                entry = mutation_map.get(f.name, {})
                strategy = entry.get("strategy", "")
                variant = entry.get("variant")
                file_id = session.start_file_fuzzing(
                    source_file=resolved,
                    output_file=resolved,
                    severity="unknown",
                )
                if strategy:
                    session.record_mutation(
                        strategy_name=strategy,
                        mutation_type="format_fuzzing",
                        variant=variant,
                    )
                session.end_file_fuzzing(resolved)
                file_id_map[resolved] = file_id

            # Run campaign
            test_start = time.time()
            results = runner.run_campaign(
                test_files=files, stop_on_crash=args.stop_on_crash
            )
            test_elapsed = time.time() - test_start

            # Record crashes into session and print crash alerts
            TargetTestingController._record_crashes(
                session, results, file_id_map, args.target
            )

            # Display results
            summary = runner.get_summary(results)  # type: ignore[arg-type]
            print(summary)
            tests_per_sec = len(files) / test_elapsed if test_elapsed > 0 else 0
            cli.info(
                f"Target testing completed in {test_elapsed:.2f}s "
                f"({tests_per_sec:.1f} tests/sec)"
            )

            # Generate HTML report
            report_path = TargetTestingController._generate_report(session, output_dir)
            if report_path:
                cli.detail("Report", str(report_path))

            return 0

        except FileNotFoundError as e:
            logger.error("Target executable not found: %s", e)
            cli.error(f"Target executable not found: {args.target}")
            cli.info("Please verify the path and try again.")
            return 1
        except ImportError as e:
            logger.error("Missing dependency: %s", e)
            cli.error(str(e))
            return 1
        except Exception as e:
            logger.error("Target testing failed: %s", e, exc_info=args.verbose)
            cli.error(f"Target testing failed: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()
            return 1

    @staticmethod
    def _display_header(
        args: Namespace,
        files: list[Path],
        gui_mode: bool,
        memory_limit: int | None,
    ) -> None:
        """Display test campaign header."""
        title = (
            "Target Application Testing (GUI mode)"
            if gui_mode
            else "Target Application Testing"
        )
        cli.section(title)
        cli.detail("Target", str(args.target))
        cli.detail("Timeout", f"{args.timeout}s")
        cli.detail("Files", str(len(files)))
        if gui_mode:
            cli.detail("Mode", "GUI (app killed after timeout)")
            if memory_limit:
                cli.detail("Mem limit", f"{memory_limit}MB")
            startup_delay_display = getattr(args, "startup_delay", 0.0)
            if startup_delay_display > 0:
                cli.detail(
                    "Startup", f"{startup_delay_display}s delay before monitoring"
                )
        cli.divider()

    @staticmethod
    def _load_mutation_map(
        files: list[Path],
    ) -> dict[str, dict[str, str | None]]:
        """Load filename->strategy/variant mapping written by the generation phase.

        Handles both the old format ({filename: strategy_str}) and the current
        format ({filename: {"strategy": str, "variant": str | null}}).
        """
        if not files:
            return {}
        # mutation_map.json lives in the same directory as the fuzzed files
        map_path = files[0].parent / "mutation_map.json"
        if not map_path.exists():
            return {}
        try:
            with open(map_path) as f:
                raw: dict[str, object] = json.load(f)
            # Normalize: old entries are plain strings; new entries are dicts
            normalized: dict[str, dict[str, str | None]] = {}
            for filename, value in raw.items():
                if isinstance(value, dict):
                    normalized[filename] = {
                        "strategy": value.get("strategy", ""),
                        "variant": value.get("variant"),
                    }
                else:
                    normalized[filename] = {"strategy": str(value), "variant": None}
            logger.info("Loaded mutation map: %d entries", len(normalized))
            return normalized
        except Exception as e:
            logger.warning("Failed to load mutation map: %s", e)
            return {}

    @staticmethod
    def _create_runner(
        args: Namespace,
        output_dir: Path,
        gui_mode: bool,
        memory_limit: int | None,
        resource_limits: ResourceLimits | None,
    ) -> GUITargetRunner | TargetRunner:
        """Create the appropriate target runner.

        Args:
            args: Parsed command-line arguments
            output_dir: Output directory for crashes
            gui_mode: Whether to use GUI mode
            memory_limit: Memory limit for GUI mode
            resource_limits: Resource limits for CLI mode

        Returns:
            GUITargetRunner or TargetRunner instance

        Raises:
            SystemExit: If GUI mode requested but psutil not available

        """
        runner: GUITargetRunner | TargetRunner
        if gui_mode:
            # Use GUITargetRunner for GUI applications
            if not HAS_PSUTIL:
                cli.error("GUI mode requires psutil. Install with: pip install psutil")
                sys.exit(1)

            startup_delay = getattr(args, "startup_delay", 0.0)
            runner = GUITargetRunner(
                target_executable=args.target,
                timeout=args.timeout,
                crash_dir=str(output_dir / "crashes"),
                memory_limit_mb=memory_limit,
                startup_delay=startup_delay,
            )
            logger.info("Starting GUI fuzzing campaign...")
        else:
            # Use standard TargetRunner for CLI applications
            runner = TargetRunner(
                target_executable=args.target,
                timeout=args.timeout,
                crash_dir=str(output_dir / "crashes"),
                resource_limits=resource_limits,
            )
            logger.info("Starting target testing campaign...")

        return runner

    @staticmethod
    def _record_crashes(
        session: FuzzingSession,
        results: dict[ExecutionStatus, list[Any]],
        file_id_map: dict[Path, str],
        target_path: str,
    ) -> int:
        """Record crash results into the fuzzing session and print alerts.

        Returns:
            Total number of crashes + hangs recorded.

        """
        crash_results = results.get(ExecutionStatus.CRASH, [])
        hang_results = results.get(ExecutionStatus.HANG, [])
        alert_num = 0

        for result in crash_results:
            test_file = result.test_file.resolve()
            file_id = file_id_map.get(test_file)
            if not file_id:
                continue

            severity = "high"
            exception_type = None
            exception_message = None

            crash_info = getattr(result, "windows_crash_info", None)
            if crash_info:
                exception_type = crash_info.exception_name
                exception_message = crash_info.description
                sev = str(crash_info.severity).lower()
                if "critical" in sev:
                    severity = "critical"
                elif "high" in sev:
                    severity = "high"
                else:
                    severity = "medium"

            exit_code = getattr(result, "exit_code", None)
            if not exception_message and exit_code is not None:
                exception_message = f"Process exited with code {exit_code}"

            session.record_crash(
                file_id=file_id,
                crash_type="crash",
                severity=severity,
                return_code=exit_code,
                exception_type=exception_type,
                exception_message=exception_message,
                viewer_path=target_path,
            )

            alert_num += 1
            label = exception_type or "CRASH"
            cli.warning(f"CRASH #{alert_num}: {test_file.name} ({label}, {severity})")

        for result in hang_results:
            test_file = result.test_file.resolve()
            file_id = file_id_map.get(test_file)
            if not file_id:
                continue

            session.record_crash(
                file_id=file_id,
                crash_type="hang",
                severity="medium",
                exception_type="Timeout",
                exception_message=f"Process hung (timeout={getattr(result, 'execution_time', 'unknown')}s)",
                viewer_path=target_path,
            )

            alert_num += 1
            cli.warning(f"HANG #{alert_num}: {test_file.name} (Timeout, medium)")

        return alert_num

    @staticmethod
    def _generate_report(
        session: FuzzingSession,
        output_dir: Path,
    ) -> Path | None:
        """Generate HTML report from session data.

        Args:
            session: Completed fuzzing session
            output_dir: Output directory for reports

        Returns:
            Path to generated HTML report, or None on failure

        """
        try:
            report_data = session.generate_session_report()
            reports_dir = output_dir / "reports"
            generator = EnhancedReportGenerator(output_dir=str(reports_dir))
            return generator.generate_html_report(report_data)
        except Exception as e:
            logger.warning("Failed to generate HTML report: %s", e)
            return None
