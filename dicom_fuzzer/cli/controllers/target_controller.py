"""Target Testing Controller for DICOM Fuzzer CLI.

Handles target application testing with fuzzed files.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import time
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING, Any

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

            # Register all test files with the session
            file_id_map: dict[Path, str] = {}
            for f in files:
                resolved = f.resolve()
                file_id = session.start_file_fuzzing(
                    source_file=resolved,
                    output_file=resolved,
                    severity="unknown",
                )
                session.end_file_fuzzing(resolved)
                file_id_map[resolved] = file_id

            # Run campaign
            test_start = time.time()
            results = runner.run_campaign(
                test_files=files, stop_on_crash=args.stop_on_crash
            )
            test_elapsed = time.time() - test_start

            # Record crashes into session
            TargetTestingController._record_crashes(
                session, results, file_id_map, args.target
            )

            # Display results
            summary = runner.get_summary(results)  # type: ignore[arg-type]
            print(summary)
            print(
                f"\nTarget testing completed in {test_elapsed:.2f}s "
                f"({len(files) / test_elapsed:.1f} tests/sec)\n"
            )

            # Generate HTML report
            report_path = TargetTestingController._generate_report(session, output_dir)
            if report_path:
                print(f"  Report: {report_path}\n")

            return 0

        except FileNotFoundError as e:
            logger.error("Target executable not found: %s", e)
            print(f"\n[ERROR] Target executable not found: {args.target}")
            print("Please verify the path and try again.")
            return 1
        except ImportError as e:
            logger.error("Missing dependency: %s", e)
            print(f"\n[ERROR] {e}")
            return 1
        except Exception as e:
            logger.error("Target testing failed: %s", e, exc_info=args.verbose)
            print(f"\n[ERROR] Target testing failed: {e}")
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
        """Display test campaign header.

        Args:
            args: Parsed command-line arguments
            files: List of test files
            gui_mode: Whether GUI mode is enabled
            memory_limit: Memory limit in MB

        """
        print("\n" + "=" * 70)
        if gui_mode:
            print("  GUI Application Testing (--gui-mode)")
        else:
            print("  Target Application Testing")
        print("=" * 70)
        print(f"  Target:     {args.target}")
        print(f"  Timeout:    {args.timeout}s")
        print(f"  Test files: {len(files)}")
        if gui_mode:
            print("  Mode:       GUI (app killed after timeout)")
            if memory_limit:
                print(f"  Mem limit:  {memory_limit}MB")
            startup_delay_display = getattr(args, "startup_delay", 0.0)
            if startup_delay_display > 0:
                print(f"  Startup:    {startup_delay_display}s delay before monitoring")
        print("=" * 70 + "\n")

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
                print(
                    "[ERROR] GUI mode requires psutil. Install with: pip install psutil"
                )
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
    ) -> None:
        """Record crash results into the fuzzing session.

        Args:
            session: Active fuzzing session
            results: Campaign results keyed by status
            file_id_map: Mapping from file path to session file ID
            target_path: Path to target executable

        """
        crash_results = results.get(ExecutionStatus.CRASH, [])
        hang_results = results.get(ExecutionStatus.HANG, [])

        for result in crash_results:
            test_file = result.test_file.resolve()
            file_id = file_id_map.get(test_file)
            if not file_id:
                continue

            severity = "high"
            exception_type = None
            exception_message = None

            # Extract Windows crash info if available
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
