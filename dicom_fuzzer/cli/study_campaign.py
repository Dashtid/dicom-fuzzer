"""Study-Level Fuzzing Campaign Subcommand for DICOM Fuzzer.

Combines study-level mutation with target application testing for automated
security testing campaigns. Monitors for crashes, memory issues, and collects
artifacts for analysis.

Example:
    dicom-fuzzer study-campaign --target ./viewer.exe --study ./test_study --count 100

"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for study-campaign subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer study-campaign",
        description="Study-level fuzzing campaign with target application testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run campaign with 100 tests
  dicom-fuzzer study-campaign --target ./viewer.exe --study ./test_study --count 100

  # List available strategies
  dicom-fuzzer study-campaign --list-strategies

  # Use specific strategy with aggressive mutations
  dicom-fuzzer study-campaign --target ./viewer.exe --study ./test_study \\
      --strategy cross-series --severity aggressive --count 50

  # Stop on first crash
  dicom-fuzzer study-campaign --target ./viewer.exe --study ./test_study \\
      --stop-on-crash

For study mutation only (no target testing), use:
  dicom-fuzzer study --study ./test_study -o ./output
        """,
    )

    # Action group - either run campaign or list strategies/adapters
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--target",
        type=str,
        metavar="EXE",
        help="Path to target executable (DICOM viewer, etc.)",
    )
    action_group.add_argument(
        "--list-strategies",
        action="store_true",
        help="List available study mutation strategies",
    )
    action_group.add_argument(
        "--list-adapters",
        action="store_true",
        help="List available viewer adapters",
    )

    # Study input
    parser.add_argument(
        "--study",
        type=str,
        metavar="DIR",
        help="Path to source study directory containing DICOM series (required with --target)",
    )

    # Mutation options
    mutation_group = parser.add_argument_group("mutation options")
    mutation_group.add_argument(
        "--strategy",
        type=str,
        choices=[
            "cross-series",
            "frame-of-reference",
            "patient-consistency",
            "study-metadata",
            "mixed-modality",
            "all",
        ],
        default="all",
        help="Mutation strategy (default: all)",
    )
    mutation_group.add_argument(
        "--severity",
        type=str,
        choices=["minimal", "moderate", "aggressive", "extreme"],
        default="moderate",
        help="Mutation severity (default: moderate)",
    )
    mutation_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=100,
        metavar="N",
        help="Number of test iterations (default: 100)",
    )
    mutation_group.add_argument(
        "--mutations-per-test",
        type=int,
        default=5,
        metavar="N",
        help="Mutations per test iteration (default: 5)",
    )

    # Target options
    target_group = parser.add_argument_group("target options")
    target_group.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        metavar="SEC",
        help="Target timeout in seconds (default: 15.0)",
    )
    target_group.add_argument(
        "--memory-limit",
        type=int,
        default=2048,
        metavar="MB",
        help="Memory limit in MB (default: 2048)",
    )
    target_group.add_argument(
        "--startup-delay",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Startup delay before monitoring in seconds (default: 3.0)",
    )
    target_group.add_argument(
        "--stop-on-crash",
        action="store_true",
        help="Stop campaign on first crash",
    )

    # Adapter options (viewer-specific automation)
    adapter_group = parser.add_argument_group("adapter options")
    adapter_group.add_argument(
        "--adapter",
        type=str,
        metavar="NAME",
        help="Viewer adapter for UI automation (e.g., 'affinity'). "
        "Enables study loading into viewport and validation.",
    )
    adapter_group.add_argument(
        "--series-name",
        type=str,
        metavar="NAME",
        help="Series name to search for when using adapter",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="DIR",
        default="./artifacts/study-campaign",
        help="Output directory (default: ./artifacts/study-campaign)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_list_strategies() -> int:
    """List available study mutation strategies."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Study Campaign Mutation Strategies")
    print("=" * 70 + "\n")

    strategies = [
        ("cross-series", "Cross-series reference attacks (ReferencedSeriesSequence)"),
        ("frame-of-reference", "FrameOfReferenceUID manipulation for registration"),
        ("patient-consistency", "Patient demographic conflicts across series"),
        ("study-metadata", "Study-level metadata corruption"),
        ("mixed-modality", "Mixed modality study injection"),
        ("all", "Apply all strategies (cycles through each)"),
    ]

    print("Available strategies:\n")
    for name, description in strategies:
        print(f"  {name:22} - {description}")

    print("\n[i] Use --strategy <name> to select a specific strategy")
    print("[i] Campaign cycles through severities: moderate -> aggressive -> extreme")
    return 0


def run_list_adapters() -> int:
    """List available viewer adapters."""
    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - Available Viewer Adapters")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.core.adapters import get_adapter, list_adapters

        adapters = list_adapters()
        if adapters:
            print("Available adapters:\n")
            for name in adapters:
                try:
                    adapter = get_adapter(name)
                    viewers = ", ".join(adapter.supported_viewers)
                    print(f"  {name:15} - {adapter.name} ({viewers})")
                except Exception:
                    print(f"  {name:15} - (error loading)")
        else:
            print("No adapters available.")
            print("\n[i] Install pywinauto for Windows UI automation:")
            print("    pip install pywinauto")

        print("\n[i] Use --adapter <name> to enable viewer-specific automation")
        print("[i] Adapters load studies into viewport and can extract patient info")

    except ImportError:
        print("No adapters available (adapters module not found).")

    return 0


def log(message: str, log_file: Path | None = None) -> None:
    """Log message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"{timestamp} - {message}"
    print(formatted)
    if log_file:
        with open(log_file, "a") as f:
            f.write(formatted + "\n")


def _run_single_test(
    test_id: int,
    total_tests: int,
    study_path: Path,
    strategy: object,
    severity: str,
    mutations_per_test: int,
    harness: object,
    viewer_adapter: object | None,
    series_name: str | None,
    log_file: Path | None,
    verbose: bool,
) -> dict[str, Any]:
    """Execute a single test iteration.

    Args:
        test_id: Current test number.
        total_tests: Total planned tests.
        study_path: Path to source study.
        strategy: Mutation strategy to use.
        severity: Mutation severity level.
        mutations_per_test: Number of mutations per test.
        harness: TargetHarness instance.
        viewer_adapter: Optional viewer adapter.
        series_name: Optional series name for adapter.
        log_file: Optional log file path.
        verbose: Whether to print verbose output.

    Returns:
        dict with keys: status, is_failure, error_message, records

    """
    from dicom_fuzzer.attacks.series.study_mutator import StudyMutator

    result_info = {
        "status": "error",
        "is_failure": False,
        "error_message": None,
        "records": [],
        "render_failed": False,
    }

    mutator = StudyMutator(severity=severity)

    with tempfile.TemporaryDirectory(prefix="fuzz_study_") as temp_dir:
        temp_path = Path(temp_dir)

        try:
            # Reload study for fresh mutation
            study = mutator.load_study(study_path)

            # Apply mutations
            mutated_datasets, records = mutator.mutate_study(
                study,
                strategy=strategy,
                mutation_count=mutations_per_test,
            )
            result_info["records"] = records

            # Save mutated study
            output_study = temp_path / "study"
            output_study.mkdir()
            for series_idx, datasets in enumerate(mutated_datasets):
                series_dir = output_study / f"series_{series_idx:03d}"
                series_dir.mkdir(parents=True, exist_ok=True)
                for ds_idx, ds in enumerate(datasets):
                    ds.save_as(str(series_dir / f"slice_{ds_idx:04d}.dcm"))

            log(
                f"[{test_id}/{total_tests}] Testing "
                f"{strategy.value}/{severity} "
                f"(mutations: {len(records)})",
                log_file,
            )

            # Test with target
            result = harness.test_study_directory(
                output_study,
                viewer_adapter=viewer_adapter,
                series_name=series_name,
            )

            result_info["status"] = result.status
            result_info["is_failure"] = result.is_failure()
            result_info["error_message"] = result.error_message
            result_info["result"] = result
            result_info["output_study"] = output_study

            # Log result
            if result.is_failure():
                log(
                    f"  [!] {result.status.upper()}: "
                    f"{result.error_message or 'unknown'}",
                    log_file,
                )
                if result.error_message and "Render failed" in result.error_message:
                    result_info["render_failed"] = True
            else:
                log(
                    f"  [+] OK (mem: {result.memory_peak_mb:.1f}MB, "
                    f"time: {result.duration_seconds:.1f}s)",
                    log_file,
                )

            if verbose:
                for record in records:
                    print(
                        f"    - {record.strategy}: "
                        f"{record.tag} -> {record.mutated_value}"
                    )

        except Exception as e:
            log(f"  [-] Error: {e}", log_file)
            result_info["status"] = "error"
            result_info["error_message"] = str(e)
            if verbose:
                traceback.print_exc()

    return result_info


def _save_campaign_results(
    output_path: Path,
    target_path: Path,
    study_path: Path,
    args: argparse.Namespace,
    stats: dict[str, Any],
    log_file: Path | None,
) -> None:
    """Save campaign results to JSON file.

    Args:
        output_path: Output directory.
        target_path: Path to target executable.
        study_path: Path to source study.
        args: Command line arguments.
        stats: Campaign statistics.
        log_file: Optional log file path.

    """
    results_file = output_path / "campaign_results.json"
    with open(results_file, "w") as f:
        json.dump(
            {
                "config": {
                    "target": str(target_path),
                    "study": str(study_path),
                    "strategy": args.strategy,
                    "severity": args.severity,
                    "count": args.count,
                    "timeout": args.timeout,
                    "memory_limit": args.memory_limit,
                    "adapter": args.adapter,
                },
                "stats": stats,
            },
            f,
            indent=2,
        )
    log(f"[+] Results saved to: {results_file}", log_file)


def _validate_campaign_args(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path] | None:
    """Validate campaign arguments and return paths.

    Returns:
        Tuple of (target_path, study_path, output_path) or None if invalid.

    """
    if not args.study:
        print("[-] --study is required when using --target")
        return None

    target_path = Path(args.target)
    study_path = Path(args.study)
    output_path = Path(args.output)

    if not target_path.exists():
        print(f"[-] Target executable not found: {target_path}")
        return None

    if not study_path.exists():
        print(f"[-] Study directory not found: {study_path}")
        return None

    return target_path, study_path, output_path


def _setup_campaign_dirs(output_path: Path) -> tuple[Path, Path]:
    """Create campaign directories and return paths.

    Returns:
        Tuple of (crashes_dir, log_file).

    """
    output_path.mkdir(parents=True, exist_ok=True)
    crashes_dir = output_path / "crashes"
    crashes_dir.mkdir(exist_ok=True)
    log_file = output_path / "campaign.log"
    return crashes_dir, log_file


def _log_campaign_header(
    target_path: Path,
    study_path: Path,
    output_path: Path,
    args: argparse.Namespace,
    log_file: Path,
) -> None:
    """Log campaign header information."""
    log("=" * 70, log_file)
    log("STUDY-LEVEL FUZZING CAMPAIGN", log_file)
    log("=" * 70, log_file)
    log(f"Target: {target_path}", log_file)
    log(f"Study source: {study_path}", log_file)
    log(f"Output: {output_path}", log_file)
    log(f"Strategy: {args.strategy}", log_file)
    log(f"Severity: {args.severity}", log_file)
    log(f"Total tests planned: {args.count}", log_file)
    log("=" * 70, log_file)


def _setup_viewer_adapter(
    adapter_name: str | None, log_file: Path
) -> tuple[object | None, int | None]:
    """Setup viewer adapter if specified.

    Returns:
        Tuple of (adapter, error_code). error_code is None if successful.

    """
    if not adapter_name:
        return None, None

    try:
        from dicom_fuzzer.core.adapters import get_adapter

        adapter = get_adapter(adapter_name)
        log(f"[+] Using adapter: {adapter.name}", log_file)
        return adapter, None
    except ImportError:
        log("[-] Adapters module not available", log_file)
        return None, 1
    except ValueError as e:
        log(f"[-] {e}", log_file)
        return None, 1


def _get_strategies(strategy_arg: str, strategy_map: dict[str, Any]) -> list[Any]:
    """Get list of strategies based on CLI argument."""
    if strategy_arg == "all":
        return list(strategy_map.values())
    return [strategy_map[strategy_arg]]


def _get_severities(severity_arg: str) -> list[str]:
    """Get list of severities for campaign cycling."""
    severities = ["moderate", "aggressive", "extreme"]
    if severity_arg != "moderate":
        try:
            start_idx = severities.index(severity_arg)
            return severities[start_idx:]
        except ValueError:
            return [severity_arg]
    return severities


def _process_test_result(
    result: object,
    stats: dict[str, Any],
    test_id: int,
    output_study: Path,
    records: list[Any],
    harness: object,
    viewer_adapter: object | None,
    args: argparse.Namespace,
    log_file: Path,
) -> bool:
    """Process test result, update stats, and save crash artifacts.

    Returns:
        True if campaign should stop (--stop-on-crash triggered).

    """
    stats["total"] += 1
    status = result.status
    if status in stats:
        stats[status] += 1

    if result.is_failure():
        log(
            f"  [!] {result.status.upper()}: {result.error_message or 'unknown'}",
            log_file,
        )
        if result.error_message and "Render failed" in result.error_message:
            stats["render_failed"] += 1
        harness.save_crash_artifact(
            result,
            output_study,
            test_id,
            mutation_records=[r.__dict__ for r in records],
            viewer_adapter=viewer_adapter,
        )
        if args.stop_on_crash and result.status == "crash":
            log("[!] Stopping on crash (--stop-on-crash)", log_file)
            return True
    else:
        log(
            f"  [+] OK (mem: {result.memory_peak_mb:.1f}MB, "
            f"time: {result.duration_seconds:.1f}s)",
            log_file,
        )

    if args.verbose:
        for record in records:
            print(f"    - {record.strategy}: {record.tag} -> {record.mutated_value}")

    return False


def _log_progress(
    test_id: int, total_count: int, start_time: float, log_file: Path
) -> None:
    """Log campaign progress every 10 tests."""
    if test_id % 10 != 0:
        return
    elapsed = time.time() - start_time
    rate = test_id / elapsed if elapsed > 0 else 0
    remaining = (total_count - test_id) / rate / 60 if rate > 0 else 0
    log(
        f"  Progress: {test_id}/{total_count} "
        f"({rate * 60:.2f} tests/min, ~{remaining:.1f}min remaining)",
        log_file,
    )


def _log_campaign_summary(
    stats: dict[str, Any], elapsed_total: float, log_file: Path
) -> None:
    """Log final campaign summary."""
    log("", log_file)
    log("=" * 70, log_file)
    log("CAMPAIGN COMPLETE", log_file)
    log("=" * 70, log_file)
    log(f"Duration: {elapsed_total / 60:.2f} minutes", log_file)
    log(f"Total tests: {stats['total']}", log_file)
    log(f"Success: {stats['success']}", log_file)
    log(f"Crashes: {stats['crash']}", log_file)
    log(f"Memory exceeded: {stats['memory_exceeded']}", log_file)
    if stats["render_failed"] > 0:
        log(f"Render failed: {stats['render_failed']}", log_file)
    log(f"Errors: {stats['error']}", log_file)
    log("=" * 70, log_file)


def _run_campaign_loop(
    args: argparse.Namespace,
    study_path: Path,
    severities: list[str],
    strategies: list[Any],
    harness: object,
    viewer_adapter: object | None,
    stats: dict[str, Any],
    log_file: Path,
    start_campaign: float,
) -> bool:
    """Run the main campaign test loop.

    Returns:
        True if campaign was stopped early (e.g., --stop-on-crash).

    """
    from dicom_fuzzer.attacks.series.study_mutator import StudyMutator

    test_id = 0
    try:
        for severity in severities:
            mutator = StudyMutator(severity=severity)
            for strategy in strategies:
                tests_per_combo = max(
                    1, args.count // (len(severities) * len(strategies))
                )
                for _ in range(tests_per_combo):
                    if test_id >= args.count:
                        return False

                    test_id += 1
                    should_stop = _run_single_campaign_test(
                        test_id=test_id,
                        args=args,
                        study_path=study_path,
                        strategy=strategy,
                        severity=severity,
                        mutator=mutator,
                        harness=harness,
                        viewer_adapter=viewer_adapter,
                        stats=stats,
                        log_file=log_file,
                    )
                    if should_stop:
                        return True

                    _log_progress(test_id, args.count, start_campaign, log_file)

                if test_id >= args.count:
                    return False
            if test_id >= args.count:
                return False

    except KeyboardInterrupt:
        log("[i] Campaign interrupted by user", log_file)

    return False


def _run_single_campaign_test(
    test_id: int,
    args: argparse.Namespace,
    study_path: Path,
    strategy: object,
    severity: str,
    mutator: object,
    harness: object,
    viewer_adapter: object | None,
    stats: dict[str, Any],
    log_file: Path,
) -> bool:
    """Run a single test in the campaign.

    Returns:
        True if campaign should stop (--stop-on-crash triggered).

    """
    with tempfile.TemporaryDirectory(prefix="fuzz_study_") as temp_dir:
        temp_path = Path(temp_dir)
        try:
            # Load and mutate study
            study = mutator.load_study(study_path)
            mutated_datasets, records = mutator.mutate_study(
                study,
                strategy=strategy,
                mutation_count=args.mutations_per_test,
            )

            # Save mutated study
            output_study = temp_path / "study"
            output_study.mkdir()
            for series_idx, datasets in enumerate(mutated_datasets):
                series_dir = output_study / f"series_{series_idx:03d}"
                series_dir.mkdir(parents=True, exist_ok=True)
                for ds_idx, ds in enumerate(datasets):
                    ds.save_as(str(series_dir / f"slice_{ds_idx:04d}.dcm"))

            log(
                f"[{test_id}/{args.count}] Testing "
                f"{strategy.value}/{severity} (mutations: {len(records)})",
                log_file,
            )

            # Test with target
            result = harness.test_study_directory(
                output_study,
                viewer_adapter=viewer_adapter,
                series_name=args.series_name,
            )

            # Process result and check if we should stop
            return _process_test_result(
                result=result,
                stats=stats,
                test_id=test_id,
                output_study=output_study,
                records=records,
                harness=harness,
                viewer_adapter=viewer_adapter,
                args=args,
                log_file=log_file,
            )

        except Exception as e:
            log(f"  [-] Error: {e}", log_file)
            stats["error"] += 1
            if args.verbose:
                traceback.print_exc()
            return False


def run_campaign(args: argparse.Namespace) -> int:
    """Execute the study-level fuzzing campaign."""
    # Validate arguments
    paths = _validate_campaign_args(args)
    if paths is None:
        return 1
    target_path, study_path, output_path = paths

    # Create output directories
    crashes_dir, log_file = _setup_campaign_dirs(output_path)

    # Print header
    _log_campaign_header(target_path, study_path, output_path, args, log_file)

    try:
        from dicom_fuzzer.core.harness.target_harness import TargetConfig, TargetHarness
        from dicom_fuzzer.attacks.series.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        # Setup target harness
        config = TargetConfig(
            executable=target_path,
            timeout_seconds=args.timeout,
            startup_delay_seconds=args.startup_delay,
            memory_limit_mb=args.memory_limit,
        )
        harness = TargetHarness(config, crash_dir=crashes_dir, log_file=log_file)

        # Map CLI strategy to enum
        strategy_map = {
            "cross-series": StudyMutationStrategy.CROSS_SERIES_REFERENCE,
            "frame-of-reference": StudyMutationStrategy.FRAME_OF_REFERENCE,
            "patient-consistency": StudyMutationStrategy.PATIENT_CONSISTENCY,
            "study-metadata": StudyMutationStrategy.STUDY_METADATA,
            "mixed-modality": StudyMutationStrategy.MIXED_MODALITY_STUDY,
        }

        strategies = _get_strategies(args.strategy, strategy_map)
        severities = _get_severities(args.severity)

        # Statistics
        stats = {
            "total": 0,
            "success": 0,
            "crash": 0,
            "memory_exceeded": 0,
            "render_failed": 0,
            "error": 0,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
        }

        # Setup viewer adapter if specified
        viewer_adapter, error_code = _setup_viewer_adapter(args.adapter, log_file)
        if error_code is not None:
            return error_code

        # Load source study
        log("[i] Loading source study...", log_file)
        mutator = StudyMutator(severity=args.severity)
        source_study = mutator.load_study(study_path)
        log(
            f"[+] Loaded study with {len(source_study.series_list)} series, "
            f"{source_study.get_total_slices()} slices",
            log_file,
        )

        start_campaign = time.time()
        _run_campaign_loop(
            args=args,
            study_path=study_path,
            severities=severities,
            strategies=strategies,
            harness=harness,
            viewer_adapter=viewer_adapter,
            stats=stats,
            log_file=log_file,
            start_campaign=start_campaign,
        )

        # Final summary
        elapsed_total = time.time() - start_campaign
        stats["end_time"] = datetime.now().isoformat()
        _log_campaign_summary(stats, elapsed_total, log_file)
        _save_campaign_results(
            output_path, target_path, study_path, args, stats, log_file
        )

        # Return non-zero if crashes found
        return 1 if stats["crash"] > 0 else 0

    except ImportError as e:
        log(f"[-] Module not available: {e}", log_file)
        log("[i] Ensure required modules are installed", log_file)
        return 1
    except Exception as e:
        log(f"[-] Campaign failed: {e}", log_file)
        if args.verbose:
            traceback.print_exc()
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for study-campaign subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.list_strategies:
        return run_list_strategies()
    elif args.list_adapters:
        return run_list_adapters()
    elif args.target:
        return run_campaign(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
