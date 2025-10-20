#!/usr/bin/env python3
"""
Coverage-Guided Fuzzing CLI for DICOM-Fuzzer

Command-line interface for running coverage-guided fuzzing campaigns
against DICOM parsers and applications.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.core.coverage_guided_fuzzer import CoverageGuidedFuzzer, FuzzingConfig
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel


console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Coverage-guided fuzzing for DICOM files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz with default settings
  python coverage_fuzz.py

  # Fuzz a specific target with seeds
  python coverage_fuzz.py --seeds ./samples --target /path/to/parser

  # Parallel fuzzing with 4 workers
  python coverage_fuzz.py --workers 4 --iterations 10000

  # DICOM-aware fuzzing with adaptive mutations
  python coverage_fuzz.py --dicom-aware --adaptive
        """,
    )

    # Target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument(
        "--target", type=str, help="Path to target binary or Python module"
    )
    target_group.add_argument(
        "--target-args", type=str, help="Arguments to pass to target binary"
    )
    target_group.add_argument(
        "--modules", type=str, nargs="+", help="Python modules to track coverage for"
    )

    # Fuzzing options
    fuzz_group = parser.add_argument_group("Fuzzing Options")
    fuzz_group.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=10000,
        help="Maximum number of fuzzing iterations (default: 10000)",
    )
    fuzz_group.add_argument(
        "-w",
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1)",
    )
    fuzz_group.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout per execution in seconds (default: 1.0)",
    )
    fuzz_group.add_argument(
        "--max-mutations",
        type=int,
        default=10,
        help="Maximum mutations per seed (default: 10)",
    )

    # Corpus options
    corpus_group = parser.add_argument_group("Corpus Options")
    corpus_group.add_argument(
        "-s", "--seeds", type=Path, help="Directory containing seed DICOM files"
    )
    corpus_group.add_argument(
        "-c",
        "--corpus",
        type=Path,
        help="Corpus directory for saving/loading test cases",
    )
    corpus_group.add_argument(
        "--max-corpus-size",
        type=int,
        default=1000,
        help="Maximum corpus size (default: 1000)",
    )
    corpus_group.add_argument(
        "--minimize",
        action="store_true",
        help="Minimize corpus to remove redundant seeds",
    )

    # Coverage options
    coverage_group = parser.add_argument_group("Coverage Options")
    coverage_group.add_argument(
        "--no-coverage", action="store_true", help="Disable coverage-guided fuzzing"
    )
    coverage_group.add_argument(
        "--branches",
        action="store_true",
        default=True,
        help="Track branch coverage (default: True)",
    )

    # Mutation options
    mutation_group = parser.add_argument_group("Mutation Options")
    mutation_group.add_argument(
        "--adaptive",
        action="store_true",
        default=True,
        help="Enable adaptive mutation strategies (default: True)",
    )
    mutation_group.add_argument(
        "--dicom-aware",
        action="store_true",
        default=True,
        help="Enable DICOM-specific mutations (default: True)",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("fuzzing_output"),
        help="Output directory (default: fuzzing_output)",
    )
    output_group.add_argument(
        "--crashes",
        type=Path,
        default=Path("crashes"),
        help="Directory for saving crashes (default: crashes)",
    )
    output_group.add_argument(
        "--save-all", action="store_true", help="Save all generated inputs"
    )
    output_group.add_argument(
        "--report-interval",
        type=int,
        default=100,
        help="Report progress every N executions (default: 100)",
    )

    # Other options
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("--config", type=Path, help="Load configuration from JSON file")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show configuration without running"
    )

    return parser


def create_status_table(stats: dict) -> Table:
    """Create a status table for live display."""
    table = Table(title="Fuzzing Status", expand=True)

    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    # Add rows
    table.add_row("Executions", f"{stats.get('total_executions', 0):,}")
    table.add_row("Exec/sec", f"{stats.get('exec_per_sec', 0):.1f}")
    table.add_row("Coverage", f"{stats.get('current_coverage', 0):,} edges")
    table.add_row("Corpus Size", f"{stats.get('corpus_size', 0):,}")
    table.add_row(
        "Crashes",
        f"{stats.get('total_crashes', 0)} ({stats.get('unique_crashes', 0)} unique)",
    )
    table.add_row("Coverage Increases", f"{stats.get('coverage_increases', 0)}")

    return table


def create_mutation_table(mutation_stats: dict) -> Table:
    """Create mutation statistics table."""
    table = Table(title="Mutation Statistics", expand=True)

    table.add_column("Strategy", style="cyan")
    table.add_column("Success Rate", style="green")
    table.add_column("Count", style="yellow")
    table.add_column("Weight", style="magenta")

    # Sort by success rate
    sorted_stats = sorted(
        mutation_stats.items(), key=lambda x: x[1].get("success_rate", 0), reverse=True
    )

    for strategy, stats in sorted_stats[:10]:  # Top 10
        table.add_row(
            strategy,
            f"{stats.get('success_rate', 0):.2%}",
            f"{stats.get('total_count', 0):,}",
            f"{stats.get('weight', 1.0):.2f}",
        )

    return table


async def run_fuzzing_campaign(config: FuzzingConfig) -> None:
    """Run the fuzzing campaign with live updates."""
    fuzzer = CoverageGuidedFuzzer(config)

    console.print(
        Panel.fit(
            "[bold green]Starting Coverage-Guided Fuzzing Campaign[/bold green]\n"
            f"Target: {config.target_binary or config.target_function or 'DICOM Parser'}\n"
            f"Workers: {config.num_workers}\n"
            f"Max Iterations: {config.max_iterations:,}",
            title="DICOM Fuzzer",
        )
    )

    # Run with live display
    with Live(create_status_table({}), refresh_per_second=2, console=console) as live:
        # Start fuzzing in background
        fuzzing_task = asyncio.create_task(fuzzer.run())

        # Update display
        while not fuzzing_task.done():
            await asyncio.sleep(0.5)

            # Get current stats
            stats_dict = {
                "total_executions": fuzzer.stats.total_executions,
                "exec_per_sec": fuzzer.stats.exec_per_sec,
                "current_coverage": fuzzer.stats.current_coverage,
                "corpus_size": fuzzer.stats.corpus_size,
                "total_crashes": fuzzer.stats.total_crashes,
                "unique_crashes": fuzzer.stats.unique_crashes,
                "coverage_increases": fuzzer.stats.coverage_increases,
            }

            # Update table
            live.update(create_status_table(stats_dict))

        # Get final stats
        final_stats = await fuzzing_task

    # Display final results
    console.print("\n[bold green]Fuzzing Campaign Complete![/bold green]\n")

    # Show mutation statistics
    if final_stats.mutation_stats:
        console.print(create_mutation_table(final_stats.mutation_stats))

    # Summary
    console.print(
        Panel(
            f"[bold]Final Statistics:[/bold]\n"
            f"Total Executions: {final_stats.total_executions:,}\n"
            f"Unique Crashes: {final_stats.unique_crashes}\n"
            f"Maximum Coverage: {final_stats.max_coverage} edges\n"
            f"Final Corpus Size: {final_stats.corpus_size}\n"
            f"Average Exec/sec: {final_stats.exec_per_sec:.1f}",
            title="Summary",
        )
    )


def load_config_from_file(config_path: Path) -> FuzzingConfig:
    """Load configuration from JSON file."""
    with open(config_path, "r") as f:
        config_dict = json.load(f)

    # Convert paths
    for key in ["corpus_dir", "seed_dir", "output_dir", "crash_dir"]:
        if key in config_dict and config_dict[key]:
            config_dict[key] = Path(config_dict[key])

    return FuzzingConfig(**config_dict)


def create_config_from_args(args: argparse.Namespace) -> FuzzingConfig:
    """Create fuzzing configuration from command-line arguments."""
    config = FuzzingConfig()

    # Target configuration
    if args.target:
        if args.target.endswith(".py"):
            # Python module
            import importlib.util

            spec = importlib.util.spec_from_file_location("target", args.target)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            config.target_function = getattr(module, "fuzz_target", None)
        else:
            config.target_binary = args.target

    config.target_modules = args.modules or []

    # Fuzzing parameters
    config.max_iterations = args.iterations
    config.num_workers = args.workers
    config.timeout_per_run = args.timeout
    config.max_mutations = args.max_mutations

    # Coverage parameters
    config.coverage_guided = not args.no_coverage
    config.track_branches = args.branches
    config.minimize_corpus = args.minimize

    # Corpus parameters
    config.corpus_dir = args.corpus
    config.seed_dir = args.seeds
    config.max_corpus_size = args.max_corpus_size

    # Mutation parameters
    config.adaptive_mutations = args.adaptive
    config.dicom_aware = args.dicom_aware

    # Output configuration
    config.output_dir = args.output
    config.crash_dir = args.crashes
    config.save_all_inputs = args.save_all
    config.report_interval = args.report_interval

    # Other
    config.verbose = args.verbose

    return config


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Load configuration
    if args.config:
        config = load_config_from_file(args.config)
    else:
        config = create_config_from_args(args)

    # Dry run - show configuration
    if args.dry_run:
        console.print(
            Panel(
                json.dumps(
                    {
                        "max_iterations": config.max_iterations,
                        "num_workers": config.num_workers,
                        "timeout_per_run": config.timeout_per_run,
                        "coverage_guided": config.coverage_guided,
                        "adaptive_mutations": config.adaptive_mutations,
                        "dicom_aware": config.dicom_aware,
                        "corpus_dir": str(config.corpus_dir)
                        if config.corpus_dir
                        else None,
                        "seed_dir": str(config.seed_dir) if config.seed_dir else None,
                        "output_dir": str(config.output_dir),
                    },
                    indent=2,
                ),
                title="Fuzzing Configuration",
            )
        )
        return

    # Run fuzzing campaign
    try:
        asyncio.run(run_fuzzing_campaign(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
