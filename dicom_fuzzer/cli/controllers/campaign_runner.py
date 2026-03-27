"""Campaign Runner for DICOM Fuzzer CLI.

Handles file generation and campaign orchestration.
"""

from __future__ import annotations

import json
import logging
import time
from argparse import Namespace
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from dicom_fuzzer.cli.utils import output as cli
from dicom_fuzzer.core.engine import DICOMGenerator
from dicom_fuzzer.utils.logger import suppress_console

logger = logging.getLogger(__name__)

# Check for tqdm availability
try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    tqdm = None  # type: ignore[misc,assignment,unused-ignore]


class CampaignRunner:
    """Runs file generation campaigns for fuzzing."""

    def __init__(
        self,
        args: Namespace,
        input_files: list[Path],
        selected_strategies: list[str] | None = None,
    ):
        """Initialize the campaign runner.

        Args:
            args: Parsed command-line arguments
            input_files: List of input DICOM files
            selected_strategies: List of strategy names to use

        """
        self.args = args
        self.input_files = input_files
        self.selected_strategies = selected_strategies
        self.is_directory_input = len(input_files) > 1
        self.seed: int | None = getattr(args, "seed", None)

        # Calculate number of files to generate per input
        _count = getattr(args, "count", None)
        _num_mutations = getattr(args, "num_mutations", None)
        self.num_files_per_input: int = (
            _count
            if _count is not None
            else (_num_mutations if _num_mutations is not None else 100)
        )

    def display_header(self) -> None:
        """Display campaign header information."""
        recursive = getattr(self.args, "recursive", False)

        cli.header("DICOM Fuzzer - Fuzzing Campaign", "v1.6.0")
        if self.is_directory_input:
            cli.detail(
                "Input", f"{self.args.input_file} ({len(self.input_files)} files)"
            )
            if recursive:
                cli.detail("Mode", "Recursive directory scan")
            cli.detail("Per-file", f"{self.num_files_per_input} mutations each")
            total_expected = self.num_files_per_input * len(self.input_files)
            cli.detail("Total", f"~{total_expected} files (max)")
        else:
            cli.detail("Input", str(self.input_files[0].name))
            cli.detail("Target", f"{self.num_files_per_input} files")
        cli.detail("Output", str(self.args.output))
        if self.selected_strategies:
            cli.detail("Strategies", ", ".join(self.selected_strategies))
        else:
            cli.detail("Strategies", "all (metadata, header, pixel)")
        cli.divider()

    def generate_files(self) -> tuple[list[Path], dict[str, Any]]:
        """Generate fuzzed files.

        Returns:
            Tuple of (list of generated file paths, results dictionary)

        """
        total_expected = self.num_files_per_input * len(self.input_files)
        logger.info("Generating up to %d fuzzed files...", total_expected)
        start_time = time.time()

        generator = DICOMGenerator(
            self.args.output, skip_write_errors=True, seed=self.seed
        )
        self.seed = generator.seed  # capture auto-generated seed if not provided
        files: list[Path] = []

        # Process each input file
        if self.is_directory_input:
            files = self._generate_from_directory(generator)
        else:
            files = self._generate_from_single_file(generator)

        elapsed_time = time.time() - start_time
        results_data = self._collect_stats(generator, files, elapsed_time)

        # Persist mutation map so target testing can link crashes to strategies
        self._save_mutation_map(generator)

        self._save_session_json(results_data)
        self._log_strategy_table(results_data)

        return files, results_data

    def _generate_from_directory(self, generator: DICOMGenerator) -> list[Path]:
        """Generate fuzzed files from directory input.

        Args:
            generator: The DICOM generator instance

        Returns:
            List of generated file paths

        """
        files: list[Path] = []
        print(f"Processing {len(self.input_files)} input files...")

        input_iterator: Iterable[Path]
        if HAS_TQDM and not self.args.verbose:
            from tqdm import tqdm as tqdm_iter

            input_iterator = tqdm_iter(
                self.input_files,
                desc="Input files",
                unit="file",
                ncols=70,
            )
        else:
            input_iterator = self.input_files

        for input_file in input_iterator:
            try:
                batch_files = generator.generate_batch(
                    str(input_file),
                    count=self.num_files_per_input,
                    strategies=self.selected_strategies,
                )
                files.extend(batch_files)
            except Exception as e:
                logger.warning("Failed to process %s: %s", input_file, e)
                if self.args.verbose:
                    print(f"  [!] Skipping {input_file.name}: {e}")

        return files

    def _generate_from_single_file(self, generator: DICOMGenerator) -> list[Path]:
        """Generate fuzzed files from single input file.

        In verbose mode, generates one file at a time and prints a clean
        per-file line with the strategy name. Otherwise uses tqdm progress bar.

        Args:
            generator: The DICOM generator instance

        Returns:
            List of generated file paths

        """
        input_path = self.input_files[0]

        if self.args.verbose:
            return self._generate_verbose(generator, input_path)

        # Suppress console logging during generation so structlog messages
        # don't interleave with the tqdm progress bar. The file handler
        # still captures everything at DEBUG level.
        with suppress_console():
            if HAS_TQDM and self.num_files_per_input >= 20:
                print("Generating fuzzed files...")
                with tqdm(
                    total=self.num_files_per_input, unit="file", ncols=70
                ) as pbar:
                    batch_size = max(1, self.num_files_per_input // 20)
                    remaining = self.num_files_per_input
                    all_files: list[Path] = []

                    while remaining > 0:
                        current_batch = min(batch_size, remaining)
                        batch_files = generator.generate_batch(
                            str(input_path),
                            count=current_batch,
                            strategies=self.selected_strategies,
                        )
                        all_files.extend(batch_files)
                        pbar.update(len(batch_files))
                        remaining -= current_batch

                    return all_files

            return generator.generate_batch(
                str(input_path),
                count=self.num_files_per_input,
                strategies=self.selected_strategies,
            )

    def _generate_verbose(
        self, generator: DICOMGenerator, input_path: Path
    ) -> list[Path]:
        """Generate files one at a time with per-file console output.

        Prints a clean one-liner per file:
            [1/500] fuzzed_abc123.dcm <- encoding

        """
        all_files: list[Path] = []
        total = self.num_files_per_input

        with suppress_console():
            for i in range(total):
                batch = generator.generate_batch(
                    str(input_path),
                    count=1,
                    strategies=self.selected_strategies,
                )
                if batch:
                    generated = batch[0]
                    strategy = self._get_last_strategy(generator)
                    print(f"  [{i + 1}/{total}] {generated.name} <- {strategy}")
                    all_files.extend(batch)
                else:
                    print(f"  [{i + 1}/{total}] (skipped)")

        return all_files

    @staticmethod
    def _get_last_strategy(generator: DICOMGenerator) -> str:
        """Extract the strategy name from the most recent mutation."""
        session = generator.mutator.current_session
        if session and session.mutations:
            last = session.mutations[-1]
            if last.success:
                return last.strategy_name
        return "unknown"

    def _save_mutation_map(self, generator: DICOMGenerator) -> None:
        """Persist filename->strategy/variant mapping so crash reports include mutation info."""
        strategy_map = generator.file_strategy_map
        if not strategy_map:
            return
        variant_map = generator.file_variant_map
        binary_map = generator.file_binary_mutations_map
        output_dir = Path(self.args.output)
        map_path = output_dir / "mutation_map.json"
        try:
            combined = {
                filename: {
                    "strategy": strategy,
                    "variant": variant_map.get(filename),
                    "binary_mutations": binary_map.get(filename, []),
                }
                for filename, strategy in strategy_map.items()
            }
            output = {"seed": self.seed, "mutations": combined}
            with open(map_path, "w") as f:
                json.dump(output, f, indent=2)
            logger.debug("Mutation map saved: %s (%d entries)", map_path, len(combined))
        except Exception as e:
            logger.warning("Failed to save mutation map: %s", e)

    def _collect_stats(
        self,
        generator: DICOMGenerator,
        files: list[Path],
        elapsed_time: float,
    ) -> dict[str, Any]:
        """Collect statistics from generation run.

        Args:
            generator: The DICOM generator instance
            files: List of generated files
            elapsed_time: Time taken for generation

        Returns:
            Dictionary of statistics

        """
        skipped = (
            getattr(generator.stats, "skipped_due_to_write_errors", 0)
            if hasattr(generator, "stats")
            else 0
        )
        files_per_sec = len(files) / elapsed_time if elapsed_time > 0 else 0

        results_data: dict[str, Any] = {
            "status": "success",
            "seed": getattr(self, "seed", None),
            "generated_count": len(files),
            "skipped_count": skipped,
            "duration_seconds": round(elapsed_time, 2),
            "files_per_second": round(files_per_sec, 1),
            "output_directory": str(self.args.output),
            "files": [str(f) for f in files[:100]],  # Limit to 100 in JSON
        }

        # Add cumulative strategy usage across all batches
        if (
            hasattr(generator, "cumulative_strategies")
            and generator.cumulative_strategies
        ):
            results_data["strategies_used"] = generator.cumulative_strategies

        # Compute per-strategy hit rates against total generated files
        total_generated = len(files)
        known = generator.known_strategy_names
        if known and total_generated > 0:
            hit_rates: dict[str, dict[str, Any]] = {}
            for name in known:
                hits = generator.cumulative_strategies.get(name, 0)
                hit_rates[name] = {
                    "hits": hits,
                    "hit_rate_pct": round(hits / total_generated * 100, 1),
                }
            results_data["strategy_hit_rates"] = hit_rates

        return results_data

    def _save_session_json(self, results_data: dict[str, Any]) -> None:
        """Persist results_data to <run_dir>/reports/json/session.json."""
        run_dir = Path(self.args.output).parent
        reports_dir = run_dir / "reports" / "json"
        reports_dir.mkdir(parents=True, exist_ok=True)
        session_path = reports_dir / "session.json"
        try:
            with open(session_path, "w") as f:
                json.dump(results_data, f, indent=2)
            logger.debug("Session JSON saved: %s", session_path)
        except Exception as e:
            logger.warning("Failed to save session JSON: %s", e)

    def _log_strategy_table(self, results_data: dict[str, Any]) -> None:
        """Log strategy hit-rate table; emit WARNING for zero-hit strategies."""
        hit_rates = results_data.get("strategy_hit_rates")
        if not hit_rates:
            return
        logger.info("Strategy hit rates:")
        logger.info("  %-35s %6s %9s", "strategy", "hits", "hit_rate%")
        logger.info("  %s", "-" * 55)
        for name, data in sorted(hit_rates.items()):
            hits = data["hits"]
            rate = data["hit_rate_pct"]
            logger.info("  %-35s %6d %8.1f%%", name, hits, rate)
            if hits == 0:
                logger.warning("Zero-hit strategy: %s", name)

    def display_results(
        self,
        files: list[Path],
        results_data: dict[str, Any],
        json_mode: bool = False,
        quiet_mode: bool = False,
    ) -> None:
        """Display campaign results.

        Args:
            files: List of generated files
            results_data: Statistics dictionary
            json_mode: Whether to output JSON
            quiet_mode: Whether to suppress output

        """
        if json_mode:
            print(json.dumps(results_data, indent=2))
        elif not quiet_mode:
            elapsed_time = results_data["duration_seconds"]
            files_per_sec = results_data["files_per_second"]
            skipped = results_data["skipped_count"]

            # Display results with colored output
            cli.section("Campaign Results")
            stats = {
                "Successfully generated": f"{len(files)} files",
                "Skipped": skipped,
                "Duration": f"{elapsed_time:.2f}s ({files_per_sec:.1f} files/sec)",
                "Output": str(self.args.output),
                "Seed": str(results_data.get("seed", "n/a")),
            }

            if "strategies_used" in results_data:
                strat_used = results_data["strategies_used"]
                if isinstance(strat_used, dict):
                    stats["Strategies"] = ", ".join(
                        f"{s}({c})" for s, c in sorted(strat_used.items())
                    )

            cli.print_summary(
                "Fuzzing Complete",
                stats,
                success_count=len(files),
                error_count=skipped,
            )

            if self.args.verbose:
                cli.info("Sample generated files:")
                for f in files[:10]:
                    cli.status(f"  - {f.name}")
                if len(files) > 10:
                    cli.status(f"  ... and {len(files) - 10} more")
