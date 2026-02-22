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

        generator = DICOMGenerator(self.args.output, skip_write_errors=True)
        files: list[Path] = []

        # Process each input file
        if self.is_directory_input:
            files = self._generate_from_directory(generator)
        else:
            files = self._generate_from_single_file(generator)

        elapsed_time = time.time() - start_time
        results_data = self._collect_stats(generator, files, elapsed_time)

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

        Args:
            generator: The DICOM generator instance

        Returns:
            List of generated file paths

        """
        input_path = self.input_files[0]

        if HAS_TQDM and not self.args.verbose and self.num_files_per_input >= 20:
            print("Generating fuzzed files...")
            with tqdm(total=self.num_files_per_input, unit="file", ncols=70) as pbar:
                # Generate in smaller batches to update progress
                batch_size = max(1, self.num_files_per_input // 20)  # 20 updates
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
        else:
            # No progress bar or small file count, generate all at once
            return generator.generate_batch(
                str(input_path),
                count=self.num_files_per_input,
                strategies=self.selected_strategies,
            )

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
            "generated_count": len(files),
            "skipped_count": skipped,
            "duration_seconds": round(elapsed_time, 2),
            "files_per_second": round(files_per_sec, 1),
            "output_directory": str(self.args.output),
            "files": [str(f) for f in files[:100]],  # Limit to 100 in JSON
        }

        # Add strategy usage if available
        if hasattr(generator, "stats") and hasattr(generator.stats, "strategies_used"):
            strategies_used = generator.stats.strategies_used
            if isinstance(strategies_used, dict) and strategies_used:
                results_data["strategies_used"] = strategies_used

        return results_data

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
