#!/usr/bin/env python3
"""
Production Fuzzing Example: DCMTK dcmdump

This example demonstrates a complete end-to-end fuzzing workflow against
the DCMTK dcmdump parser using real DICOM files and production-grade configurations.

WORKFLOW:
  1. Download/import seed corpus
  2. Generate fuzzed DICOM files with mutations
  3. Execute dcmdump against each fuzzed file
  4. Detect crashes and analyze failures
  5. Generate comprehensive HTML/JSON reports

PREREQUISITES:
  - DCMTK installed (`dcmdump` in PATH) OR Docker with dicom-fuzzer/dcmtk image
  - Seed corpus (use scripts/download_public_seeds.py to get started)

USAGE:
  # Quick start with generated seeds
  python examples/production_fuzzing/fuzz_dcmtk.py --quick-start

  # Full fuzzing campaign with custom seeds
  python examples/production_fuzzing/fuzz_dcmtk.py --seeds ./my_seeds --iterations 1000

  # Docker mode (isolated execution)
  python examples/production_fuzzing/fuzz_dcmtk.py --docker --iterations 500

  # Resume interrupted campaign
  python examples/production_fuzzing/fuzz_dcmtk.py --resume ./reports/session_12345
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity
from dicom_fuzzer.core.target_runner import TargetConfig, TargetRunner
from dicom_fuzzer.utils.identifiers import generate_timestamp_id

try:
    import pydicom
except ImportError:
    print("[!] Error: pydicom not installed. Run: pip install pydicom")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class DCMTKFuzzer:
    """Production fuzzer for DCMTK dcmdump."""

    def __init__(
        self,
        target_path: str = "dcmdump",
        use_docker: bool = False,
        output_dir: Path = Path("./artifacts/fuzzed"),
        strip_pixels: bool = True,
    ):
        """
        Initialize DCMTK fuzzer.

        Args:
            target_path: Path to dcmdump executable
            use_docker: Use Docker container instead of local executable
            output_dir: Directory for fuzzing outputs
            strip_pixels: Remove PixelData to focus on parser fuzzing
        """
        self.target_path = target_path
        self.use_docker = use_docker
        self.output_dir = Path(output_dir)
        self.strip_pixels = strip_pixels

        # Create output directories
        self.fuzzed_dir = self.output_dir / "fuzzed"
        self.crashes_dir = self.output_dir / "crashes"
        self.reports_dir = self.output_dir / "reports"

        for directory in [self.fuzzed_dir, self.crashes_dir, self.reports_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Initialize fuzzing session
        self.session = FuzzingSession()

        # Initialize mutator
        self.mutator = DicomMutator()

        # Initialize target runner
        target_config = self._create_target_config()
        self.runner = TargetRunner(target_config)

    def _create_target_config(self) -> TargetConfig:
        """Create target configuration for dcmdump."""
        if self.use_docker:
            return TargetConfig(
                name="dcmtk_dcmdump_docker",
                executable="docker",
                args=[
                    "run",
                    "--rm",
                    "-v",
                    f"{self.fuzzed_dir.absolute()}:/input",
                    "dicom-fuzzer/dcmtk",
                    "fuzz-dcmdump",
                    "/input/{input_file}",
                ],
                timeout=10.0,
                memory_limit_mb=512,
                cpu_limit_percent=100,
            )
        else:
            return TargetConfig(
                name="dcmtk_dcmdump",
                executable=self.target_path,
                args=["{input_file}"],
                timeout=10.0,
                memory_limit_mb=512,
            )

    def generate_fuzzed_files(self, seed_dir: Path, count: int) -> list:
        """
        Generate fuzzed DICOM files from seeds.

        Args:
            seed_dir: Directory containing seed DICOM files
            count: Number of fuzzed files to generate

        Returns:
            List of paths to fuzzed files
        """
        logger.info(f"Generating {count} fuzzed files from seeds in {seed_dir}")

        seed_files = list(seed_dir.glob("*.dcm"))
        if not seed_files:
            raise ValueError(f"No seed files found in {seed_dir}")

        logger.info(f"Found {len(seed_files)} seed files")

        fuzzed_files = []
        for i in range(count):
            # Select seed (round-robin)
            seed_file = seed_files[i % len(seed_files)]

            try:
                # Load seed
                dataset = pydicom.dcmread(seed_file, force=True)

                # Optionally strip PixelData
                if self.strip_pixels and hasattr(dataset, "PixelData"):
                    del dataset.PixelData
                    logger.debug(f"Stripped PixelData from {seed_file.name}")

                # Apply mutations
                mutated = self.mutator.apply_mutations(
                    dataset, num_mutations=3, severity=MutationSeverity.MODERATE
                )

                # Save fuzzed file
                fuzzed_path = self.fuzzed_dir / f"fuzzed_{i:05d}.dcm"
                mutated.save_as(fuzzed_path, write_like_original=False)

                fuzzed_files.append(fuzzed_path)

                if (i + 1) % 100 == 0:
                    logger.info(f"  Generated {i + 1}/{count} files...")

            except Exception as e:
                logger.error(f"Failed to fuzz {seed_file}: {e}")
                continue

        logger.info(f"Generated {len(fuzzed_files)} fuzzed files")
        return fuzzed_files

    def run_fuzzing_campaign(
        self, fuzzed_files: list, stop_on_crash: bool = False
    ) -> dict:
        """
        Execute fuzzing campaign against dcmdump.

        Args:
            fuzzed_files: List of fuzzed file paths
            stop_on_crash: Stop campaign on first crash

        Returns:
            Campaign statistics
        """
        logger.info(f"Starting fuzzing campaign: {len(fuzzed_files)} test cases")

        stats = {
            "total": len(fuzzed_files),
            "passed": 0,
            "crashed": 0,
            "hanged": 0,
            "errors": 0,
            "crashes": [],
        }

        for idx, fuzzed_file in enumerate(fuzzed_files, 1):
            # Execute test
            result = self.runner.execute_test(fuzzed_file)

            # Record in session
            self.session.record_test_result(result)

            # Update statistics
            if result.classification == "PASS":
                stats["passed"] += 1
            elif result.classification == "CRASH":
                stats["crashed"] += 1
                stats["crashes"].append(
                    {
                        "file": str(fuzzed_file),
                        "exit_code": result.exit_code,
                        "stderr": result.stderr[:500],  # First 500 chars
                    }
                )

                # Save crash sample
                crash_sample = self.crashes_dir / f"crash_{stats['crashed']:04d}.dcm"
                crash_sample.write_bytes(fuzzed_file.read_bytes())

                logger.warning(
                    f"  [CRASH] Test {idx}: {fuzzed_file.name} (exit code: {result.exit_code})"
                )

                if stop_on_crash:
                    logger.info("Stopping campaign on first crash (--stop-on-crash)")
                    break

            elif result.classification == "HANG":
                stats["hanged"] += 1
                logger.warning(f"  [HANG] Test {idx}: {fuzzed_file.name}")
            else:
                stats["errors"] += 1

            # Progress update
            if idx % 100 == 0:
                logger.info(
                    f"  Progress: {idx}/{len(fuzzed_files)} "
                    f"(Crashes: {stats['crashed']}, Hangs: {stats['hanged']})"
                )

        return stats

    def generate_report(self) -> Path:
        """
        Generate comprehensive fuzzing report.

        Returns:
            Path to HTML report
        """
        logger.info("Generating fuzzing report...")

        reporter = EnhancedReportGenerator()

        # Generate reports
        html_path = self.reports_dir / f"fuzzing_report_{generate_timestamp_id()}.html"
        json_path = html_path.with_suffix(".json")

        # HTML report
        reporter.generate_html_report(session=self.session, output_path=html_path)

        # JSON report
        json_data = reporter.generate_json_report(self.session)
        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2)

        logger.info("Reports generated:")
        logger.info(f"  HTML: {html_path}")
        logger.info(f"  JSON: {json_path}")

        return html_path


def main():
    parser = argparse.ArgumentParser(
        description="Production fuzzing for DCMTK dcmdump",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--seeds", type=Path, help="Directory containing seed DICOM files"
    )
    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=100,
        help="Number of fuzzed files to generate (default: 100)",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="dcmdump",
        help="Path to dcmdump executable (default: dcmdump in PATH)",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Use Docker container instead of local executable",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./artifacts/fuzzed"),
        help="Output directory (default: ./artifacts/fuzzed)",
    )
    parser.add_argument(
        "--keep-pixels",
        action="store_true",
        help="Keep PixelData in fuzzed files (default: strip for parser focus)",
    )
    parser.add_argument(
        "--stop-on-crash", action="store_true", help="Stop fuzzing on first crash"
    )
    parser.add_argument(
        "--quick-start",
        action="store_true",
        help="Download seeds and run quick fuzzing campaign",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Quick start mode: download seeds automatically
        if args.quick_start:
            logger.info("Quick start mode: downloading public seeds...")
            import subprocess

            subprocess.run(
                [
                    sys.executable,
                    "scripts/download_public_seeds.py",
                    "--source",
                    "generated",
                    "--count",
                    "20",
                    "--output",
                    "./seeds",
                ],
                check=True,
            )
            args.seeds = Path("./seeds")

        # Validate seeds directory
        if not args.seeds:
            logger.error("No seed directory specified. Use --seeds or --quick-start")
            sys.exit(1)

        if not args.seeds.exists():
            logger.error(f"Seed directory does not exist: {args.seeds}")
            sys.exit(1)

        # Initialize fuzzer
        fuzzer = DCMTKFuzzer(
            target_path=args.target,
            use_docker=args.docker,
            output_dir=args.output,
            strip_pixels=not args.keep_pixels,
        )

        # Start fuzzing session
        fuzzer.session.start_session(
            config={
                "target": args.target,
                "docker": args.docker,
                "iterations": args.iterations,
                "strip_pixels": not args.keep_pixels,
            }
        )

        # Generate fuzzed files
        fuzzed_files = fuzzer.generate_fuzzed_files(
            seed_dir=args.seeds, count=args.iterations
        )

        # Run fuzzing campaign
        stats = fuzzer.run_fuzzing_campaign(
            fuzzed_files=fuzzed_files, stop_on_crash=args.stop_on_crash
        )

        # End session
        fuzzer.session.end_session()

        # Generate report
        report_path = fuzzer.generate_report()

        # Print summary
        print("\n" + "=" * 80)
        print("FUZZING CAMPAIGN SUMMARY")
        print("=" * 80)
        print(f"Total Tests:    {stats['total']}")
        print(f"Passed:         {stats['passed']}")
        print(f"Crashed:        {stats['crashed']}")
        print(f"Hanged:         {stats['hanged']}")
        print(f"Errors:         {stats['errors']}")
        print()
        print(f"Report: {report_path}")
        print(f"Crashes: {fuzzer.crashes_dir}")
        print("=" * 80)

        # Exit with appropriate code
        if stats["crashed"] > 0:
            logger.info(f"Fuzzing found {stats['crashed']} crashes!")
            sys.exit(0)
        else:
            logger.info("Fuzzing completed with no crashes found")
            sys.exit(0)

    except KeyboardInterrupt:
        logger.warning("\nFuzzing interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(
            f"Fuzzing failed: {e}",
            exc_info=args.verbose if "args" in locals() else False,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
