#!/usr/bin/env python3
"""
Fuzz DICOM Viewer Applications

This script fuzzes DICOM viewer applications (like Hermes.exe) by:
1. Loading real DICOM files from a local directory
2. Applying intelligent mutations using dictionary-based fuzzing
3. Saving mutated files to an output directory
4. Optionally launching the viewer with each mutated file
5. Monitoring for crashes and unexpected behavior

SECURITY: This script is for DEFENSIVE security testing only.
Use only on systems you own or have explicit permission to test.

Example usage:
    # Generate fuzzed files only (no execution)
    python fuzz_dicom_viewer.py --input "C:/Data/Kiwi - Example Data - 20210423" \\
        --output "./fuzzed_output" --count 100

    # Fuzz and test viewer (automated)
    python fuzz_dicom_viewer.py --input "C:/Data/Kiwi - Example Data - 20210423" \\
        --output "./fuzzed_output" --viewer "C:/Hermes/Affinity/Hermes.exe" \\
        --count 50 --timeout 5
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import pydicom

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.generator import DICOMGenerator
from core.mutator import DicomMutator
from core.types import MutationSeverity
from core.validator import DicomValidator
from strategies.dictionary_fuzzer import DictionaryFuzzer
from utils.logger import get_logger

logger = get_logger(__name__)


class ViewerFuzzer:
    """Fuzzer for DICOM viewer applications."""

    def __init__(
        self,
        input_dir: str,
        output_dir: str,
        viewer_path: Optional[str] = None,
        timeout: int = 5,
    ):
        """
        Initialize viewer fuzzer.

        Args:
            input_dir: Directory containing real DICOM files
            output_dir: Directory to save fuzzed files
            viewer_path: Path to DICOM viewer executable (optional)
            timeout: Timeout in seconds for viewer execution
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.viewer_path = Path(viewer_path) if viewer_path else None
        self.timeout = timeout

        # Validate paths
        if not self.input_dir.exists():
            raise FileNotFoundError(f"Input directory not found: {input_dir}")

        if self.viewer_path and not self.viewer_path.exists():
            raise FileNotFoundError(f"Viewer not found: {viewer_path}")

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize fuzzing components
        self.mutator = DicomMutator({"auto_register_strategies": True})
        self.generator = DICOMGenerator()
        self.validator = DicomValidator(strict_mode=False)

        # Statistics
        self.stats = {
            "files_processed": 0,
            "files_fuzzed": 0,
            "files_generated": 0,
            "viewer_crashes": 0,
            "viewer_hangs": 0,
            "viewer_success": 0,
        }

    def find_dicom_files(self, limit: Optional[int] = None) -> List[Path]:
        """
        Find DICOM files in input directory.

        Args:
            limit: Maximum number of files to return

        Returns:
            List of DICOM file paths
        """
        logger.info(f"Searching for DICOM files in {self.input_dir}")

        dicom_files = []
        for ext in ["*.dcm", "*.DCM", "*.dicom", "*.DICOM"]:
            dicom_files.extend(self.input_dir.rglob(ext))

        if limit:
            dicom_files = dicom_files[:limit]

        logger.info(f"Found {len(dicom_files)} DICOM files")
        return dicom_files

    def generate_fuzzed_file(
        self, source_file: Path, severity: MutationSeverity
    ) -> Optional[Path]:
        """
        Generate a fuzzed DICOM file.

        Args:
            source_file: Path to source DICOM file
            severity: Mutation severity level

        Returns:
            Path to fuzzed file, or None if failed
        """
        try:
            # Parse source file using pydicom
            dataset = pydicom.dcmread(str(source_file), force=True)
            if not dataset:
                logger.warning(f"Failed to parse {source_file}")
                return None

            # Apply mutations
            self.mutator.start_session(dataset)
            mutated = self.mutator.apply_mutations(
                dataset, num_mutations=3, severity=severity
            )
            self.mutator.end_session()

            # Generate output filename
            severity_name = severity.value
            timestamp = int(time.time() * 1000)
            output_name = f"fuzzed_{severity_name}_{source_file.stem}_{timestamp}.dcm"
            output_path = self.output_dir / output_name

            # Save fuzzed file (disable validation to allow malformed data)
            try:
                pydicom.dcmwrite(str(output_path), mutated, write_like_original=False)
                self.stats["files_fuzzed"] += 1
                logger.info(f"Generated fuzzed file: {output_path}")
                return output_path
            except Exception as write_error:
                # Some mutations may be too corrupt to write - that's okay
                logger.warning(f"Could not write fuzzed file: {write_error}")
                return None

        except Exception as e:
            logger.error(f"Error fuzzing {source_file}: {e}")
            return None

    def test_viewer(self, dicom_file: Path) -> dict:
        """
        Test viewer with a DICOM file.

        Args:
            dicom_file: Path to DICOM file to test

        Returns:
            Dictionary with test results
        """
        if not self.viewer_path:
            return {"status": "skipped", "reason": "No viewer specified"}

        result = {
            "status": "unknown",
            "return_code": None,
            "crashed": False,
            "hung": False,
            "error": None,
        }

        try:
            # Launch viewer with DICOM file
            logger.info(f"Testing viewer with {dicom_file.name}")

            proc = subprocess.Popen(
                [str(self.viewer_path), str(dicom_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait with timeout
            try:
                stdout, stderr = proc.communicate(timeout=self.timeout)
                result["return_code"] = proc.returncode

                # Check for crash (non-zero exit code)
                if proc.returncode != 0:
                    result["crashed"] = True
                    result["status"] = "crashed"
                    self.stats["viewer_crashes"] += 1

                    # Log crash
                    crash_log = self.output_dir / f"crash_{dicom_file.stem}.txt"
                    with open(crash_log, "w") as f:
                        f.write(f"File: {dicom_file}\n")
                        f.write(f"Return Code: {proc.returncode}\n")
                        f.write(f"STDOUT:\n{stdout.decode(errors='ignore')}\n")
                        f.write(f"STDERR:\n{stderr.decode(errors='ignore')}\n")

                    logger.warning(f"CRASH detected: {dicom_file}")
                else:
                    result["status"] = "success"
                    self.stats["viewer_success"] += 1

            except subprocess.TimeoutExpired:
                proc.kill()
                result["hung"] = True
                result["status"] = "timeout"
                self.stats["viewer_hangs"] += 1

                # Log hang
                hang_log = self.output_dir / f"hang_{dicom_file.stem}.txt"
                with open(hang_log, "w") as f:
                    f.write(f"File: {dicom_file}\n")
                    f.write(f"Viewer hung after {self.timeout}s timeout\n")

                logger.warning(f"HANG detected: {dicom_file}")

        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"
            logger.error(f"Error testing viewer: {e}")

        return result

    def run_fuzzing_campaign(
        self, count: int, severity: MutationSeverity = MutationSeverity.MODERATE
    ):
        """
        Run a fuzzing campaign.

        Args:
            count: Number of fuzzed files to generate
            severity: Mutation severity level
        """
        logger.info(
            f"Starting fuzzing campaign: {count} files, severity={severity.value}"
        )
        logger.info(f"Input: {self.input_dir}")
        logger.info(f"Output: {self.output_dir}")
        if self.viewer_path:
            logger.info(f"Viewer: {self.viewer_path}")

        # Find source DICOM files
        source_files = self.find_dicom_files(limit=count)
        if not source_files:
            logger.error("No DICOM files found!")
            return

        # Fuzz each file
        for i, source_file in enumerate(source_files, 1):
            logger.info(f"\n[{i}/{len(source_files)}] Processing {source_file.name}")

            # Generate fuzzed file
            fuzzed_file = self.generate_fuzzed_file(source_file, severity)
            if not fuzzed_file:
                continue

            # Test viewer if specified
            if self.viewer_path:
                result = self.test_viewer(fuzzed_file)
                logger.info(f"  Viewer result: {result['status']}")

            self.stats["files_processed"] += 1

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print fuzzing campaign summary."""
        logger.info("\n" + "=" * 70)
        logger.info("FUZZING CAMPAIGN SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Files Processed: {self.stats['files_processed']}")
        logger.info(f"Files Fuzzed: {self.stats['files_fuzzed']}")
        logger.info(f"Files Generated: {self.stats['files_generated']}")

        if self.viewer_path:
            logger.info(f"\nViewer Testing Results:")
            logger.info(f"  Success: {self.stats['viewer_success']}")
            logger.info(f"  Crashes: {self.stats['viewer_crashes']}")
            logger.info(f"  Hangs: {self.stats['viewer_hangs']}")

            total_tests = (
                self.stats["viewer_success"]
                + self.stats["viewer_crashes"]
                + self.stats["viewer_hangs"]
            )
            if total_tests > 0:
                crash_rate = (self.stats["viewer_crashes"] / total_tests) * 100
                hang_rate = (self.stats["viewer_hangs"] / total_tests) * 100
                logger.info(f"  Crash Rate: {crash_rate:.1f}%")
                logger.info(f"  Hang Rate: {hang_rate:.1f}%")

        logger.info(f"\nOutput Directory: {self.output_dir}")
        logger.info("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Fuzz DICOM viewer applications for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 100 fuzzed files
  python fuzz_dicom_viewer.py --input "C:/Data/Kiwi - Example Data - 20210423" \\
      --output "./fuzzed_output" --count 100

  # Fuzz and test Hermes viewer
  python fuzz_dicom_viewer.py \\
      --input "C:/Data/Kiwi - Example Data - 20210423" \\
      --output "./fuzzed_output" \\
      --viewer "C:/Hermes/Affinity/Hermes.exe" \\
      --count 50 --timeout 5 --severity aggressive

  # Use environment variables for paths
  export DICOM_INPUT="C:/Data/Kiwi - Example Data - 20210423"
  export DICOM_VIEWER="C:/Hermes/Affinity/Hermes.exe"
  python fuzz_dicom_viewer.py --count 20
        """,
    )

    parser.add_argument(
        "--input",
        "-i",
        default=os.getenv("DICOM_INPUT", "C:/Data/Kiwi - Example Data - 20210423"),
        help="Input directory with DICOM files (default: DICOM_INPUT env var)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default="./fuzzed_output",
        help="Output directory for fuzzed files (default: ./fuzzed_output)",
    )

    parser.add_argument(
        "--viewer",
        "-v",
        default=os.getenv("DICOM_VIEWER"),
        help="Path to DICOM viewer executable (default: DICOM_VIEWER env var)",
    )

    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=10,
        help="Number of fuzzed files to generate (default: 10)",
    )

    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=5,
        help="Viewer execution timeout in seconds (default: 5)",
    )

    parser.add_argument(
        "--severity",
        "-s",
        choices=["minimal", "moderate", "aggressive", "extreme"],
        default="moderate",
        help="Mutation severity level (default: moderate)",
    )

    args = parser.parse_args()

    # Convert severity string to enum
    severity_map = {
        "minimal": MutationSeverity.MINIMAL,
        "moderate": MutationSeverity.MODERATE,
        "aggressive": MutationSeverity.AGGRESSIVE,
        "extreme": MutationSeverity.EXTREME,
    }
    severity = severity_map[args.severity]

    try:
        # Create fuzzer
        fuzzer = ViewerFuzzer(
            input_dir=args.input,
            output_dir=args.output,
            viewer_path=args.viewer,
            timeout=args.timeout,
        )

        # Run fuzzing campaign
        fuzzer.run_fuzzing_campaign(count=args.count, severity=severity)

    except KeyboardInterrupt:
        logger.info("\n\nFuzzing interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
