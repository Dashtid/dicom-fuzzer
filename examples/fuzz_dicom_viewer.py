#!/usr/bin/env python3
r"""
Fuzz DICOM Viewer Applications

This script fuzzes DICOM viewer applications by:
1. Loading real DICOM files from a local directory
2. Applying intelligent mutations using dictionary-based fuzzing
3. Saving mutated files to an output directory
4. Optionally launching the viewer with each mutated file
5. Monitoring for crashes and unexpected behavior

SECURITY NOTICE: For Defensive Security Testing Only
---------------------------------------------------
This tool is for AUTHORIZED security testing only.

AUTHORIZED USES:
- Security testing of in-house medical imaging software
- Vulnerability assessment in controlled lab environments
- Compliance testing for medical device manufacturers
- Academic research with IRB approval

PROHIBITED USES:
- Testing production medical systems without authorization
- Attacking third-party medical infrastructure
- Processing real patient data (PHI) without proper safeguards

PRIVACY REQUIREMENTS:
- Use only de-identified, public test datasets
- Never commit patient data to version control
- Comply with HIPAA, GDPR, and local regulations

Example usage:
    # Generate fuzzed files only (no execution)
    python fuzz_dicom_viewer.py --input "./test_data/dicom_samples" \\
        --output "./fuzzed_output" --count 100

    # Fuzz and test viewer (automated)
    python fuzz_dicom_viewer.py \\
        --input "./test_data/dicom_samples" \\
        --output "./fuzzed_output" \\
        --viewer "/path/to/viewer" \\
        --count 50 --timeout 5 --severity moderate

    # Use environment variables for paths
    export DICOM_INPUT_DIR="./test_data/dicom_samples"
    export DICOM_VIEWER_PATH="/path/to/viewer"
    python fuzz_dicom_viewer.py --count 20
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pydicom

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to load local configuration (never committed to git)
try:
    from config import local_paths

    DEFAULT_INPUT = str(local_paths.DICOM_INPUT_DIR)
    DEFAULT_VIEWER = str(local_paths.DICOM_VIEWER_PATH)
    DEFAULT_TIMEOUT = local_paths.VIEWER_TIMEOUT
except ImportError:
    # Fallback to environment variables if local_paths.py doesn't exist
    DEFAULT_INPUT = os.getenv("DICOM_INPUT_DIR", "./test_data/dicom_samples")
    DEFAULT_VIEWER = os.getenv("DICOM_VIEWER_PATH")
    DEFAULT_TIMEOUT = int(os.getenv("DICOM_VIEWER_TIMEOUT", "5"))

from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.core.validator import DicomValidator

# from dicom_fuzzer.strategies.dictionary_fuzzer import DictionaryFuzzer
from dicom_fuzzer.utils.identifiers import generate_session_id, generate_timestamp_id
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class ViewerFuzzer:
    """Fuzzer for DICOM viewer applications."""

    def __init__(
        self,
        input_dir: str,
        output_dir: str,
        viewer_path: str | None = None,
        timeout: int = 5,
        use_enhanced_reporting: bool = True,
    ):
        """
        Initialize viewer fuzzer.

        Args:
            input_dir: Directory containing real DICOM files
            output_dir: Directory to save fuzzed files
            viewer_path: Path to DICOM viewer executable (optional)
            timeout: Timeout in seconds for viewer execution
            use_enhanced_reporting: Use new FuzzingSession tracking (recommended)
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.viewer_path = Path(viewer_path) if viewer_path else None
        self.timeout = timeout
        self.use_enhanced_reporting = use_enhanced_reporting

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

        # Initialize enhanced reporting if enabled
        self.fuzzing_session: FuzzingSession | None = None
        self.current_file_id: str | None = None

        if self.use_enhanced_reporting:
            session_name = generate_session_id("viewer_fuzzing")
            self.fuzzing_session = FuzzingSession(
                session_name=session_name,
                output_dir=str(self.output_dir),
                reports_dir="./reports",
            )
            logger.info("Enhanced reporting enabled - full traceability active")

        # Statistics
        self.stats = {
            "files_processed": 0,
            "files_fuzzed": 0,
            "files_generated": 0,
            "viewer_crashes": 0,
            "viewer_hangs": 0,
            "viewer_success": 0,
            "write_failures": 0,
            "validation_failures": 0,
        }

        # Detailed failure tracking (legacy support)
        self.failures = {
            "write_failures": [],  # Files that failed to write after mutation
            "validation_failures": [],  # Files that failed validation
            "viewer_crashes": [],  # Files that crashed the viewer
            "viewer_hangs": [],  # Files that hung the viewer
        }

    def find_dicom_files(self, limit: int | None = None) -> list[Path]:
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
    ) -> Path | None:
        """
        Generate a fuzzed DICOM file.

        Args:
            source_file: Path to source DICOM file
            severity: Mutation severity level

        Returns:
            Path to fuzzed file, or None if failed
        """
        # Generate output filename first
        severity_name = severity.value
        timestamp = int(time.time() * 1000)
        output_name = f"fuzzed_{severity_name}_{source_file.stem}_{timestamp}.dcm"
        output_path = self.output_dir / output_name

        # Start enhanced session tracking if enabled
        if self.fuzzing_session:
            self.current_file_id = self.fuzzing_session.start_file_fuzzing(
                source_file=source_file, output_file=output_path, severity=severity_name
            )

        try:
            # Parse source file using pydicom
            dataset = pydicom.dcmread(str(source_file), force=True)
            if not dataset:
                logger.warning(f"Failed to parse {source_file}")
                if self.fuzzing_session:
                    self.fuzzing_session.end_file_fuzzing(output_path, success=False)
                return None

            # Apply mutations
            self.mutator.start_session(dataset)
            mutated = self.mutator.apply_mutations(
                dataset, num_mutations=3, severity=severity
            )

            # Record mutations in session if enabled
            if self.fuzzing_session and self.mutator.current_session:
                for mutation_record in self.mutator.current_session.mutations:
                    self.fuzzing_session.record_mutation(
                        strategy_name=mutation_record.strategy_name,
                        mutation_type=mutation_record.description or "mutation",
                        parameters={
                            "severity": mutation_record.severity.value,
                            **mutation_record.parameters,
                        },
                    )

            self.mutator.end_session()

            # Save fuzzed file (disable validation to allow malformed data)
            try:
                pydicom.dcmwrite(str(output_path), mutated, write_like_original=False)
                self.stats["files_fuzzed"] += 1
                self.stats["files_generated"] += 1

                # End session tracking
                if self.fuzzing_session:
                    self.fuzzing_session.end_file_fuzzing(output_path, success=True)

                logger.info(f"Generated fuzzed file: {output_path}")
                return output_path
            except Exception as write_error:
                # Some mutations may be too corrupt to write - that's okay
                self.stats["files_fuzzed"] += 1  # Still count as fuzzed
                self.stats["write_failures"] += 1
                self.failures["write_failures"].append(
                    {
                        "source_file": str(source_file),
                        "severity": severity.value,
                        "error": str(write_error),
                        "timestamp": timestamp,
                    }
                )
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

                    # Log crash (legacy)
                    crash_log = self.output_dir / f"crash_{dicom_file.stem}.txt"
                    with open(crash_log, "w") as f:
                        f.write(f"File: {dicom_file}\n")
                        f.write(f"Return Code: {proc.returncode}\n")
                        f.write(f"STDOUT:\n{stdout.decode(errors='ignore')}\n")
                        f.write(f"STDERR:\n{stderr.decode(errors='ignore')}\n")

                    # Track crash details (legacy)
                    self.failures["viewer_crashes"].append(
                        {
                            "file": str(dicom_file),
                            "return_code": proc.returncode,
                            "crash_log": str(crash_log),
                        }
                    )

                    # Enhanced crash recording
                    if self.fuzzing_session and self.current_file_id:
                        stderr_str = stderr.decode(errors="ignore")
                        self.fuzzing_session.record_test_result(
                            self.current_file_id, "crash", return_code=proc.returncode
                        )
                        self.fuzzing_session.record_crash(
                            file_id=self.current_file_id,
                            crash_type="crash",
                            severity="high",
                            return_code=proc.returncode,
                            exception_message=f"Viewer crashed with exit code {proc.returncode}",
                            stack_trace=stderr_str if stderr_str else None,
                            viewer_path=str(self.viewer_path),
                        )

                    logger.warning(f"CRASH detected: {dicom_file}")
                else:
                    result["status"] = "success"
                    self.stats["viewer_success"] += 1

                    # Record success in enhanced tracking
                    if self.fuzzing_session and self.current_file_id:
                        self.fuzzing_session.record_test_result(
                            self.current_file_id, "success"
                        )

            except subprocess.TimeoutExpired:
                proc.kill()
                result["hung"] = True
                result["status"] = "timeout"
                self.stats["viewer_hangs"] += 1

                # Log hang (legacy)
                hang_log = self.output_dir / f"hang_{dicom_file.stem}.txt"
                with open(hang_log, "w") as f:
                    f.write(f"File: {dicom_file}\n")
                    f.write(f"Viewer hung after {self.timeout}s timeout\n")

                # Track hang details (legacy)
                self.failures["viewer_hangs"].append(
                    {
                        "file": str(dicom_file),
                        "timeout": self.timeout,
                        "hang_log": str(hang_log),
                    }
                )

                # Enhanced hang recording
                if self.fuzzing_session and self.current_file_id:
                    self.fuzzing_session.record_test_result(
                        self.current_file_id, "hang", timeout=self.timeout
                    )
                    self.fuzzing_session.record_crash(
                        file_id=self.current_file_id,
                        crash_type="hang",
                        severity="high",
                        exception_message=f"Viewer hung after {self.timeout}s timeout (DoS vulnerability)",
                        viewer_path=str(self.viewer_path),
                    )

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
            self.stats["files_processed"] += 1

            # Generate fuzzed file
            fuzzed_file = self.generate_fuzzed_file(source_file, severity)
            if not fuzzed_file:
                logger.warning("  Skipping - failed to generate fuzzed file")
                continue

            # Test viewer if specified
            if self.viewer_path:
                result = self.test_viewer(fuzzed_file)
                logger.info(f"  Viewer result: {result['status']}")

        # Print summary and generate reports
        self.print_summary()

    def print_summary(self):
        """Print fuzzing campaign summary and generate enhanced reports."""
        logger.info("\n" + "=" * 70)
        logger.info("FUZZING CAMPAIGN SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Files Processed: {self.stats['files_processed']}")
        logger.info(f"Files Fuzzed: {self.stats['files_fuzzed']}")
        logger.info(f"Files Generated: {self.stats['files_generated']}")
        logger.info(f"Write Failures: {self.stats['write_failures']}")

        if self.viewer_path:
            logger.info("\nViewer Testing Results:")
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

        # Print detailed failure information
        if self.stats["write_failures"] > 0:
            logger.info(
                f"\nWrite Failures Details ({self.stats['write_failures']} files):"
            )
            for i, failure in enumerate(self.failures["write_failures"][:10], 1):
                logger.info(f"  {i}. {Path(failure['source_file']).name}")
                logger.info(f"     Severity: {failure['severity']}")
                logger.info(f"     Error: {failure['error'][:100]}...")

        if self.stats["viewer_crashes"] > 0:
            logger.info(f"\nViewer Crashes ({self.stats['viewer_crashes']} files):")
            for i, crash in enumerate(self.failures["viewer_crashes"][:10], 1):
                logger.info(f"  {i}. {Path(crash['file']).name}")
                logger.info(f"     Return Code: {crash['return_code']}")
                logger.info(f"     Log: {crash['crash_log']}")

        if self.stats["viewer_hangs"] > 0:
            logger.info(f"\nViewer Hangs ({self.stats['viewer_hangs']} files):")
            for i, hang in enumerate(self.failures["viewer_hangs"][:10], 1):
                logger.info(f"  {i}. {Path(hang['file']).name}")
                logger.info(f"     Timeout: {hang['timeout']}s")
                logger.info(f"     Log: {hang['hang_log']}")

        logger.info(f"\nOutput Directory: {self.output_dir}")
        logger.info("=" * 70)

        # Save legacy JSON report
        self.save_json_report()

        # Generate enhanced reports if enabled
        if self.fuzzing_session:
            logger.info("\n" + "=" * 70)
            logger.info("GENERATING ENHANCED REPORTS")
            logger.info("=" * 70)

            # Save session JSON
            json_path = self.fuzzing_session.save_session_report()
            logger.info(f"Session JSON: {json_path}")

            # Generate interactive HTML report
            import json as json_module

            with open(json_path, encoding="utf-8") as f:
                session_data = json_module.load(f)

            reporter = EnhancedReportGenerator()
            html_path = reporter.generate_html_report(session_data)
            logger.info(f"HTML Report: {html_path}")

            # Print crash summary
            crashes = session_data.get("crashes", [])
            if crashes:
                logger.info(f"\n⚠️  {len(crashes)} CRASHES DETECTED")
                logger.info("\nCrash Artifacts:")
                for crash in crashes:
                    logger.info(f"  • {crash['crash_id']}")
                    logger.info(
                        f"    Type: {crash['crash_type']} | Severity: {crash['severity']}"
                    )
                    logger.info(f"    Sample: {crash.get('preserved_sample_path')}")
                    logger.info(f"    Log: {crash.get('crash_log_path')}")
                    if crash.get("reproduction_command"):
                        logger.info(f"    Repro: {crash['reproduction_command']}")
                    logger.info("")

            logger.info("=" * 70)

    def save_json_report(self):
        """Save fuzzing results to JSON report."""
        import json

        # Create report data
        report = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "input_dir": str(self.input_dir),
                "output_dir": str(self.output_dir),
                "viewer_path": str(self.viewer_path) if self.viewer_path else None,
                "timeout": self.timeout,
            },
            "statistics": self.stats.copy(),
            "failures": {
                "write_failures": self.failures["write_failures"],
                "viewer_crashes": self.failures["viewer_crashes"],
                "viewer_hangs": self.failures["viewer_hangs"],
            },
        }

        # Calculate rates if viewer was used
        if self.viewer_path:
            total_tests = (
                self.stats["viewer_success"]
                + self.stats["viewer_crashes"]
                + self.stats["viewer_hangs"]
            )
            if total_tests > 0:
                report["statistics"]["crash_rate"] = (
                    self.stats["viewer_crashes"] / total_tests
                ) * 100
                report["statistics"]["hang_rate"] = (
                    self.stats["viewer_hangs"] / total_tests
                ) * 100

        # Save to reports directory with organized structure
        timestamp = generate_timestamp_id()

        # Create reports subdirectories
        reports_dir = Path("reports")
        json_dir = reports_dir / "json"
        html_dir = reports_dir / "html"
        json_dir.mkdir(parents=True, exist_ok=True)
        html_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON report
        json_path = json_dir / f"fuzzing_report_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # Generate HTML report
        html_path = html_dir / f"fuzzing_report_{timestamp}.html"
        self._generate_html_report(report, html_path)

        logger.info(f"\nJSON report: {json_path}")
        logger.info(f"HTML report: {html_path}")

    def _generate_html_report(self, report: dict, output_path: Path):
        """Generate HTML report from fuzzing results."""
        import json
        import subprocess
        import sys

        # Use the HTML report generator tool
        tools_dir = Path(__file__).parent.parent / "tools"
        generator = tools_dir / "create_html_report.py"

        if generator.exists():
            # Create temp JSON for the generator
            temp_json = (
                output_path.parent.parent / "json" / f"temp_{output_path.stem}.json"
            )
            with open(temp_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            try:
                subprocess.run(
                    [sys.executable, str(generator), str(temp_json), str(output_path)],
                    check=True,
                    capture_output=True,
                )
                temp_json.unlink()  # Clean up temp file
            except Exception as e:
                logger.warning(f"Could not generate HTML report: {e}")
        else:
            logger.warning(f"HTML generator not found at {generator}")


def main():
    """Parse arguments and run fuzzing campaign."""
    parser = argparse.ArgumentParser(
        description="Fuzz DICOM viewer applications for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 100 fuzzed files
  python fuzz_dicom_viewer.py --input "./test_data/dicom_samples" \\
      --output "./fuzzed_output" --count 100

  # Fuzz and test DICOM viewer application
  python fuzz_dicom_viewer.py \\
      --input "./test_data/dicom_samples" \\
      --output "./fuzzed_output" \\
      --viewer "/path/to/dicom/viewer" \\
      --count 50 --timeout 5 --severity moderate

  # Use environment variables for paths
  export DICOM_INPUT_DIR="./test_data/dicom_samples"
  export DICOM_VIEWER_PATH="/path/to/dicom/viewer"
  python fuzz_dicom_viewer.py --count 20
        """,
    )

    parser.add_argument(
        "--input",
        "-i",
        default=DEFAULT_INPUT,
        help=f"Input directory with DICOM files (default: {DEFAULT_INPUT})",
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
        default=DEFAULT_VIEWER,
        help=f"Path to DICOM viewer executable (default: {DEFAULT_VIEWER or 'Not configured'})",
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
        default=DEFAULT_TIMEOUT,
        help=f"Viewer execution timeout in seconds (default: {DEFAULT_TIMEOUT})",
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
