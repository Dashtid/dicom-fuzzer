"""Configuration Validation and Pre-flight Checks

CONCEPT: Validates configuration and system state before starting fuzzing
campaigns to catch issues early and provide clear error messages.

STABILITY: Prevents wasted time by validating everything upfront:
- File system access and permissions
- Available disk space
- Target executable accessibility
- Configuration parameter validity
- Python dependencies
"""

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of a validation check."""

    passed: bool
    message: str
    severity: str = "error"  # error, warning, info

    def __bool__(self) -> bool:
        """Allow boolean evaluation."""
        return self.passed


class ConfigValidator:
    """Validates configuration and performs pre-flight checks.

    CONCEPT: Run a battery of validation checks before starting a campaign
    to catch configuration errors early and provide helpful feedback.
    """

    def __init__(self, strict: bool = True):
        """Initialize configuration validator.

        Args:
            strict: If True, warnings are treated as errors

        """
        self.strict = strict
        self.errors: list[ValidationResult] = []
        self.warnings: list[ValidationResult] = []
        self.info: list[ValidationResult] = []

    def _log_results(self) -> None:
        """Log all validation results."""
        if self.info:
            logger.info(f"Pre-flight info ({len(self.info)}):")
            for result in self.info:
                logger.info(f"  [INFO] {result.message}")
        if self.warnings:
            logger.warning(f"Pre-flight warnings ({len(self.warnings)}):")
            for result in self.warnings:
                logger.warning(f"  [WARN] {result.message}")
        if self.errors:
            logger.error(f"Pre-flight errors ({len(self.errors)}):")
            for result in self.errors:
                logger.error(f"  [ERROR] {result.message}")

    def _determine_overall_result(self) -> bool:
        """Determine if validation passed based on errors, warnings, and strict mode."""
        if self.errors:
            return False
        if self.warnings and self.strict:
            logger.error("Strict mode enabled - treating warnings as errors")
            return False
        logger.info("All pre-flight checks passed")
        return True

    def validate_all(
        self,
        input_file: Path | None = None,
        output_dir: Path | None = None,
        target_executable: Path | None = None,
        min_disk_space_mb: float = 1024,
        num_files: int | None = None,
    ) -> bool:
        """Run all validation checks.

        Args:
            input_file: Input DICOM file to validate
            output_dir: Output directory to validate
            target_executable: Target application to validate
            min_disk_space_mb: Minimum required disk space in MB
            num_files: Number of files to generate (for capacity check)

        Returns:
            True if all checks passed (or only warnings in non-strict mode)

        """
        logger.info("Running pre-flight validation checks...")

        self._check_python_version()
        self._check_dependencies()

        if input_file:
            self._validate_input_file(input_file)
        if output_dir:
            self._validate_output_dir(output_dir)
        if output_dir and num_files:
            self._check_disk_space(output_dir, min_disk_space_mb, num_files)
        if target_executable:
            self._validate_target_executable(target_executable)

        self._check_system_resources()
        self._log_results()
        return self._determine_overall_result()

    def _check_python_version(self) -> None:
        """Check Python version meets requirements."""
        required_version = (3, 11)
        current_version = sys.version_info[:2]

        if current_version < required_version:
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=(
                        f"Python {required_version[0]}.{required_version[1]}+ required, "
                        f"found {current_version[0]}.{current_version[1]}"
                    ),
                    severity="error",
                )
            )
        else:
            self.info.append(
                ValidationResult(
                    passed=True,
                    message=f"Python version: {current_version[0]}.{current_version[1]}",
                    severity="info",
                )
            )

    def _check_dependencies(self) -> None:
        """Check that required dependencies are installed."""
        required = ["pydicom", "pytest"]
        optional = ["tqdm", "psutil"]

        # Check required
        missing_required = []
        for dep in required:
            try:
                __import__(dep)
            except ImportError:
                missing_required.append(dep)

        if missing_required:
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=f"Missing required dependencies: {', '.join(missing_required)}",
                    severity="error",
                )
            )

        # Check optional
        missing_optional = []
        for dep in optional:
            try:
                __import__(dep)
            except ImportError:
                missing_optional.append(dep)

        if missing_optional:
            self.warnings.append(
                ValidationResult(
                    passed=False,
                    message=f"Missing optional dependencies: {', '.join(missing_optional)}",
                    severity="warning",
                )
            )

    def _validate_input_file(self, input_file: Path) -> None:
        """Validate input DICOM file."""
        # Check existence
        if not input_file.exists():
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=f"Input file not found: {input_file}",
                    severity="error",
                )
            )
            return

        # Check it's a file
        if not input_file.is_file():
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=f"Input path is not a file: {input_file}",
                    severity="error",
                )
            )
            return

        # Check readable
        if not os.access(input_file, os.R_OK):
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=f"Input file not readable: {input_file}",
                    severity="error",
                )
            )
            return

        # Check file size
        file_size = input_file.stat().st_size
        if file_size == 0:
            self.warnings.append(
                ValidationResult(
                    passed=False,
                    message=f"Input file is empty: {input_file}",
                    severity="warning",
                )
            )
        elif file_size < 132:  # DICOM minimum (128 byte preamble + DICM)
            self.warnings.append(
                ValidationResult(
                    passed=False,
                    message=f"Input file too small to be valid DICOM ({file_size} bytes)",
                    severity="warning",
                )
            )

        # Try to load with pydicom
        try:
            import pydicom

            pydicom.dcmread(input_file, stop_before_pixels=True)
            self.info.append(
                ValidationResult(
                    passed=True,
                    message=f"Input file validated: {input_file.name}",
                    severity="info",
                )
            )
        except Exception as e:
            self.warnings.append(
                ValidationResult(
                    passed=False,
                    message=f"Input file may not be valid DICOM: {e}",
                    severity="warning",
                )
            )

    def _validate_output_dir(self, output_dir: Path) -> None:
        """Validate output directory."""
        # If it doesn't exist, check parent is writable
        if not output_dir.exists():
            parent = output_dir.parent
            if not parent.exists():
                self.errors.append(
                    ValidationResult(
                        passed=False,
                        message=f"Output directory parent doesn't exist: {parent}",
                        severity="error",
                    )
                )
                return

            if not os.access(parent, os.W_OK):
                self.errors.append(
                    ValidationResult(
                        passed=False,
                        message=f"Cannot create output directory (parent not writable): {parent}",
                        severity="error",
                    )
                )
                return

            self.info.append(
                ValidationResult(
                    passed=True,
                    message=f"Output directory will be created: {output_dir}",
                    severity="info",
                )
            )
        else:
            # Directory exists - check it's writable
            if not output_dir.is_dir():
                self.errors.append(
                    ValidationResult(
                        passed=False,
                        message=f"Output path exists but is not a directory: {output_dir}",
                        severity="error",
                    )
                )
                return

            if not os.access(output_dir, os.W_OK):
                self.errors.append(
                    ValidationResult(
                        passed=False,
                        message=f"Output directory not writable: {output_dir}",
                        severity="error",
                    )
                )
                return

            self.info.append(
                ValidationResult(
                    passed=True,
                    message=f"Output directory validated: {output_dir}",
                    severity="info",
                )
            )

    def _validate_target_executable(self, target_exe: Path) -> None:
        """Validate target executable."""
        if not target_exe.exists():
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=f"Target executable not found: {target_exe}",
                    severity="error",
                )
            )
            return

        if not target_exe.is_file():
            self.errors.append(
                ValidationResult(
                    passed=False,
                    message=f"Target path is not a file: {target_exe}",
                    severity="error",
                )
            )
            return

        # Check executable permission (Unix only)
        if sys.platform != "win32":
            if not os.access(target_exe, os.X_OK):
                self.warnings.append(
                    ValidationResult(
                        passed=False,
                        message=f"Target file may not be executable: {target_exe}",
                        severity="warning",
                    )
                )
                return

        self.info.append(
            ValidationResult(
                passed=True,
                message=f"Target executable validated: {target_exe.name}",
                severity="info",
            )
        )

    def _check_disk_space(
        self, output_dir: Path, min_mb: float, num_files: int
    ) -> None:
        """Check available disk space."""
        try:
            stat = shutil.disk_usage(
                output_dir if output_dir.exists() else output_dir.parent
            )
            free_mb = stat.free / (1024 * 1024)

            # Estimate required space (assuming 1MB per file as default)
            estimated_mb = num_files * 1.5  # Add 50% overhead

            if free_mb < min_mb:
                self.errors.append(
                    ValidationResult(
                        passed=False,
                        message=(
                            f"Insufficient disk space: {free_mb:.0f}MB available, "
                            f"{min_mb:.0f}MB required"
                        ),
                        severity="error",
                    )
                )
            elif free_mb < estimated_mb:
                self.warnings.append(
                    ValidationResult(
                        passed=False,
                        message=(
                            f"Disk space may be tight: {free_mb:.0f}MB available, "
                            f"estimated {estimated_mb:.0f}MB needed for {num_files} files"
                        ),
                        severity="warning",
                    )
                )
            else:
                self.info.append(
                    ValidationResult(
                        passed=True,
                        message=f"Disk space available: {free_mb:.0f}MB",
                        severity="info",
                    )
                )
        except Exception as e:
            self.warnings.append(
                ValidationResult(
                    passed=False,
                    message=f"Could not check disk space: {e}",
                    severity="warning",
                )
            )

    def _check_system_resources(self) -> None:
        """Check system resources (RAM, CPU)."""
        try:
            import psutil

            # Check available memory
            mem = psutil.virtual_memory()
            mem_available_mb = mem.available / (1024 * 1024)

            if mem_available_mb < 512:
                self.warnings.append(
                    ValidationResult(
                        passed=False,
                        message=f"Low available memory: {mem_available_mb:.0f}MB",
                        severity="warning",
                    )
                )
            else:
                self.info.append(
                    ValidationResult(
                        passed=True,
                        message=f"Available memory: {mem_available_mb:.0f}MB",
                        severity="info",
                    )
                )

            # Check CPU count
            cpu_count = psutil.cpu_count(logical=True)
            self.info.append(
                ValidationResult(
                    passed=True,
                    message=f"CPU cores available: {cpu_count}",
                    severity="info",
                )
            )

        except ImportError:
            # psutil not available - skip resource checks
            self.info.append(
                ValidationResult(
                    passed=True,
                    message="Install 'psutil' for system resource checks",
                    severity="info",
                )
            )

    def get_summary(self) -> str:
        """Get summary of validation results.

        Returns:
            Formatted summary string

        """
        lines = ["=" * 70, "  Pre-flight Validation Summary", "=" * 70]

        if self.errors:
            lines.append(f"\n  [X] Errors: {len(self.errors)}")
            for result in self.errors:
                lines.append(f"      - {result.message}")

        if self.warnings:
            lines.append(f"\n  [!] Warnings: {len(self.warnings)}")
            for result in self.warnings:
                lines.append(f"      - {result.message}")

        if self.info:
            lines.append(f"\n  [i] Info: {len(self.info)}")
            for result in self.info[:5]:  # Show first 5
                lines.append(f"      - {result.message}")
            if len(self.info) > 5:
                lines.append(f"      ... and {len(self.info) - 5} more")

        lines.append("=" * 70)
        return "\n".join(lines)
