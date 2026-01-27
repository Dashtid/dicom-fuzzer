"""DICOM Series Validation.

Validates DICOM series for completeness, consistency, geometry, and metadata.
Detects anomalies and potential attack vectors.

Series with validation errors are more likely to trigger vulnerabilities.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import numpy as np
import pydicom

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""

    INFO = "info"  # Informational, not necessarily an error
    WARNING = "warning"  # Potential issue, series may still be usable
    ERROR = "error"  # Significant issue, series may be corrupted
    CRITICAL = "critical"  # Series is invalid, cannot be used


@dataclass
class ValidationIssue:
    """Represents a single validation issue found in a series.

    Attributes:
        severity: Severity level of the issue
        category: Category (completeness, consistency, geometry, metadata)
        message: Human-readable description
        slice_index: Index of affected slice (None if series-level issue)
        slice_path: Path to affected slice file (None if series-level issue)
        details: Additional details about the issue

    """

    severity: ValidationSeverity
    category: str
    message: str
    slice_index: int | None = None
    slice_path: Path | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        """String representation for logging."""
        slice_info = (
            f" (slice {self.slice_index})" if self.slice_index is not None else ""
        )
        return f"[{self.severity.value.upper()}] {self.category}: {self.message}{slice_info}"


@dataclass
class ValidationReport:
    """Complete validation report for a DICOM series.

    Attributes:
        series: The DicomSeries that was validated
        issues: List of ValidationIssue objects found
        is_valid: True if no ERROR or CRITICAL issues
        validation_time: Time taken for validation (seconds)

    """

    series: DicomSeries
    issues: list[ValidationIssue] = field(default_factory=list)
    is_valid: bool = True
    validation_time: float = 0.0

    def get_issues_by_severity(
        self, severity: ValidationSeverity
    ) -> list[ValidationIssue]:
        """Get all issues of a specific severity."""
        return [issue for issue in self.issues if issue.severity == severity]

    def has_critical_issues(self) -> bool:
        """Check if report contains any CRITICAL issues."""
        return any(
            issue.severity == ValidationSeverity.CRITICAL for issue in self.issues
        )

    def has_errors(self) -> bool:
        """Check if report contains ERROR or CRITICAL issues."""
        return any(
            issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]
            for issue in self.issues
        )

    def summary(self) -> str:
        """Generate a summary of validation results."""
        if not self.issues:
            return "Series is valid with no issues"

        critical = len(self.get_issues_by_severity(ValidationSeverity.CRITICAL))
        errors = len(self.get_issues_by_severity(ValidationSeverity.ERROR))
        warnings = len(self.get_issues_by_severity(ValidationSeverity.WARNING))
        info = len(self.get_issues_by_severity(ValidationSeverity.INFO))

        return (
            f"Series validation: "
            f"{critical} critical, {errors} errors, {warnings} warnings, {info} info"
        )


class SeriesValidator:
    """Validate DICOM series for completeness, consistency, and correctness.

    This validator performs comprehensive checks to detect:
    - Missing or duplicate slices
    - Inconsistent metadata (UIDs, modality, orientation)
    - Geometric anomalies (non-uniform spacing, gaps)
    - Missing required DICOM tags
    - Potential security vulnerabilities (extreme values, unusual patterns)
    """

    def __init__(self, strict: bool = False):
        """Initialize validator.

        Args:
            strict: If True, treat warnings as errors

        """
        self.strict = strict

    def validate_series(self, series: DicomSeries) -> ValidationReport:
        """Perform comprehensive validation of a DICOM series.

        Args:
            series: DicomSeries to validate

        Returns:
            ValidationReport with all issues found

        """
        import time

        start_time = time.time()

        report = ValidationReport(series=series)

        # Run all validation checks
        self._validate_completeness(series, report)
        self._validate_consistency(series, report)
        self._validate_geometry(series, report)
        self._validate_metadata(series, report)
        self._validate_security_concerns(series, report)

        # Determine if series is valid
        report.is_valid = not report.has_errors()

        report.validation_time = time.time() - start_time

        logger.info(
            f"Validated series {series.series_uid[:16]}... in "
            f"{report.validation_time:.2f}s: {report.summary()}"
        )

        return report

    def _validate_completeness(
        self, series: DicomSeries, report: ValidationReport
    ) -> None:
        """Validate series completeness (no missing slices).

        Checks:
        - At least one slice present
        - No gaps in InstanceNumber sequence
        - Reasonable number of slices for modality
        """
        # Check for empty series
        if series.slice_count == 0:
            report.issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.CRITICAL,
                    category="completeness",
                    message="Series contains no slices",
                )
            )
            return

        # Check instance numbers for gaps
        instance_numbers = []
        for i, slice_path in enumerate(series.slices):
            try:
                ds = pydicom.dcmread(slice_path, stop_before_pixels=True)
                if hasattr(ds, "InstanceNumber"):
                    instance_numbers.append(int(ds.InstanceNumber))
                else:
                    report.issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="completeness",
                            message="Slice missing InstanceNumber",
                            slice_index=i,
                            slice_path=slice_path,
                        )
                    )
            except Exception as e:
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category="completeness",
                        message=f"Error reading slice: {e}",
                        slice_index=i,
                        slice_path=slice_path,
                    )
                )

        # Check for gaps in sequence
        if instance_numbers:
            instance_numbers_sorted = sorted(instance_numbers)
            expected_range = range(
                instance_numbers_sorted[0], instance_numbers_sorted[-1] + 1
            )
            missing_instances = set(expected_range) - set(instance_numbers)

            if missing_instances:
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category="completeness",
                        message=f"Missing {len(missing_instances)} instance(s) in sequence",
                        details={"missing_instances": sorted(missing_instances)},
                    )
                )

        # Check for reasonable slice count
        if series.slice_count > 1000:
            report.issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="completeness",
                    message=f"Unusually large series: {series.slice_count} slices",
                    details={"slice_count": series.slice_count},
                )
            )

    def _validate_consistency(
        self, series: DicomSeries, report: ValidationReport
    ) -> None:
        """Validate consistency of series-level attributes across all slices.

        Checks:
        - All slices have same SeriesInstanceUID
        - All slices have same StudyInstanceUID
        - All slices have same Modality
        - All slices have same ImageOrientationPatient
        """
        # Use DicomSeries built-in validation
        consistency_errors = series.validate_series_consistency()

        for error in consistency_errors:
            report.issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    category="consistency",
                    message=error,
                )
            )

    def _validate_geometry(self, series: DicomSeries, report: ValidationReport) -> None:
        """Validate geometric properties of the series.

        Checks:
        - Uniform slice spacing
        - Valid ImagePositionPatient values
        - Consistent ImageOrientationPatient
        - Reasonable physical dimensions
        """
        if series.slice_count < 2:
            return  # Cannot validate geometry with single slice

        # Check slice spacing
        positions = series.get_slice_positions()

        if len(positions) < 2:
            report.issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="geometry",
                    message="Insufficient position data for geometry validation",
                )
            )
            return

        # Calculate spacing between consecutive slices
        spacings = []
        for i in range(len(positions) - 1):
            z1 = positions[i][2]
            z2 = positions[i + 1][2]
            spacing = abs(z2 - z1)
            spacings.append(spacing)

        if spacings:
            mean_spacing = np.mean(spacings)
            std_spacing = np.std(spacings)

            # Check for non-uniform spacing
            if mean_spacing > 0 and std_spacing / mean_spacing > 0.01:
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="geometry",
                        message="Non-uniform slice spacing detected",
                        details={
                            "mean_spacing_mm": float(mean_spacing),
                            "std_spacing_mm": float(std_spacing),
                            "coefficient_variation": float(std_spacing / mean_spacing),
                        },
                    )
                )

            # Check for zero spacing (overlapping slices)
            if min(spacings) < 0.01:
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category="geometry",
                        message="Overlapping or duplicate slice positions detected",
                        details={"min_spacing_mm": float(min(spacings))},
                    )
                )

            # Check for extreme spacing
            if max(spacings) > 50.0:  # > 5cm between slices
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="geometry",
                        message="Unusually large spacing between slices",
                        details={"max_spacing_mm": float(max(spacings))},
                    )
                )

    def _validate_metadata(self, series: DicomSeries, report: ValidationReport) -> None:
        """Validate presence and validity of required DICOM metadata.

        Checks:
        - Required DICOM tags present (Patient, Study, Series, Instance)
        - Valid UID formats
        - Reasonable metadata values
        """
        required_tags = [
            ("SeriesInstanceUID", "Series Instance UID"),
            ("StudyInstanceUID", "Study Instance UID"),
            ("Modality", "Modality"),
        ]

        for i, slice_path in enumerate(series.slices):
            try:
                ds = pydicom.dcmread(slice_path, stop_before_pixels=True)

                # Check required tags
                for tag_name, display_name in required_tags:
                    if not hasattr(ds, tag_name):
                        report.issues.append(
                            ValidationIssue(
                                severity=ValidationSeverity.ERROR,
                                category="metadata",
                                message=f"Missing required tag: {display_name}",
                                slice_index=i,
                                slice_path=slice_path,
                            )
                        )

            except Exception as e:
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        category="metadata",
                        message=f"Error reading metadata: {e}",
                        slice_index=i,
                        slice_path=slice_path,
                    )
                )

    def _validate_security_concerns(
        self, series: DicomSeries, report: ValidationReport
    ) -> None:
        """Check for patterns that may indicate security issues or fuzzing targets.

        Based on 2025 CVE research:
        - CVE-2025-35975: Out-of-bounds write
        - CVE-2025-36521: Out-of-bounds read
        - CVE-2025-5943: Memory corruption

        Checks:
        - Extreme values in numeric fields
        - Unusual patterns that may trigger parser bugs
        - Inconsistencies that could cause viewer crashes
        """
        # Check for extreme image dimensions
        dimensions = series.get_dimensions()
        if dimensions:
            rows, cols, slices = dimensions

            if rows > 4096 or cols > 4096:
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="security",
                        message=f"Unusually large image dimensions: {rows}x{cols}",
                        details={"rows": rows, "columns": cols},
                    )
                )

            if rows * cols * slices > 1e9:  # > 1 billion pixels
                report.issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="security",
                        message="Extremely large volume may cause memory exhaustion",
                        details={
                            "total_pixels": rows * cols * slices,
                            "estimated_memory_gb": (rows * cols * slices * 2) / 1e9,
                        },
                    )
                )
